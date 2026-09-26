package service

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

// 打票探测的「真实用户出站」线格式（wire realism）。
//
// 背景：打票探测长期以 Go 默认 http.Transport 出站——TLS 层是 Go crypto/tls
// 的 ClientHello（真实转发路径早已是 CodexProfile utls 指纹），HTTP 层是 Go 的
// 规范大写头 + 字母序，请求体是 map 序列化的字母序 JSON，且探测前的
// /cdn-cgi/trace 不带任何头（Go 默认 UA "Go-http-client/1.1"）。真实 Codex CLI
// （reqwest/hyper + OpenSSL）出站是小写头、固定插入序、结构体字段序 JSON、
// 携带完整会话身份头。上游（Cloudflare JA4/JA4H、OpenAI 风控）可据此把探测
// 流量与真实用户一眼区分。
//
// 本文件提供三件事：
//  1. openAITicketProbeIdentity —— 账号级稳定的会话身份（installation/session/
//     thread），每轮新 turn_id（UUIDv7），与真实 CLI「一个长期会话多轮对话」
//     的形态一致；账号配置了指纹收敛种子时直接复用收敛值，探测与真实转发
//     身份同源。
//  2. buildOpenAITicketProbeRequestBody —— 按 codex-rs ResponsesApiRequest 的
//     字段序手工构造探测体（map 序列化会按字母序重排，无法表达）。
//  3. openAITicketWireRoundTripper —— 单连接手工 HTTP/1.1 写出器：全小写头、
//     固定顺序、显式 content-length；一次拨号上先 trace 后探测（出口归属
//     不变量与原实现一致）。给 probeOnce 换上后，探测连接从 TLS 到 HTTP 全
//     层面与真实 Codex 出站同构。

// openAITicketProbeIdentity 打票探测使用的会话身份。
type openAITicketProbeIdentity struct {
	installationID string
	sessionID      string
	threadID       string
	turnID         string
	windowID       string
	turnStartedAt  int64 // unix ms
}

// resolveOpenAITicketProbeIdentity 计算账号的探测身份。
// installation/session 优先复用账号指纹收敛值（探测与真实转发同源）；未配置
// 收敛的账号从账号 ID 确定性派生稳定值（同一账号的探测始终是同一个「CLI
// 会话」，而不是每次探测新开一个）。thread 用探测专属命名空间，避免与真实
// 转发的线程空间碰撞。turn_id 每次调用新造（真实对话每一轮都是新 turn）。
func resolveOpenAITicketProbeIdentity(account *Account) *openAITicketProbeIdentity {
	seed, _ := codexFingerprintSeed(account.Extra)
	accountKey := strconv.FormatInt(account.ID, 10)

	installationID := resolveConvergedInstallationID(account, seed)
	if installationID == "" {
		installationID = deriveStableUUIDv4("sub2api:codex-ticket-probe-install:v1:" + accountKey)
	}
	sessionID := resolveConvergedSessionID(seed)
	if sessionID == "" {
		sessionID = deriveStableUUIDv4("sub2api:codex-ticket-probe-session:v1:" + accountKey)
	}
	threadID := deriveStableUUIDv4("sub2api:codex-ticket-probe-thread:v1:" + accountKey)
	return &openAITicketProbeIdentity{
		installationID: installationID,
		sessionID:      sessionID,
		threadID:       threadID,
		turnID:         uuid.NewString(),
		windowID:       threadID + ":0",
		turnStartedAt:  time.Now().UnixMilli(),
	}
}

// openAITicketProbeInstructions 探测体的 instructions。真实 codex CLI 会携带
// 完整的数 KB 级基础提示词（随版本变化）；探测按用量考虑使用其公开开头段
// （codex-rs prompt 的起始两句）+ 简短延续，保证形态上是 Codex 会话而非
// 裸的 "Reply with OK."。
const openAITicketProbeInstructions = "You are Codex, based on GPT-5. You are running as a coding agent " +
	"in the Codex CLI on a user's computer. Apply the software engineering best practices " +
	"for accomplishing the task. Follow the user's instructions carefully."

// buildOpenAITicketProbeRequestBody 按 codex-rs ResponsesApiRequest 的字段序
// 构造探测请求体：model, instructions, input, tool_choice, parallel_tool_calls,
// reasoning, store, stream, include, prompt_cache_key, client_metadata。
// 必须手工拼字节：encoding/json 对 map 按字母序输出，与 codex（serde 结构体
// 序）不一致。tools 为空时整体省略（与序列化层 skip 空向量的行为一致）。
// prompt_cache_key 与 client_metadata 复用网关出站收敛的约定（session 维度）。
func buildOpenAITicketProbeRequestBody(model string, ids *openAITicketProbeIdentity) []byte {
	var b bytes.Buffer
	b.WriteString(`{"model":`)
	writeJSONString(&b, model)
	b.WriteString(`,"instructions":`)
	writeJSONString(&b, openAITicketProbeInstructions)
	b.WriteString(`,"input":[{"type":"message","role":"user","content":`)
	writeJSONString(&b, "Reply with OK.")
	b.WriteString(`}],"tool_choice":"auto","parallel_tool_calls":false,` +
		`"reasoning":{"effort":"low","summary":"auto"},"store":false,"stream":true,` +
		`"include":["reasoning.encrypted_content"],"prompt_cache_key":`)
	writeJSONString(&b, ids.sessionID)
	b.WriteString(`,"client_metadata":{"x-codex-installation-id":`)
	writeJSONString(&b, ids.installationID)
	b.WriteString(`,"session_id":`)
	writeJSONString(&b, ids.sessionID)
	b.WriteString(`,"thread_id":`)
	writeJSONString(&b, ids.threadID)
	b.WriteString(`,"x-codex-window-id":`)
	writeJSONString(&b, ids.windowID)
	b.WriteString(`,"x-codex-turn-metadata":`)
	writeJSONString(&b, buildOpenAITicketTurnMetadataJSON(ids))
	b.WriteString(`}}`)
	return b.Bytes()
}

// buildOpenAITicketTurnMetadataJSON 构造 x-codex-turn-metadata 的内层 JSON
// （字段序与 codex 协议结构体一致：installation_id, session_id, thread_id,
// turn_id, window_id, turn_started_at_unix_ms）。
func buildOpenAITicketTurnMetadataJSON(ids *openAITicketProbeIdentity) string {
	var b bytes.Buffer
	b.WriteString(`{"installation_id":`)
	writeJSONString(&b, ids.installationID)
	b.WriteString(`,"session_id":`)
	writeJSONString(&b, ids.sessionID)
	b.WriteString(`,"thread_id":`)
	writeJSONString(&b, ids.threadID)
	b.WriteString(`,"turn_id":`)
	writeJSONString(&b, ids.turnID)
	b.WriteString(`,"window_id":`)
	writeJSONString(&b, ids.windowID)
	b.WriteString(`,"turn_started_at_unix_ms":`)
	b.WriteString(strconv.FormatInt(ids.turnStartedAt, 10))
	b.WriteString(`}`)
	return b.String()
}

func writeJSONString(b *bytes.Buffer, s string) {
	enc, _ := json.Marshal(s)
	b.Write(enc)
}

// openAITicketWireHeaderOrder 探测请求头的固定写出顺序（全小写）。
// 依据真实 codex 出站形态（reqwest 逐头小写、鉴权/身份头先于内容协商头）。
var openAITicketWireHeaderOrder = []string{
	"user-agent",
	"authorization",
	"chatgpt-account-id",
	"openai-beta",
	"version",
	"originator",
	"session_id",
	"conversation_id",
	"x-codex-installation-id",
	"x-codex-window-id",
	"x-codex-turn-metadata",
	"accept",
	"content-type",
}

// writeOpenAITicketWireRequest 手工序列化 HTTP/1.1 请求：host 首位、顺序表内
// 的头按序小写输出、顺序表外的头按字母序补尾（语义不丢），有体时显式
// content-length。Go 的 http.Transport 会把头规范化成大写驼峰并按字母序发送，
// 与 hyper（小写、插入序）不一致，JA4H 可见。
func writeOpenAITicketWireRequest(w io.Writer, req *http.Request, body []byte) error {
	var b bytes.Buffer
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\n", req.Method, req.URL.RequestURI())
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	b.WriteString("host: ")
	b.WriteString(host)
	written := map[string]bool{"host": true}
	for _, name := range openAITicketWireHeaderOrder {
		values, ok := req.Header[http.CanonicalHeaderKey(name)]
		if !ok {
			// 直接以小写键写入的头（不经 Set/Add）不会被规范化，补查一次。
			values, ok = req.Header[name]
		}
		if !ok || len(values) == 0 {
			continue
		}
		for _, v := range values {
			b.WriteString("\r\n")
			b.WriteString(name)
			b.WriteString(": ")
			b.WriteString(v)
		}
		written[name] = true
	}
	// 顺序表外的头按字母序补尾。
	extra := make([]string, 0, len(req.Header))
	extraValues := make(map[string][]string, len(req.Header))
	for name, values := range req.Header {
		lower := strings.ToLower(name)
		if written[lower] || lower == "content-length" || lower == "transfer-encoding" ||
			lower == "connection" || lower == "host" {
			continue
		}
		extra = append(extra, lower)
		extraValues[lower] = values
	}
	sort.Strings(extra)
	for _, name := range extra {
		for _, v := range extraValues[name] {
			b.WriteString("\r\n")
			b.WriteString(name)
			b.WriteString(": ")
			b.WriteString(v)
		}
	}
	if body != nil {
		b.WriteString("\r\ncontent-length: ")
		b.WriteString(strconv.Itoa(len(body)))
	}
	b.WriteString("\r\n\r\n")
	if body != nil {
		b.Write(body)
	}
	_, err := w.Write(b.Bytes())
	return err
}

// openAITicketWireBody 关闭时连带关闭底层连接（探测 POST 的响应是终态）。
type openAITicketWireBody struct {
	io.ReadCloser
	conn net.Conn
}

func (b *openAITicketWireBody) Close() error {
	err := b.ReadCloser.Close()
	_ = b.conn.Close()
	return err
}

// openAITicketWireRoundTripper 单连接手工 HTTP/1.1 RoundTripper：
//   - 首个请求惰性拨号（由注入的 dial 决定出口，拨号器带 CodexProfile utls
//     指纹；probeOnce 每次探测新建实例 = 新连接 = 新出口，语义与原独立
//     Transport 一致）；
//   - trace 与探测复用同一连接（出口归属不变量）；
//   - POST 响应体关闭时关闭连接；实例 Close 兜底（探测未发出 POST 的场景）。
type openAITicketWireRoundTripper struct {
	dial func(ctx context.Context, network, addr string) (net.Conn, error)

	conn net.Conn
	br   *bufio.Reader
}

func (rt *openAITicketWireRoundTripper) ensureConn(ctx context.Context, addr string) error {
	if rt.conn != nil {
		return nil
	}
	conn, err := rt.dial(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	rt.conn = conn
	rt.br = bufio.NewReader(conn)
	return nil
}

// watchContext 在 ctx 结束时把连接 deadline 置为过去以中断阻塞中的
// Read/Write（手工客户端没有 http.Transport 的自动取消管道）。
func (rt *openAITicketWireRoundTripper) watchContext(ctx context.Context) func() {
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = rt.conn.SetDeadline(time.Now())
		case <-done:
		}
	}()
	return func() {
		close(done)
		_ = rt.conn.SetDeadline(time.Time{})
	}
}

func (rt *openAITicketWireRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL == nil {
		return nil, fmt.Errorf("wire round tripper: nil URL")
	}
	addr := req.URL.Host
	if !strings.Contains(addr, ":") {
		addr += ":443"
	}
	if err := rt.ensureConn(req.Context(), addr); err != nil {
		return nil, err
	}
	stop := rt.watchContext(req.Context())
	defer stop()

	var body []byte
	if req.Body != nil {
		var err error
		body, err = io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		_ = req.Body.Close()
	}
	if deadline, ok := req.Context().Deadline(); ok {
		_ = rt.conn.SetWriteDeadline(deadline)
		_ = rt.conn.SetReadDeadline(deadline)
	}
	if err := writeOpenAITicketWireRequest(rt.conn, req, body); err != nil {
		return nil, err
	}
	resp, err := http.ReadResponse(rt.br, req)
	if err != nil {
		return nil, err
	}
	if req.Method == http.MethodPost {
		resp.Body = &openAITicketWireBody{ReadCloser: resp.Body, conn: rt.conn}
	}
	return resp, nil
}

// Close 释放底层连接（探测流程结束后的兜底；POST 响应体关闭时已关则幂等）。
func (rt *openAITicketWireRoundTripper) Close() {
	if rt.conn != nil {
		_ = rt.conn.Close()
	}
}
