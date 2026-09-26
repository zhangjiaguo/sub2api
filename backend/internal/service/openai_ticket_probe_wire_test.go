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
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// 探测体必须按 codex-rs ResponsesApiRequest 的字段序输出（map 序列化是字母序，
// 会被上游按 JSON 指纹区分），且补齐真实 codex 会携带的 reasoning /
// prompt_cache_key / client_metadata。
func TestBuildOpenAITicketProbeRequestBody_CodexFieldOrder(t *testing.T) {
	ids := &openAITicketProbeIdentity{
		installationID: "11111111-1111-4111-8111-111111111111",
		sessionID:      "22222222-2222-4222-8222-222222222222",
		threadID:       "33333333-3333-4333-8333-333333333333",
		turnID:         "44444444-4444-7444-8444-444444444444",
		windowID:       "33333333-3333-4333-8333-333333333333:0",
		turnStartedAt:  1770000000000,
	}
	body := string(buildOpenAITicketProbeRequestBody("gpt-6-astra", ids))

	order := []string{
		`"model":`, `"instructions":`, `"input":`, `"tool_choice":`,
		`"parallel_tool_calls":`, `"reasoning":`, `"store":`, `"stream":`,
		`"include":`, `"prompt_cache_key":`, `"client_metadata":`,
	}
	last := 0
	for _, key := range order {
		idx := strings.Index(body, key)
		require.GreaterOrEqual(t, idx, 0, "缺少字段 %s：%s", key, body)
		require.Greater(t, idx, last, "字段 %s 顺序错误：%s", key, body)
		last = idx
	}
	require.True(t, strings.HasPrefix(body, `{"model":"gpt-6-astra","instructions":"`),
		"body 应以 model 开头：%s", body)
	require.Contains(t, body, `"reasoning":{"effort":"low","summary":"auto"}`)
	require.Contains(t, body, `"parallel_tool_calls":false`)
	// input 用户消息为字符串 content 形态（真实 codex 单段内容是裸字符串）。
	require.Contains(t, body, `"input":[{"type":"message","role":"user","content":"Reply with OK."}]`)
	// prompt_cache_key 与网关出站收敛约定一致（session 维度）。
	require.Contains(t, body, `"prompt_cache_key":"22222222-2222-4222-8222-222222222222"`)
	// client_metadata 键集与真实 codex 请求体一致，turn metadata 内层 JSON
	// 字段序固定且 turn_id 为 UUIDv7。
	require.Contains(t, body, `"client_metadata":{"x-codex-installation-id":"11111111-1111-4111-8111-111111111111"`)
	metadataIdx := strings.Index(body, `"x-codex-turn-metadata":"`)
	require.GreaterOrEqual(t, metadataIdx, 0)
	parsed, err := uuid.Parse(ids.turnID)
	require.NoError(t, err)
	require.Equal(t, uuid.Version(7), parsed.Version(), "turn_id 应为 UUIDv7")
	require.Contains(t, body, `\"turn_started_at_unix_ms\":1770000000000`)
	require.True(t, json.Valid([]byte(body)), "body 应为合法 JSON：%s", body)
}

// 身份稳定性：同一账号重复探测是同一个「CLI 会话」（installation/session/
// thread 不变），turn_id 每轮新造；配置了指纹收敛种子的账号直接复用收敛值，
// 探测与真实转发身份同源。
func TestResolveOpenAITicketProbeIdentity_StablePerAccount(t *testing.T) {
	account := &Account{ID: 133}
	first := resolveOpenAITicketProbeIdentity(account)
	second := resolveOpenAITicketProbeIdentity(account)
	require.Equal(t, first.installationID, second.installationID)
	require.Equal(t, first.sessionID, second.sessionID)
	require.Equal(t, first.threadID, second.threadID)
	require.NotEqual(t, first.turnID, second.turnID)
	require.Equal(t, first.threadID+":0", first.windowID)
	for _, v := range []string{first.installationID, first.sessionID, first.threadID} {
		_, err := uuid.Parse(v)
		require.NoError(t, err, "身份应为 UUID 形态：%s", v)
	}

	seed := "55555555-5555-4555-8555-555555555555"
	converged := &Account{ID: 145, Extra: map[string]any{codexFingerprintSeedExtraKey: seed}}
	ids := resolveOpenAITicketProbeIdentity(converged)
	require.Equal(t, resolveConvergedSessionID(seed), ids.sessionID)
	require.Equal(t, resolveConvergedInstallationID(converged, seed), ids.installationID)

	// 不同账号会话不同（上游视角是不同用户实例）。
	other := resolveOpenAITicketProbeIdentity(&Account{ID: 213})
	require.NotEqual(t, first.sessionID, other.sessionID)
}

// wire 客户端全链路：一次拨号上先 trace 后 POST（出口归属不变量），
// 请求行外的所有头小写、顺序表序、POST 带正确 content-length，
// POST 响应体关闭后连接关闭。
func TestOpenAITicketWireRoundTripper_FullWireShape(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()

	var dialCount int
	rt := &openAITicketWireRoundTripper{
		dial: func(context.Context, string, string) (net.Conn, error) {
			dialCount++
			return clientConn, nil
		},
	}
	client := &http.Client{Transport: rt}

	serverDone := make(chan error, 1)
	go func() {
		serverDone <- func() error {
			server := bufio.NewReader(serverConn)

			// 第一次请求：/cdn-cgi/trace，应带 codex UA（不再是 Go 默认 UA）。
			traceReq, err := http.ReadRequest(server)
			if err != nil {
				return err
			}
			if traceReq.Method != http.MethodGet || traceReq.URL.Path != "/cdn-cgi/trace" {
				return fmt.Errorf("trace 请求行错误")
			}
			if ua := traceReq.Header.Get("User-Agent"); ua != CodexCanonicalUserAgent() {
				return fmt.Errorf("trace 缺 codex UA: %s", ua)
			}
			traceBody := "ip=203.0.113.7\ncolo=LAX\n"
			if _, err := serverConn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: " +
				strconv.Itoa(len(traceBody)) + "\r\nContent-Type: text/plain\r\n\r\n" + traceBody)); err != nil {
				return err
			}

			// 第二次请求：探测 POST。
			postReq, err := http.ReadRequest(server)
			if err != nil {
				return err
			}
			if postReq.Method != http.MethodPost || postReq.URL.Path != "/backend-api/codex/responses" {
				return fmt.Errorf("POST 请求行错误")
			}
			body, err := io.ReadAll(postReq.Body)
			if err != nil {
				return err
			}
			if !bytes.HasPrefix(body, []byte(`{"model":`)) {
				return fmt.Errorf("POST 体应按 codex 字段序以 model 开头")
			}
			sse := "data: {\"type\":\"response.completed\"}\n\n"
			_, err = serverConn.Write([]byte("HTTP/1.1 200 OK\r\n" +
				"x-codex-turn-state: TICKET\r\n" +
				"Content-Type: text/event-stream\r\n" +
				"Content-Length: " + strconv.Itoa(len(sse)) + "\r\n\r\n" + sse))
			if err != nil {
				return err
			}
			// 等待客户端关闭连接（POST 响应体关闭连带关连接）。
			_, _ = server.Read(make([]byte, 1))
			return nil
		}()
	}()

	ctx := context.Background()
	ip, colo := openAITicketTraceExit(ctx, client)
	require.Equal(t, "203.0.113.7", ip)
	require.Equal(t, "LAX", colo)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://chatgpt.com/backend-api/codex/responses", bytes.NewReader([]byte(`{"model":"gpt-6-astra"}`)))
	require.NoError(t, err)
	req.Host = "chatgpt.com"
	req.Header.Set("authorization", "Bearer tk")
	req.Header.Set("user-agent", CodexCanonicalUserAgent())
	req.Header.Set("accept", "text/event-stream")
	req.Header.Set("content-type", "application/json")
	resp, err := client.Do(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "TICKET", resp.Header.Get("x-codex-turn-state"))
	data, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Contains(t, string(data), "response.completed")
	require.NoError(t, resp.Body.Close())

	require.Equal(t, 1, dialCount, "trace 与 POST 必须共用同一条连接（出口归属不变量）")
	require.NoError(t, <-serverDone)
}

// 原始字节断言：请求头全小写、固定顺序、无 Go 规范大写形态。
func TestWriteOpenAITicketWireRequest_LowercaseOrderedHeaders(t *testing.T) {
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost,
		"https://chatgpt.com/backend-api/codex/responses", nil)
	req.Host = "chatgpt.com"
	req.Header.Set("authorization", "Bearer tk")
	req.Header.Set("user-agent", "codex_cli_rs/0.155.0 (Windows 11.0.0; x86_64) WindowsTerminal")
	req.Header.Set("chatgpt-account-id", "acct-1")
	req.Header.Set("openai-beta", "responses=experimental")
	req.Header.Set("version", "0.155.0")
	req.Header.Set("originator", "codex_cli_rs")
	req.Header.Set("session_id", "sess-1")
	req.Header.Set("conversation_id", "conv-1")
	req.Header.Set("accept", "text/event-stream")
	req.Header.Set("content-type", "application/json")
	req.Header.Set("x-custom-extra", "v") // 顺序表外的头按字母序补尾

	var buf bytes.Buffer
	require.NoError(t, writeOpenAITicketWireRequest(&buf, req, []byte(`{}`)))
	wire := buf.String()

	lines := strings.Split(strings.TrimRight(wire, "\r\n{}"), "\r\n")
	require.Equal(t, "POST /backend-api/codex/responses HTTP/1.1", lines[0])
	require.Equal(t, "host: chatgpt.com", lines[1])
	joined := strings.Join(lines, "\n")
	for _, upper := range []string{"User-Agent:", "Authorization:", "Accept:", "Content-Type:", "Content-Length:"} {
		require.NotContains(t, joined, upper, "不应出现 Go 规范大写头")
	}
	order := []string{"host: chatgpt.com", "user-agent:", "authorization:", "chatgpt-account-id:",
		"openai-beta:", "version:", "originator:", "session_id:", "conversation_id:",
		"accept: text/event-stream", "content-type:", "x-custom-extra: v", "content-length: 2"}
	last := -1
	for _, marker := range order {
		idx := strings.Index(joined, marker)
		require.GreaterOrEqual(t, idx, 0, "缺少 %s：%s", marker, joined)
		require.Greater(t, idx, last, "顺序错误：%s", joined)
		last = idx
	}
	require.True(t, strings.HasSuffix(wire, "\r\n\r\n{}"), "体应紧随头部空行")
}

// ctx 取消应中断阻塞中的请求（手工客户端的取消管道）。
func TestOpenAITicketWireRoundTripper_ContextCancelAborts(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()
	rt := &openAITicketWireRoundTripper{
		dial: func(context.Context, string, string) (net.Conn, error) {
			return clientConn, nil
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://chatgpt.com/cdn-cgi/trace", nil)
	client := &http.Client{Transport: rt}
	resp, err := client.Do(req)
	if resp != nil {
		_ = resp.Body.Close()
	}
	require.Error(t, err, "ctx 取消后应返回错误")
}
