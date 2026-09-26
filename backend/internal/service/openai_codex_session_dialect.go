package service

import (
	"fmt"
	"net/http"
	"strings"
)

// codex-rs 0.148+ 的 Responses 线上会话方言（codex-api/src/requests/headers.rs
// build_session_headers + endpoint/responses.rs）：
//   - HTTP/WS 都只发连字符形式 session-id / thread-id；
//   - x-client-request-id = thread_id（HTTP 与 WS 握手都带）；
//   - conversation_id 头自 0.148 起已不存在（对话标识只活在 body 的
//     prompt_cache_key / client_metadata）；
//   - installation_id 只在 body client_metadata 里，不发独立 HTTP 头。
//
// 网关出站统一迁移到该方言后，version 头（自动跟随官方最新版）与头形状才
// 自洽：带着下划线 session_id/conversation_id 的请求等于自报了一个 14+ 个
// 版本前就废弃的客户端形态，与声明的 0.157.x 版本互相矛盾。
const (
	codexSessionIDHeader       = "session-id"
	codexThreadIDHeader        = "thread-id"
	codexClientRequestIDHeader = "x-client-request-id"
)

// codexLegacySessionDialectHeaders 是已废弃/由方言层接管的出站头清单，
// 构造出站请求时先全部剥除再按 0.15x 方言重写。
var codexLegacySessionDialectHeaders = []string{
	"session_id",
	"session-id",
	"conversation_id",
	"thread-id",
	codexClientRequestIDHeader,
	"x-codex-installation-id",
}

// deleteCodexHeaderAllSpellings 删除一个头的全部拼写形态。
// http.Header.Del 只删 canonical 键；入站透传的 map 里可能同时存在
// 原始小写键与 canonical 键，逐键扫描才能剥干净。
func deleteCodexHeaderAllSpellings(h http.Header, name string) {
	canonical := http.CanonicalHeaderKey(name)
	for key := range h {
		if strings.EqualFold(key, name) || key == canonical {
			delete(h, key)
		}
	}
}

// stripCodexSessionDialectHeaders 剥除全部会话方言头（含旧下划线形态与
// 连字符形态），供三个出站构造器（forward / passthrough / WS 握手）在
// 重写前调用，防止客户端旧方言残留出站。
func stripCodexSessionDialectHeaders(h http.Header) {
	if h == nil {
		return
	}
	for _, name := range codexLegacySessionDialectHeaders {
		deleteCodexHeaderAllSpellings(h, name)
	}
}

// readClientCodexSessionHeaders 读取客户端原始会话标识（优先连字符形式，
// 回落旧下划线形式），用于出站隔离/收敛的种子。
type clientCodexSessionIdentity struct {
	SessionID  string
	ThreadID   string
	HasSession bool
	HasThread  bool
}

func readClientCodexSessionHeaders(h http.Header) clientCodexSessionIdentity {
	identity := clientCodexSessionIdentity{}
	if h == nil {
		return identity
	}
	if v := strings.TrimSpace(h.Get("session-id")); v != "" {
		identity.SessionID = v
		identity.HasSession = true
	} else if v := strings.TrimSpace(h.Get("session_id")); v != "" {
		identity.SessionID = v
		identity.HasSession = true
	}
	if v := strings.TrimSpace(h.Get("thread-id")); v != "" {
		identity.ThreadID = v
		identity.HasThread = true
	}
	return identity
}

// applyCodexSessionDialectHeaders 按 0.15x 方言写入会话头三件套：
//
//	session-id     = isolate(sessionSeed)
//	thread-id      = isolate(clientThreadID)，客户端没带则从隔离后的会话派生
//	x-client-request-id = thread-id（与真实 Codex 一致：等值 thread_id）
//
// account 传调用方已解析的收敛源（codexAccountIdentitySource 的结果）。
// sessionSeed 为空时三者都不写（真实 Codex 不会发空值头）。调用前应已
// stripCodexSessionDialectHeaders；指纹收敛（full 模式）在本函数之后仍会以
// 账号级恒定值覆盖这三者。
func applyCodexSessionDialectHeaders(h http.Header, apiKeyID int64, account *Account, sessionSeed, clientThreadID string) {
	if h == nil {
		return
	}
	sessionSeed = strings.TrimSpace(sessionSeed)
	if sessionSeed == "" {
		return
	}
	isolated := isolateOpenAIUpstreamSessionID(apiKeyID, account, sessionSeed)
	if isolated == "" {
		return
	}
	h.Set(codexSessionIDHeader, isolated)

	threadID := strings.TrimSpace(clientThreadID)
	if threadID != "" {
		threadID = isolateOpenAIUpstreamSessionID(apiKeyID, account, threadID)
	} else {
		// 无客户端线程标识（非 Codex 客户端 / 旧方言）：从隔离后的会话派生一个
		// 稳定线程 UUID，保证同一会话跨 failover/重试的 thread-id 恒定。
		threadID = generateSessionUUID(fmt.Sprintf("u%d:a%s:%s:thread", apiKeyID, codexAccountIdentityNamespace(account), isolated))
	}
	if threadID != "" {
		h.Set(codexThreadIDHeader, threadID)
		h.Set(codexClientRequestIDHeader, threadID)
	}
}
