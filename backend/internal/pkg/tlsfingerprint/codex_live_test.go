package tlsfingerprint

import (
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"
)

// TestCodexProfileLiveHandshake 用 CodexProfile 对真实上游做完整 TLS 握手 +
// HTTP/1.1 请求冒烟测试。默认跳过，设 CODEX_TLS_LIVE=1 启用（部署前在干净
// 网络环境执行：TLS1.3 成功、无 ALPN、HTTP 状态码返回）。
func TestCodexProfileLiveHandshake(t *testing.T) {
	if os.Getenv("CODEX_TLS_LIVE") == "" {
		t.Skip("set CODEX_TLS_LIVE=1 to run live handshake test")
	}
	if testing.Short() {
		t.Skip("short mode")
	}
	host := "chatgpt.com"
	transport := &http.Transport{
		DialTLSContext: NewDialer(CodexProfile, nil).DialTLSContext,
		// 真实 codex 不协商 ALPN，这里同样不设置 ForceAttemptHTTP2
		MaxIdleConns:          2,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
	}
	client := &http.Client{Transport: transport, Timeout: 30 * time.Second}

	req, err := http.NewRequest("HEAD", "https://"+host+"/backend-api/codex/responses", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("User-Agent", "codex_cli_rs/0.155.1")
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("live request failed after %v: %v", time.Since(start), err)
	}
	defer resp.Body.Close()
	fmt.Printf("live handshake + request OK in %v: status=%d proto=%s\n", time.Since(start), resp.StatusCode, resp.Proto)
	if resp.Proto != "HTTP/1.1" {
		t.Fatalf("expected HTTP/1.1 (codex offers no ALPN), got %s", resp.Proto)
	}

	// 连接层确认：第二条连接同样完成握手
	conn, err := transport.DialTLSContext(t.Context(), "tcp", "chatgpt.com:443")
	if err != nil {
		t.Fatalf("second dial: %v", err)
	}
	defer conn.Close()
	fmt.Printf("second dial OK: remote=%s\n", conn.RemoteAddr())
}
