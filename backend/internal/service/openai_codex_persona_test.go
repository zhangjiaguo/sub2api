package service

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/pkg/openai"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// restorePersonaSwitch 在测试结束后恢复人设开关，避免用例间泄漏。
func restorePersonaSwitch(t *testing.T, enabled bool) {
	t.Helper()
	t.Cleanup(func() { SetCodexPersonaDiversityEnabled(enabled) })
}

func TestCodexAccountPersonaUserAgent(t *testing.T) {
	t.Run("deterministic_per_account", func(t *testing.T) {
		restorePersonaSwitch(t, true)
		SetCodexPersonaDiversityEnabled(true)
		a := codexAccountPersonaUserAgent(7)
		b := codexAccountPersonaUserAgent(7)
		assert.Equal(t, a, b, "同一账号人设必须稳定")
	})

	t.Run("diverse_across_accounts", func(t *testing.T) {
		restorePersonaSwitch(t, true)
		SetCodexPersonaDiversityEnabled(true)
		seen := map[string]bool{}
		for id := int64(1); id <= 64; id++ {
			seen[codexAccountPersonaUserAgent(id)] = true
		}
		assert.Greater(t, len(seen), 1, "多个账号不应共享同一人设")
	})

	t.Run("official_identity_preserved", func(t *testing.T) {
		restorePersonaSwitch(t, true)
		SetCodexPersonaDiversityEnabled(true)
		for id := int64(1); id <= 32; id++ {
			ua := codexAccountPersonaUserAgent(id)
			originator, _, ok := openai.PairCodexClientIdentity(ua)
			require.True(t, ok, "人设 UA 必须能配出官方 originator: %s", ua)
			assert.True(t, openai.IsCodexOfficialClientOriginator(originator))
			// 版本段必须与规范身份一致（版本自动同步不因人设漂移）。
			assert.Equal(t, resolveCodexOutboundIdentity("").version, openai.CodexUserAgentVersion(ua))
		}
	})

	t.Run("disabled_falls_back_to_canonical", func(t *testing.T) {
		restorePersonaSwitch(t, true)
		SetCodexPersonaDiversityEnabled(false)
		assert.Equal(t, resolveCodexOutboundIdentity("").userAgent, codexAccountPersonaUserAgent(7))
	})

	t.Run("invalid_account_falls_back", func(t *testing.T) {
		restorePersonaSwitch(t, true)
		SetCodexPersonaDiversityEnabled(true)
		assert.Equal(t, resolveCodexOutboundIdentity("").userAgent, codexAccountPersonaUserAgent(0))
	})
}

func TestCodexAccountOverrideUserAgent(t *testing.T) {
	t.Run("admin_override_wins", func(t *testing.T) {
		restorePersonaSwitch(t, true)
		SetCodexPersonaDiversityEnabled(true)
		account := &Account{ID: 7, Platform: PlatformOpenAI, Credentials: map[string]any{
			"user_agent": "codex-tui/0.150.0 (Mac OS X 14.0; arm64) iTerm",
		}}
		got := codexAccountOverrideUserAgent(account)
		assert.Equal(t, "codex-tui/0.150.0 (Mac OS X 14.0; arm64) iTerm", got)
	})

	t.Run("persona_when_no_override", func(t *testing.T) {
		restorePersonaSwitch(t, true)
		SetCodexPersonaDiversityEnabled(true)
		account := &Account{ID: 7}
		assert.Equal(t, codexAccountPersonaUserAgent(7), codexAccountOverrideUserAgent(account))
	})

	t.Run("nil_account_empty", func(t *testing.T) {
		assert.Empty(t, codexAccountOverrideUserAgent(nil))
	})
}

// 探针（账号测试）与真实转发必须拿到同一个 UA：上游视角下同一账号只有一台机器。
func TestCodexOverrideUserAgentForwardProbeConsistency(t *testing.T) {
	restorePersonaSwitch(t, true)
	SetCodexPersonaDiversityEnabled(true)
	account := &Account{ID: 42}
	expected := codexAccountOverrideUserAgent(account)
	assert.True(t, strings.HasPrefix(expected, openai.CodexDefaultOriginator+"/"))
	assert.Equal(t, expected, codexAccountPersonaUserAgent(42))
}

// 端到端：默认人设开启时，Forward 出站请求携带的就是该账号的人设 UA，
// 且 originator/版本段仍来自规范身份链；不同账号出站 UA 不同。
func TestCodexPersonaUAReachesUpstreamForward(t *testing.T) {
	restorePersonaSwitch(t, true)
	SetCodexPersonaDiversityEnabled(true)
	gin.SetMode(gin.TestMode)

	newAccount := func(id int64) *Account {
		return &Account{
			ID:             id,
			Name:           "acc",
			Platform:       PlatformOpenAI,
			Type:           AccountTypeOAuth,
			Concurrency:    1,
			Credentials:    map[string]any{"access_token": "oauth-token", "chatgpt_account_id": "chatgpt-acc"},
			Extra:          map[string]any{"openai_passthrough": true},
			Status:         StatusActive,
			Schedulable:    true,
			RateMultiplier: f64p(1),
		}
	}

	forward := func(account *Account) *httpUpstreamRecorder {
		rec := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(rec)
		c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", bytes.NewReader(nil))
		c.Request.Header.Set("User-Agent", "codex_cli_rs/0.1.0")
		upstream := &httpUpstreamRecorder{resp: &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"text/event-stream"}, "x-request-id": []string{"rid"}},
			Body:       io.NopCloser(strings.NewReader("data: [DONE]\n\n")),
		}}
		svc := &OpenAIGatewayService{
			cfg:          &config.Config{Gateway: config.GatewayConfig{ForceCodexCLI: false}},
			httpUpstream: upstream,
		}
		body := []byte(`{"model":"gpt-5.2","stream":false,"store":true,"input":[{"type":"text","text":"hi"}]}`)
		_, err := svc.Forward(context.Background(), c, account, body)
		require.NoError(t, err)
		require.NotNil(t, upstream.lastReq)
		return upstream
	}

	first := forward(newAccount(123))
	second := forward(newAccount(456))

	require.Equal(t, codexAccountPersonaUserAgent(123), first.lastReq.Header.Get("User-Agent"))
	require.Equal(t, codexAccountPersonaUserAgent(456), second.lastReq.Header.Get("User-Agent"))
	require.NotEqual(t,
		first.lastReq.Header.Get("User-Agent"),
		second.lastReq.Header.Get("User-Agent"),
		"不同账号必须呈现不同人设")
	for _, req := range []*http.Request{first.lastReq, second.lastReq} {
		require.Equal(t, openai.CodexDefaultOriginator, req.Header.Get("originator"))
		require.Equal(t, codexCLIVersion, req.Header.Get("version"))
	}
}
