package service

import (
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/model"
	"github.com/Wei-Shaw/sub2api/internal/pkg/tlsfingerprint"
)

// TestResolveTLSProfilePlatformDefaults 验证 ResolveTLSProfile 的账号平台
// 分流（2026-09 b84e13f2f 引入）：OpenAI OAuth 类账号启用 TLS 指纹且未绑定
// 模板时返回内置 CodexProfile（codex-cli = OpenSSL 3.6.3 形态），Anthropic
// OAuth 返回 Node.js 默认形态，API-key 账号即使置位也不启用。
func TestResolveTLSProfilePlatformDefaults(t *testing.T) {
	// 同包直构，绕过 NewTLSFingerprintProfileService 的 DB 启动加载；
	// ResolveTLSProfile 热路径只读 localCache。
	svc := &TLSFingerprintProfileService{
		localCache: map[int64]*model.TLSFingerprintProfile{
			7: {ID: 7, Name: "db-profile-x"},
		},
	}

	enabled := map[string]any{"enable_tls_fingerprint": true}

	cases := []struct {
		name    string
		account *Account
		check   func(*testing.T, *tlsfingerprint.Profile)
	}{
		{
			name:    "nil account",
			account: nil,
			check: func(t *testing.T, p *tlsfingerprint.Profile) {
				if p != nil {
					t.Fatalf("nil account must resolve nil, got %+v", p)
				}
			},
		},
		{
			name: "OpenAI OAuth enabled no binding → CodexProfile",
			account: &Account{ID: 133, Platform: PlatformOpenAI, Type: AccountTypeOAuth, Extra: enabled},
			check: func(t *testing.T, p *tlsfingerprint.Profile) {
				if p == nil {
					t.Fatal("OpenAI OAuth + enabled must resolve a profile")
				}
				if p.Name != tlsfingerprint.CodexProfile.Name {
					t.Fatalf("profile name: got %q want %q", p.Name, tlsfingerprint.CodexProfile.Name)
				}
				// 指针级一致：确保热路径直接复用内置模板（无每次分配/漂移）
				if p != tlsfingerprint.CodexProfile {
					t.Fatalf("OpenAI default must be the shared CodexProfile instance")
				}
			},
		},
		{
			name: "OpenAI SetupToken enabled no binding → CodexProfile",
			account: &Account{ID: 145, Platform: PlatformOpenAI, Type: AccountTypeSetupToken, Extra: enabled},
			check: func(t *testing.T, p *tlsfingerprint.Profile) {
				if p != tlsfingerprint.CodexProfile {
					t.Fatalf("OpenAI SetupToken default must be CodexProfile, got %+v", p)
				}
			},
		},
		{
			name: "OpenAI OAuth disabled → nil",
			account: &Account{ID: 213, Platform: PlatformOpenAI, Type: AccountTypeOAuth,
				Extra: map[string]any{"enable_tls_fingerprint": false}},
			check: func(t *testing.T, p *tlsfingerprint.Profile) {
				if p != nil {
					t.Fatalf("disabled must resolve nil, got %+v", p)
				}
			},
		},
		{
			name: "OpenAI OAuth enabled but Extra nil → nil",
			account: &Account{ID: 243, Platform: PlatformOpenAI, Type: AccountTypeOAuth},
			check: func(t *testing.T, p *tlsfingerprint.Profile) {
				if p != nil {
					t.Fatalf("nil Extra must resolve nil, got %+v", p)
				}
			},
		},
		{
			name: "OpenAI API-key enabled → nil（不支持）",
			account: &Account{ID: 999, Platform: PlatformOpenAI, Type: AccountTypeAPIKey, Extra: enabled},
			check: func(t *testing.T, p *tlsfingerprint.Profile) {
				if p != nil {
					t.Fatalf("API-key accounts must never enable TLS fingerprint, got %+v", p)
				}
			},
		},
		{
			name: "Anthropic OAuth enabled no binding → Node.js 默认",
			account: &Account{ID: 501, Platform: PlatformAnthropic, Type: AccountTypeOAuth, Extra: enabled},
			check: func(t *testing.T, p *tlsfingerprint.Profile) {
				if p == nil {
					t.Fatal("Anthropic OAuth + enabled must resolve a profile")
				}
				if p.Name != "Built-in Default (Node.js 24.x)" {
					t.Fatalf("profile name: got %q want Node.js default", p.Name)
				}
			},
		},
		{
			name: "Anthropic API-key enabled → nil",
			account: &Account{ID: 502, Platform: PlatformAnthropic, Type: AccountTypeAPIKey, Extra: enabled},
			check: func(t *testing.T, p *tlsfingerprint.Profile) {
				if p != nil {
					t.Fatalf("Anthropic API-key must resolve nil, got %+v", p)
				}
			},
		},
		{
			name: "OpenAI OAuth + 绑定存在模板 → DB 模板优先于平台默认",
			account: &Account{ID: 244, Platform: PlatformOpenAI, Type: AccountTypeOAuth,
				Extra: map[string]any{"enable_tls_fingerprint": true, "tls_fingerprint_profile_id": float64(7)}},
			check: func(t *testing.T, p *tlsfingerprint.Profile) {
				if p == nil || p.Name != "db-profile-x" {
					t.Fatalf("bound profile must win, got %+v", p)
				}
			},
		},
		{
			name: "OpenAI OAuth + 绑定不存在模板 → 回落 CodexProfile",
			account: &Account{ID: 245, Platform: PlatformOpenAI, Type: AccountTypeOAuth,
				Extra: map[string]any{"enable_tls_fingerprint": true, "tls_fingerprint_profile_id": float64(404)}},
			check: func(t *testing.T, p *tlsfingerprint.Profile) {
				if p != tlsfingerprint.CodexProfile {
					t.Fatalf("missing bound profile must fall back to CodexProfile, got %+v", p)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.check(t, svc.ResolveTLSProfile(tc.account))
		})
	}
}
