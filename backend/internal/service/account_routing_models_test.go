package service

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// extra.routing_models 显式路由白名单：对透传账号同样生效，与 model_mapping 解耦。
func TestAccount_RoutingModelAllowlist(t *testing.T) {
	t.Run("透传账号受白名单约束", func(t *testing.T) {
		account := &Account{
			Platform: PlatformOpenAI,
			Type:     AccountTypeOAuth,
			Extra: map[string]any{
				"openai_passthrough": true,
				"routing_models":     []any{"gpt-5.6-sol", "gpt-6-sol", "codex-auto-review"},
			},
		}
		require.True(t, account.IsModelSupported("gpt-5.6-sol"))
		require.True(t, account.IsModelSupported("gpt-6-sol"))
		require.True(t, account.IsModelSupported("codex-auto-review"))
		// 透传也不例外：白名单外拦截
		require.False(t, account.IsModelSupported("gpt-5.5"))
		require.False(t, account.IsModelSupported("gpt-6-astra"))
	})

	t.Run("未配置白名单的透传账号维持放行所有模型(#4936)", func(t *testing.T) {
		account := &Account{
			Platform: PlatformOpenAI,
			Type:     AccountTypeOAuth,
			Extra: map[string]any{
				"openai_passthrough": true,
			},
		}
		require.True(t, account.IsModelSupported("gpt-5.5"))
		require.True(t, account.IsModelSupported("anything-custom"))
	})

	t.Run("非透传账号同样支持该字段", func(t *testing.T) {
		account := &Account{
			Platform: PlatformAnthropic,
			Type:     AccountTypeOAuth,
			Extra: map[string]any{
				"routing_models": []any{"claude-opus-4-6"},
			},
		}
		require.True(t, account.IsModelSupported("claude-opus-4-6"))
		require.False(t, account.IsModelSupported("claude-haiku"))
	})

	t.Run("空模型名不拦截(探测类请求)", func(t *testing.T) {
		account := &Account{
			Platform: PlatformOpenAI,
			Type:     AccountTypeOAuth,
			Extra: map[string]any{
				"routing_models": []any{"gpt-5.6-sol"},
			},
		}
		require.True(t, account.IsModelSupported(""))
	})

	t.Run("空白元素被忽略,全空等价于未配置", func(t *testing.T) {
		account := &Account{
			Platform: PlatformOpenAI,
			Type:     AccountTypeOAuth,
			Extra: map[string]any{
				"routing_models": []any{"  ", ""},
			},
		}
		require.Nil(t, account.GetRoutingModelAllowlist())
		require.True(t, account.IsModelSupported("gpt-5.5"))
	})

	t.Run("类型异常视为未配置", func(t *testing.T) {
		account := &Account{
			Platform: PlatformOpenAI,
			Type:     AccountTypeOAuth,
			Extra: map[string]any{
				"routing_models": "gpt-5.6-sol",
			},
		}
		require.Nil(t, account.GetRoutingModelAllowlist())
		require.True(t, account.IsModelSupported("gpt-5.5"))
	})

	t.Run("getter 去空白保序", func(t *testing.T) {
		account := &Account{
			Platform: PlatformOpenAI,
			Type:     AccountTypeOAuth,
			Extra: map[string]any{
				"routing_models": []any{" gpt-5.6-sol ", "gpt-6-sol"},
			},
		}
		require.Equal(t, []string{"gpt-5.6-sol", "gpt-6-sol"}, account.GetRoutingModelAllowlist())
	})
}
