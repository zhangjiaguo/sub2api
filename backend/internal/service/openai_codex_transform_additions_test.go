package service

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// forceCodexInclude：无条件把 include 收敛为恰好 ["reasoning.encrypted_content"]，幂等。
func TestForceCodexInclude(t *testing.T) {
	// include 缺失 → 注入（与 reasoning 是否存在无关，对齐 CLIProxyAPI 无条件替换）
	body := map[string]any{}
	require.True(t, forceCodexInclude(body))
	require.Equal(t, []any{"reasoning.encrypted_content"}, body["include"])
	// 幂等：再次调用不重复
	require.False(t, forceCodexInclude(body))

	// 既有额外取值 → 精确替换（上游网关会丢弃多带项，直接收敛）
	body3 := map[string]any{"include": []any{"foo", "reasoning.encrypted_content"}}
	require.True(t, forceCodexInclude(body3))
	require.Equal(t, []any{"reasoning.encrypted_content"}, body3["include"])

	// 非数组异常 include → 同样收敛
	body4 := map[string]any{"include": "reasoning.encrypted_content"}
	require.True(t, forceCodexInclude(body4))
	require.Equal(t, []any{"reasoning.encrypted_content"}, body4["include"])
}

// normalizeCodexServiceTierForUpstream：fast→priority、ultrafast 保留、其余删除。
func TestNormalizeCodexServiceTierForUpstream(t *testing.T) {
	// 缺失 → 不动
	body := map[string]any{}
	require.False(t, normalizeCodexServiceTierForUpstream(body))
	_, ok := body["service_tier"]
	require.False(t, ok)

	// fast → priority（大小写不敏感，写出标准小写）
	body = map[string]any{"service_tier": "Fast"}
	require.True(t, normalizeCodexServiceTierForUpstream(body))
	require.Equal(t, "priority", body["service_tier"])
	// 已是 priority → 幂等
	require.False(t, normalizeCodexServiceTierForUpstream(body))

	// ultrafast 保留（归一小写）
	body = map[string]any{"service_tier": "Ultrafast"}
	require.True(t, normalizeCodexServiceTierForUpstream(body))
	require.Equal(t, "ultrafast", body["service_tier"])
	require.False(t, normalizeCodexServiceTierForUpstream(body))

	// auto/standard/default/flex → 删除（显式标准档会覆盖 Pro 账号默认优先档）
	for _, tier := range []string{"auto", "standard", "default", "flex", "client-unknown"} {
		body = map[string]any{"service_tier": tier}
		require.True(t, normalizeCodexServiceTierForUpstream(body), tier)
		_, ok := body["service_tier"]
		require.False(t, ok, tier)
	}

	// 非字符串 → 删除
	body = map[string]any{"service_tier": 42}
	require.True(t, normalizeCodexServiceTierForUpstream(body))
	_, ok = body["service_tier"]
	require.False(t, ok)
}

// applyCodexClientMetadata：用账号真实 device_id 注入 installation 标识，幂等、不覆盖既有项、不伪造。
func TestApplyCodexClientMetadata(t *testing.T) {
	// 仅 OpenAI OAuth 账号才有 device_id（GetOpenAIDeviceID 的门控）。
	acc := &Account{Platform: PlatformOpenAI, Type: AccountTypeOAuth, Extra: map[string]any{"openai_device_id": "dev-xyz"}}

	body := map[string]any{}
	require.True(t, applyCodexClientMetadata(body, acc))
	cm, ok := body["client_metadata"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, "dev-xyz", cm["x-codex-installation-id"])
	// 幂等
	require.False(t, applyCodexClientMetadata(body, acc))

	// OAuth 账号但无 device_id → 不写入（不伪造）
	body2 := map[string]any{}
	require.False(t, applyCodexClientMetadata(body2, &Account{Platform: PlatformOpenAI, Type: AccountTypeOAuth}))
	_, ok = body2["client_metadata"]
	require.False(t, ok)

	// 既有 client_metadata（如 turn metadata）保留，仅补 installation 键
	body3 := map[string]any{"client_metadata": map[string]any{"x-codex-turn-metadata": "t"}}
	require.True(t, applyCodexClientMetadata(body3, acc))
	cm3, _ := body3["client_metadata"].(map[string]any)
	require.Equal(t, "t", cm3["x-codex-turn-metadata"])
	require.Equal(t, "dev-xyz", cm3["x-codex-installation-id"])
}

// defaultCodexSynthInstructions：按模型选用真实 Codex base prompt。
func TestDefaultCodexSynthInstructionsModelAware(t *testing.T) {
	require.True(t, strings.Contains(defaultCodexSynthInstructions("gpt-5-codex"), "You are Codex, based on GPT-5"))
	require.True(t, strings.Contains(defaultCodexSynthInstructions("gpt-5.5"), "You are Codex, a coding agent based on GPT-5"))
	require.False(t, strings.Contains(defaultCodexSynthInstructions("gpt-5.5"), "You are GPT-5.1 running in the Codex CLI"))
	require.True(t, strings.Contains(defaultCodexSynthInstructions("gpt-5.2"), "You are GPT-5.2 running in the Codex CLI"))
	require.True(t, strings.Contains(defaultCodexSynthInstructions("gpt-5.1"), "You are GPT-5.1 running in the Codex CLI"))
}

// parallel_tool_calls：普通请求强制 true，Responses Lite 请求强制 false（与真实 Codex CLI 对齐）。
func TestApplyCodexOAuthTransformParallelToolCalls(t *testing.T) {
	// 缺省 → 补 true
	body := map[string]any{"model": "gpt-5.6-sol"}
	applyCodexOAuthTransformWithOptions(body, codexOAuthTransformOptions{})
	require.Equal(t, true, body["parallel_tool_calls"])

	// 显式 true → 保持
	body2 := map[string]any{"model": "gpt-5.6-sol", "parallel_tool_calls": true}
	applyCodexOAuthTransformWithOptions(body2, codexOAuthTransformOptions{})
	require.Equal(t, true, body2["parallel_tool_calls"])

	// Lite（body 标记）→ false
	body3 := map[string]any{
		"model":               "codex-auto-review",
		"client_metadata":     map[string]any{responsesLiteWSMetadataKey: true},
		"parallel_tool_calls": true,
	}
	applyCodexOAuthTransformWithOptions(body3, codexOAuthTransformOptions{})
	require.Equal(t, false, body3["parallel_tool_calls"])

	// Lite（option，来自入站头）→ false
	body4 := map[string]any{"model": "codex-auto-review"}
	applyCodexOAuthTransformWithOptions(body4, codexOAuthTransformOptions{IsResponsesLite: true})
	require.Equal(t, false, body4["parallel_tool_calls"])

	// Lite 标记为字符串 "true" 同样生效
	body5 := map[string]any{
		"client_metadata": map[string]any{responsesLiteWSMetadataKey: "true"},
	}
	applyCodexOAuthTransformWithOptions(body5, codexOAuthTransformOptions{})
	require.Equal(t, false, body5["parallel_tool_calls"])
}

// stripCodexPromptCacheBreakpoints：input 项与 content 分片两层的 prompt_cache_breakpoint 均剥除。
func TestStripCodexPromptCacheBreakpoints(t *testing.T) {
	body := map[string]any{
		"input": []any{
			map[string]any{
				"type":                    "message",
				"prompt_cache_breakpoint": true,
				"content": []any{
					map[string]any{"type": "input_text", "text": "hi", "prompt_cache_breakpoint": true},
				},
			},
			map[string]any{"type": "message", "role": "user"},
		},
	}
	require.True(t, stripCodexPromptCacheBreakpoints(body))
	items := body["input"].([]any)
	first := items[0].(map[string]any)
	_, exists := first["prompt_cache_breakpoint"]
	require.False(t, exists)
	part := first["content"].([]any)[0].(map[string]any)
	_, exists = part["prompt_cache_breakpoint"]
	require.False(t, exists)
	// 幂等
	require.False(t, stripCodexPromptCacheBreakpoints(body))
	// 非 input 结构不动
	require.False(t, stripCodexPromptCacheBreakpoints(map[string]any{}))
}

// OAuth 不支持字段清单：prompt_cache_options / context_management 剥除。
func TestApplyCodexOAuthTransformStripsCacheOptionsAndContextManagement(t *testing.T) {
	body := map[string]any{
		"model":                "gpt-5.6-sol",
		"prompt_cache_options": map[string]any{"keep": 1},
		"context_management":   map[string]any{},
	}
	applyCodexOAuthTransformWithOptions(body, codexOAuthTransformOptions{})
	_, ok := body["prompt_cache_options"]
	require.False(t, ok)
	_, ok = body["context_management"]
	require.False(t, ok)
}
