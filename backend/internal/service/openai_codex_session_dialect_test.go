package service

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeleteCodexHeaderAllSpellings(t *testing.T) {
	h := http.Header{}
	h["session-id"] = []string{"a"} // canonical
	h["SESSION_ID"] = []string{"b"} // 原始大写下划线
	h["Session_Id"] = []string{"c"} // canonical 下划线
	h["session_id"] = []string{"d"} // 原始小写下划线
	h.Set("x-keep", "kept")

	deleteCodexHeaderAllSpellings(h, "session-id")
	deleteCodexHeaderAllSpellings(h, "session_id")

	assert.Empty(t, h.Get("session-id"))
	assert.Empty(t, h.Get("session_id"))
	assert.Equal(t, "kept", h.Get("x-keep"))
	assert.Len(t, h, 1, "全部拼写形态都应被剥除")
}

func TestStripCodexSessionDialectHeaders(t *testing.T) {
	h := http.Header{}
	for _, name := range codexLegacySessionDialectHeaders {
		h.Set(name, "value")
	}
	h.Set("x-codex-window-id", "window")

	stripCodexSessionDialectHeaders(h)

	for _, name := range codexLegacySessionDialectHeaders {
		assert.Empty(t, h.Get(name), name)
	}
	assert.Equal(t, "window", h.Get("x-codex-window-id"), "window-id 不在剥除清单")
}

func TestReadClientCodexSessionHeaders(t *testing.T) {
	hyphen := http.Header{}
	hyphen.Set("session-id", " hyphen-session ")
	hyphen.Set("thread-id", "hyphen-thread")
	identity := readClientCodexSessionHeaders(hyphen)
	assert.Equal(t, "hyphen-session", identity.SessionID)
	assert.True(t, identity.HasSession)
	assert.Equal(t, "hyphen-thread", identity.ThreadID)
	assert.True(t, identity.HasThread)

	underscore := http.Header{}
	underscore.Set("session_id", "underscore-session")
	identity = readClientCodexSessionHeaders(underscore)
	assert.Equal(t, "underscore-session", identity.SessionID, "旧下划线形态回退读取")
	assert.True(t, identity.HasSession)
	assert.False(t, identity.HasThread)

	both := http.Header{}
	both.Set("session_id", "underscore-session")
	both.Set("session-id", "hyphen-session")
	identity = readClientCodexSessionHeaders(both)
	assert.Equal(t, "hyphen-session", identity.SessionID, "连字符形态优先")

	assert.False(t, readClientCodexSessionHeaders(nil).HasSession)
}

func TestApplyCodexSessionDialectHeaders(t *testing.T) {
	account := &Account{ID: 7, Platform: PlatformOpenAI, Type: AccountTypeOAuth,
		Credentials: map[string]any{"chatgpt_account_id": "dialect-acc"}}

	t.Run("empty seed writes nothing", func(t *testing.T) {
		h := http.Header{}
		applyCodexSessionDialectHeaders(h, 0, account, "  ", "")
		assert.Empty(t, h)
	})

	t.Run("client thread isolated verbatim shape", func(t *testing.T) {
		h := http.Header{}
		applyCodexSessionDialectHeaders(h, 5, account, "seed-session", "client-thread")
		assert.Equal(t, isolateOpenAIUpstreamSessionID(5, account, "seed-session"), h.Get("session-id"))
		assert.Equal(t, isolateOpenAIUpstreamSessionID(5, account, "client-thread"), h.Get("thread-id"))
		assert.Equal(t, h.Get("thread-id"), h.Get("x-client-request-id"), "x-client-request-id 恒等于 thread-id")
	})

	t.Run("no client thread derives stable thread from session", func(t *testing.T) {
		first := http.Header{}
		second := http.Header{}
		applyCodexSessionDialectHeaders(first, 5, account, "seed-session", "")
		applyCodexSessionDialectHeaders(second, 5, account, "seed-session", "")
		require.NotEmpty(t, first.Get("thread-id"))
		assert.Equal(t, first.Get("thread-id"), second.Get("thread-id"), "同种子派生线程必须稳定")
		assert.Equal(t, first.Get("thread-id"), first.Get("x-client-request-id"))
		assert.NotEqual(t, first.Get("session-id"), first.Get("thread-id"), "线程与会是不同标识")
	})

	t.Run("different api keys isolate apart", func(t *testing.T) {
		first := http.Header{}
		second := http.Header{}
		applyCodexSessionDialectHeaders(first, 5, account, "seed-session", "")
		applyCodexSessionDialectHeaders(second, 6, account, "seed-session", "")
		assert.NotEqual(t, first.Get("session-id"), second.Get("session-id"))
	})
}
