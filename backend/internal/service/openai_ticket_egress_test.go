package service

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/tlsfingerprint"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newEgressTestSlot(t *testing.T) *openAITicketEgressSlot {
	t.Helper()
	proxyURL := &url.URL{Scheme: "http", Host: "proxy.example.com:10000"}
	return newOpenAITicketEgressSlot(1, 0, proxyURL, nil)
}

func TestOpenAITicketEgressSlotAttachTicket(t *testing.T) {
	settings := DefaultOpenAITicketGrabSettings()
	now := time.Now()

	t.Run("无票据不附带", func(t *testing.T) {
		slot := newEgressTestSlot(t)
		header := http.Header{}
		_, ok := slot.attachTicket(header, now)
		assert.False(t, ok)
		assert.Empty(t, header.Get(openAICodexTurnStateHeader))
	})

	t.Run("代数一致且未过期时附带", func(t *testing.T) {
		slot := newEgressTestSlot(t)
		ticket := &OpenAITicket{Value: "ticket-value", IssuedAt: now, ExpiresAt: now.Add(time.Hour)}
		slot.setTicket(ticket, 0, settings)
		slot.mu.Lock()
		slot.generation = 0
		slot.mu.Unlock()

		header := http.Header{}
		gen, ok := slot.attachTicket(header, now)
		assert.True(t, ok)
		assert.Equal(t, int64(0), gen)
		assert.Equal(t, "ticket-value", header.Get(openAICodexTurnStateHeader))
	})

	t.Run("连接重拨后代数失配不附带", func(t *testing.T) {
		slot := newEgressTestSlot(t)
		ticket := &OpenAITicket{Value: "ticket-value", IssuedAt: now, ExpiresAt: now.Add(time.Hour)}
		slot.setTicket(ticket, 0, settings)
		slot.mu.Lock()
		slot.generation = 1 // 连接重建
		slot.mu.Unlock()

		header := http.Header{}
		_, ok := slot.attachTicket(header, now)
		assert.False(t, ok)
		assert.Empty(t, header.Get(openAICodexTurnStateHeader))
	})

	t.Run("剩余有效期不足安全余量不附带", func(t *testing.T) {
		slot := newEgressTestSlot(t)
		ticket := &OpenAITicket{Value: "ticket-value", IssuedAt: now, ExpiresAt: now.Add(10 * time.Second)}
		slot.setTicket(ticket, 0, settings)

		header := http.Header{}
		_, ok := slot.attachTicket(header, now)
		assert.False(t, ok)
	})

	t.Run("请求自带 turn-state 时不覆盖", func(t *testing.T) {
		slot := newEgressTestSlot(t)
		ticket := &OpenAITicket{Value: "ticket-value", IssuedAt: now, ExpiresAt: now.Add(time.Hour)}
		slot.setTicket(ticket, 0, settings)

		header := http.Header{}
		header.Set(openAICodexTurnStateHeader, "client-echoed")
		_, ok := slot.attachTicket(header, now)
		assert.False(t, ok)
		assert.Equal(t, "client-echoed", header.Get(openAICodexTurnStateHeader))
	})
}

func TestOpenAITicketEgressSlotNeedsMint(t *testing.T) {
	settings := DefaultOpenAITicketGrabSettings() // TTL=3600 lead=1200
	now := time.Now()

	t.Run("无票据需要铸造", func(t *testing.T) {
		slot := newEgressTestSlot(t)
		assert.True(t, slot.needsMint(settings, now))
	})

	t.Run("有票且代数一致不需要", func(t *testing.T) {
		slot := newEgressTestSlot(t)
		slot.setTicket(&OpenAITicket{Value: "v", IssuedAt: now, ExpiresAt: now.Add(time.Hour)}, 0, settings)
		assert.False(t, slot.needsMint(settings, now.Add(time.Minute)))
	})

	t.Run("代数失配（连接重建）需要重铸", func(t *testing.T) {
		slot := newEgressTestSlot(t)
		slot.setTicket(&OpenAITicket{Value: "v", IssuedAt: now, ExpiresAt: now.Add(time.Hour)}, 0, settings)
		slot.mu.Lock()
		slot.generation = 1
		slot.mu.Unlock()
		assert.True(t, slot.needsMint(settings, now.Add(time.Minute)))
	})

	t.Run("进入提前补票窗口需要重铸", func(t *testing.T) {
		slot := newEgressTestSlot(t)
		slot.setTicket(&OpenAITicket{Value: "v", IssuedAt: now, ExpiresAt: now.Add(time.Hour)}, 0, settings)
		// TTL-lead = 2400s 后进入补票窗口
		assert.True(t, slot.needsMint(settings, now.Add(2500*time.Second)))
	})

	t.Run("铸造节奏未到不铸", func(t *testing.T) {
		slot := newEgressTestSlot(t)
		slot.setNextMint(now.Add(time.Minute))
		assert.False(t, slot.needsMint(settings, now))
	})
}

func TestOpenAITicketEgressSlotRotateOnRelease(t *testing.T) {
	settings := DefaultOpenAITicketGrabSettings()
	now := time.Now()

	slot := newEgressTestSlot(t)
	require.True(t, slot.tryAcquire())
	slot.setTicket(&OpenAITicket{Value: "v", IssuedAt: now, ExpiresAt: now.Add(time.Hour)}, 0, settings)
	slot.markRotate()

	slot.release()

	slot.mu.Lock()
	ticket := slot.ticketValue
	slot.mu.Unlock()
	assert.Empty(t, ticket, "403 轮换后票据应作废")

	// 释放后可再次占用
	assert.True(t, slot.tryAcquire())
	slot.release()
}

func TestOpenAITicketEgressManagerAcquire(t *testing.T) {
	proxyURL := &url.URL{Scheme: "http", Host: "proxy.example.com:10000"}
	account := &Account{ID: 7, Concurrency: 2}
	m := newOpenAITicketEgressManager(account, proxyURL, nil)
	require.Len(t, m.slots, 2)

	h1 := m.acquire()
	require.NotNil(t, h1)
	h2 := m.acquire()
	require.NotNil(t, h2)
	assert.Nil(t, m.acquire(), "槽位全忙应返回 nil")

	h1.slot.release()
	assert.NotNil(t, m.acquire(), "释放后应可重新占用")
}

func TestOpenAITicketGrabServiceAcquireTicketEgressGating(t *testing.T) {	svc := NewOpenAITicketGrabService(nil, nil, nil, nil, nil)
	cache := func(settings OpenAITicketGrabSettings) {
		svc.settingsMu.Lock()
		svc.settingsCache, svc.settingsLoaded = settings, time.Now()
		svc.settingsMu.Unlock()
	}
	settings := DefaultOpenAITicketGrabSettings()
	settings.Enabled = true
	settings.ProxyURL = "http://u:p@proxy.example.com:10000"
	settings.AccountIDs = []int64{1, 2}
	settings.AttachToForward = true
	settings.AttachAccountIDs = []int64{1}
	cache(settings)

	account := &Account{ID: 1, Platform: PlatformOpenAI, Type: AccountTypeOAuth}

	t.Run("未建池回落", func(t *testing.T) {
		assert.Nil(t, svc.AcquireTicketEgress(t.Context(), account))
	})

	proxyURL := &url.URL{Scheme: "http", Host: "proxy.example.com:10000"}
	svc.egressMu.Lock()
	svc.egress[1] = newOpenAITicketEgressManager(account, proxyURL, nil)
	svc.egressMu.Unlock()

	t.Run("灰度账号可获取", func(t *testing.T) {
		assert.NotNil(t, svc.AcquireTicketEgress(t.Context(), account))
	})

	t.Run("非灰度账号回落", func(t *testing.T) {
		other := &Account{ID: 2, Platform: PlatformOpenAI, Type: AccountTypeOAuth}
		assert.Nil(t, svc.AcquireTicketEgress(t.Context(), other))
	})

	t.Run("关闭接入后回落", func(t *testing.T) {
		off := settings
		off.AttachToForward = false
		cache(off)
		assert.Nil(t, svc.AcquireTicketEgress(t.Context(), account))
	})
}

func TestOpenAITicketGrabServiceEgressOverrideProxyURL(t *testing.T) {
	svc := NewOpenAITicketGrabService(nil, nil, nil, nil, nil)
	cache := func(settings OpenAITicketGrabSettings) {
		svc.settingsMu.Lock()
		svc.settingsCache, svc.settingsLoaded = settings, time.Now()
		svc.settingsMu.Unlock()
	}
	settings := DefaultOpenAITicketGrabSettings()
	settings.Enabled = true
	settings.ProxyURL = "http://u:p@proxy.example.com:10000"
	settings.AccountIDs = []int64{1, 2}
	cache(settings)

	account := &Account{ID: 1, Platform: PlatformOpenAI, Type: AccountTypeOAuth}

	t.Run("名单内账号返回打票代理", func(t *testing.T) {
		assert.Equal(t, "http://u:p@proxy.example.com:10000", svc.EgressOverrideProxyURL(t.Context(), account))
	})
	t.Run("名单外账号不覆盖", func(t *testing.T) {
		other := &Account{ID: 3, Platform: PlatformOpenAI, Type: AccountTypeOAuth}
		assert.Empty(t, svc.EgressOverrideProxyURL(t.Context(), other))
	})
	t.Run("关闭打票后回落", func(t *testing.T) {
		off := settings
		off.Enabled = false
		cache(off)
		assert.Empty(t, svc.EgressOverrideProxyURL(t.Context(), account))
		cache(settings)
	})
	t.Run("非 OpenAI OAuth 账号不覆盖", func(t *testing.T) {
		apikey := &Account{ID: 1, Platform: PlatformOpenAI, Type: AccountTypeAPIKey}
		assert.Empty(t, svc.EgressOverrideProxyURL(t.Context(), apikey))
	})
	t.Run("非法代理地址不覆盖", func(t *testing.T) {
		bad := settings
		bad.ProxyURL = "://bad"
		cache(bad)
		assert.Empty(t, svc.EgressOverrideProxyURL(t.Context(), account))
		cache(settings)
	})
	t.Run("空代理地址不覆盖", func(t *testing.T) {
		empty := settings
		empty.ProxyURL = ""
		cache(empty)
		assert.Empty(t, svc.EgressOverrideProxyURL(t.Context(), account))
		cache(settings)
	})
}

func TestOpenAITicketGrabSettingsAttachValidate(t *testing.T) {
	t.Run("未启用打票时接入转发联动关闭而非报错", func(t *testing.T) {
		// 总开关必须永远可关（9f6621505）：保存时静默回落，不因接入转发残留配置卡住。
		settings := DefaultOpenAITicketGrabSettings()
		settings.AttachToForward = true
		settings.AttachAccountIDs = []int64{1}
		err := settings.Validate()
		require.NoError(t, err)
		assert.False(t, settings.AttachToForward)
		assert.Empty(t, settings.AttachAccountIDs)
	})

	t.Run("接入转发需要灰度账号", func(t *testing.T) {
		settings := DefaultOpenAITicketGrabSettings()
		settings.Enabled = true
		settings.ProxyURL = "http://u:p@proxy.example.com:10000"
		settings.AccountIDs = []int64{1}
		settings.AttachToForward = true
		err := settings.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "灰度账号")
	})

	t.Run("灰度账号必须在打票账号列表内", func(t *testing.T) {
		settings := DefaultOpenAITicketGrabSettings()
		settings.Enabled = true
		settings.ProxyURL = "http://u:p@proxy.example.com:10000"
		settings.AccountIDs = []int64{1}
		settings.AttachToForward = true
		settings.AttachAccountIDs = []int64{2}
		err := settings.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "打票账号列表内")
	})

	t.Run("合法灰度配置通过", func(t *testing.T) {
		settings := DefaultOpenAITicketGrabSettings()
		settings.Enabled = true
		settings.ProxyURL = "http://u:p@proxy.example.com:10000"
		settings.AccountIDs = []int64{1, 2}
		settings.AttachToForward = true
		settings.AttachAccountIDs = []int64{2}
		require.NoError(t, settings.Validate())
	})
}

// ---- 打票出口覆盖：doOpenAIUpstream 每请求独立出口 + 403 换连接重试 ----

type egressOverrideStubRouter struct {
	override string
}

func (r egressOverrideStubRouter) AcquireTicketEgress(_ context.Context, _ *Account) *OpenAITicketEgressHandle {
	return nil
}

func (r egressOverrideStubRouter) EgressOverrideProxyURL(_ context.Context, _ *Account) string {
	return r.override
}

type egressRecordingUpstream struct {
	statuses []int
	bodies   []string
}

func (u *egressRecordingUpstream) Do(req *http.Request, _ string, _ int64, _ int) (*http.Response, error) {
	return u.record(req)
}

func (u *egressRecordingUpstream) DoWithTLS(req *http.Request, _ string, _ int64, _ int, _ *tlsfingerprint.Profile) (*http.Response, error) {
	return u.record(req)
}

func (u *egressRecordingUpstream) record(req *http.Request) (*http.Response, error) {
	body, _ := io.ReadAll(req.Body)
	_ = req.Body.Close()
	u.bodies = append(u.bodies, string(body))
	status := http.StatusOK
	if len(u.bodies) <= len(u.statuses) {
		status = u.statuses[len(u.bodies)-1]
	}
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{},
		Body:       io.NopCloser(bytes.NewReader(nil)),
		Request:    req,
	}, nil
}

func newEgressOverrideUpstreamTest(t *testing.T) (*OpenAIGatewayService, *egressRecordingUpstream) {
	t.Helper()
	upstream := &egressRecordingUpstream{}
	svc := &OpenAIGatewayService{
		httpUpstream: upstream,
		ticketEgress: egressOverrideStubRouter{override: "http://u:p@golon.example.com:10000"},
	}
	return svc, upstream
}

func egressOverrideTestAccount() *Account {
	return &Account{ID: 244, Platform: PlatformOpenAI, Type: AccountTypeOAuth, Name: "acct"}
}

func TestDoOpenAIUpstreamEgressOverrideRetries403WithFreshConnection(t *testing.T) {
	svc, upstream := newEgressOverrideUpstreamTest(t)
	upstream.statuses = []int{http.StatusForbidden, http.StatusOK}

	body := []byte(`{"model":"gpt-5.6-sol"}`)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		"https://chatgpt.com/backend-api/codex/responses", bytes.NewReader(body))
	require.NoError(t, err)
	require.NotNil(t, req.GetBody)

	resp, err := svc.doOpenAIUpstream(req, "http://account-proxy.example.com:1080", egressOverrideTestAccount())
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// 第一次抽中受限出口 403，第二次换连接重试成功；请求体两次完整重放。
	require.Len(t, upstream.bodies, 2)
	assert.Equal(t, string(body), upstream.bodies[0])
	assert.Equal(t, string(body), upstream.bodies[1])
}

func TestDoOpenAIUpstreamEgressOverrideNoRetryOnSuccess(t *testing.T) {
	svc, upstream := newEgressOverrideUpstreamTest(t)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		"https://chatgpt.com/backend-api/codex/responses", bytes.NewReader([]byte(`{"a":1}`)))
	require.NoError(t, err)

	resp, err := svc.doOpenAIUpstream(req, "", egressOverrideTestAccount())
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Len(t, upstream.bodies, 1)
}

func TestDoOpenAIUpstreamEgressOverrideNoRetryWithoutGetBody(t *testing.T) {
	svc, upstream := newEgressOverrideUpstreamTest(t)
	upstream.statuses = []int{http.StatusForbidden}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		"https://chatgpt.com/backend-api/codex/responses",
		io.NopCloser(bytes.NewReader([]byte(`{"a":1}`))))
	require.NoError(t, err)
	require.Nil(t, req.GetBody)

	resp, err := svc.doOpenAIUpstream(req, "", egressOverrideTestAccount())
	require.NoError(t, err)
	require.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.Len(t, upstream.bodies, 1)
}

func TestDoOpenAIUpstreamWithoutOverrideKeepsSingleAttempt(t *testing.T) {
	upstream := &egressRecordingUpstream{statuses: []int{http.StatusForbidden, http.StatusForbidden}}
	svc := &OpenAIGatewayService{
		httpUpstream: upstream,
		ticketEgress: egressOverrideStubRouter{override: ""},
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		"https://chatgpt.com/backend-api/codex/responses", bytes.NewReader([]byte(`{"a":1}`)))
	require.NoError(t, err)

	resp, err := svc.doOpenAIUpstream(req, "http://account-proxy.example.com:1080", egressOverrideTestAccount())
	require.NoError(t, err)
	require.Equal(t, http.StatusForbidden, resp.StatusCode)
	// 未覆盖时保持原行为：不重试、不禁用连接复用。
	assert.Len(t, upstream.bodies, 1)
	assert.False(t, req.Close)
}
