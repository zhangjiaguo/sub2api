package service

import (
	"net/http"
	"net/url"
	"testing"
	"time"

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

func TestOpenAITicketGrabServiceAcquireTicketEgressGating(t *testing.T) {
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
