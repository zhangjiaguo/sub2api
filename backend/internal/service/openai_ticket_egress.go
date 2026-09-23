package service

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/tlsfingerprint"
)

// 打票出口接入（ticket egress）：把打票铸造的 turn-state 票据接到真实转发上，
// 并让真实转发的出站走「打票的出口」。
//
// 动态代理（golon）按 TCP 连接轮换出口，且不提供会话粘性；因此票据与出口的
// 严格一致只能靠「同一连接」保证。方案：每个接入账号维护 K 个槽位（K=账号并发，
// 上限 4），每个槽位是一条独占的 HTTP/1.1 连接：
//   - 连接经动态代理建立，TLS 握手使用账号解析出的 Codex 指纹
//     （与现有 tls_fingerprint 出站完全一致，utls，无 ALPN）；
//   - 票据直接在该槽位连接上铸造（探测请求复用槽位连接），因此
//     （票据，出口 IP）天然绑定；
//   - 真实转发命中槽位时附带该槽位的票据出站（仅当请求未自带
//     x-codex-turn-state 且票据未过期、连接代数一致）；
//   - MaxConnsPerHost=1 保证槽位内所有请求共用同一条连接 = 同一个出口；
//   - 连接代数（generation）在每次重新拨号时递增：票据铸造后连接若被重建
//     （空闲超时/服务端关闭/403 轮换），代数失配 ⇒ 票据不再附带，
//     调度循环会在新连接上重新铸造。
//
// 未命中槽位（灰度名单外 / 槽位全忙 / 尚未建池）的请求走原有出站路径，
// 行为与接入前完全一致。
const (
	// openAITicketEgressMaxSlotsPerAccount 每账号槽位上限。
	// 槽位数等于账号并发（连接即并发额度），过大会放大打票探测频率。
	openAITicketEgressMaxSlotsPerAccount = 4
	// openAITicketEgressIdleConnTimeout 槽位连接空闲超时：远大于 keepalive 间隔，
	// 正常情况下连接由 keepalive trace 保活不落回超时路径。
	openAITicketEgressIdleConnTimeout = 10 * time.Minute
	// openAITicketEgressKeepaliveEvery 空闲超过该时长的槽位补一个 /cdn-cgi/trace：
	// 既保活连接，也能提前发现被静默掐断的死连接（trace 可安全重试）。
	openAITicketEgressKeepaliveEvery = 60 * time.Second
	// openAITicketEgressKeepaliveTimeout 单次 keepalive trace 的超时。
	openAITicketEgressKeepaliveTimeout = 15 * time.Second
	// openAITicketEgressAttachMargin 附票安全余量：剩余有效期不足该值时不再附带，
	// 避免请求在上游侧因票据恰好过期而失效。
	openAITicketEgressAttachMargin = 30 * time.Second
	// openAITicketEgressHTTPSWarnEvery https 动态代理不支持指纹槽位的告警节流。
	openAITicketEgressHTTPSWarnEvery = time.Hour
)

// OpenAITicketEgressRouter 供网关出站路径获取「票据 + 固定出口」槽位。
type OpenAITicketEgressRouter interface {
	// AcquireTicketEgress 非阻塞获取账号的可用出站槽位；返回 nil 表示
	// 该请求不适用（未灰度 / 槽位全忙 / 未启用），调用方回落原有路径。
	AcquireTicketEgress(ctx context.Context, account *Account) *OpenAITicketEgressHandle
}

// OpenAITicketEgressHandle 一个已占用的出站槽位句柄：单请求生命周期内持有，
// 响应体关闭（或请求出错）时自动释放。
type OpenAITicketEgressHandle struct {
	slot *openAITicketEgressSlot
}

// RoundTrip 附带槽位票据并经槽位连接出站。err 非 nil 或响应体 Close 后槽位释放；
// 上游 403（出口被风控）时在释放后关闭槽位连接，触发换出口重铸。
func (h *OpenAITicketEgressHandle) RoundTrip(req *http.Request) (*http.Response, error) {
	slot := h.slot
	attachedGen, attached := slot.attachTicket(req.Header, time.Now())
	resp, err := slot.client.Do(req)
	if err != nil {
		slot.release()
		return nil, err
	}
	if attached && slot.currentGeneration() != attachedGen {
		// 拨号发生在附票之后（旧连接恰好死亡被重建）：票据与实际出口错位，
		// 无法撤回已发出的请求，但记录观测并使票据失效待重铸。
		slog.Warn("openai_ticket_egress_generation_drift",
			"account_id", slot.accountID, "slot", slot.index,
			"ticket_gen", attachedGen, "conn_gen", slot.currentGeneration())
		slot.invalidateTicket()
	}
	if resp.StatusCode == http.StatusForbidden {
		slot.markRotate()
	}
	// Go transport 透明解压时会残留 Content-Encoding 头，与真实出站路径的
	// 修复逻辑保持一致（网关按解压后的体解析 SSE/计费）。
	if resp.Uncompressed {
		resp.Header.Del("Content-Encoding")
		resp.Header.Del("Content-Length")
	}
	resp.Body = &openAITicketEgressBody{ReadCloser: resp.Body, slot: slot}
	return resp, nil
}

// openAITicketEgressBody 槽位响应体：关闭时释放槽位（并处理挂起的轮换）。
type openAITicketEgressBody struct {
	io.ReadCloser
	once sync.Once
	slot *openAITicketEgressSlot
}

func (b *openAITicketEgressBody) Close() error {
	err := b.ReadCloser.Close()
	b.once.Do(func() { b.slot.release() })
	return err
}

// openAITicketEgressSlot 单条「固定出口 + 票据」连接槽位。
type openAITicketEgressSlot struct {
	accountID int64
	index     int

	transport *http.Transport
	client    *http.Client
	inUse     chan struct{} // 容量 1 的信号量：请求进行中独占

	mu          sync.Mutex
	generation  int64 // 连接代数：每次 DialTLS 成功 +1
	rotateFlag  bool  // 响应 403：释放后关闭连接换出口
	nextMintAt  time.Time
	lastActive  time.Time
	ticketValue string
	ticketGen   int64
	ticketFP    string
	ticketExit  string
	ticketColo  string
	ticketIssAt time.Time
	ticketExpAt time.Time
	ticketRfAt  time.Time // 建议重铸时间 = 签发 + (TTL - lead)
}

func newOpenAITicketEgressSlot(accountID int64, index int, proxyURL *url.URL, profile *tlsfingerprint.Profile) *openAITicketEgressSlot {
	slot := &openAITicketEgressSlot{
		accountID: accountID,
		index:     index,
		inUse:     make(chan struct{}, 1),
	}
	transport := &http.Transport{
		MaxIdleConns:        1,
		MaxIdleConnsPerHost: 1,
		MaxConnsPerHost:     1,
		IdleConnTimeout:     openAITicketEgressIdleConnTimeout,
		// 与 buildUpstreamTransportWithTLSFingerprint 一致：自定义 DialTLSContext
		// 携带 utls 指纹（Codex 为 OpenSSL/HTTP1.1，无 ALPN），显式不升 h2。
		ForceAttemptHTTP2: false,
	}
	var base func(ctx context.Context, network, addr string) (net.Conn, error)
	switch strings.ToLower(proxyURL.Scheme) {
	case "socks5", "socks5h":
		base = tlsfingerprint.NewSOCKS5ProxyDialer(profile, proxyURL).DialTLSContext
	default:
		base = tlsfingerprint.NewHTTPProxyDialer(profile, proxyURL).DialTLSContext
	}
	transport.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := base(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		// 连接代数只统计票据目标主机（chatgpt.com）的拨号：票据与其铸造连接
		// 绑定，其他主机的连接（若出现）不应作废票据。MaxConnsPerHost 按主机
		// 独立计数，chatgpt.com 始终独占一条连接 = 一个出口。
		if host, _, splitErr := net.SplitHostPort(addr); splitErr == nil && strings.EqualFold(host, "chatgpt.com") {
			slot.mu.Lock()
			slot.generation++
			gen := slot.generation
			slot.mu.Unlock()
			slog.Info("openai_ticket_egress_dial",
				"account_id", slot.accountID, "slot", slot.index, "generation", gen)
		}
		return conn, nil
	}
	slot.transport = transport
	slot.client = &http.Client{Transport: transport}
	return slot
}

// tryAcquire 非阻塞占用槽位（真实转发与铸造共用同一信号量）。
func (slot *openAITicketEgressSlot) tryAcquire() bool {
	select {
	case slot.inUse <- struct{}{}:
		return true
	default:
		return false
	}
}

// release 释放槽位；挂起 403 轮换时关闭空闲连接并作废票据。
func (slot *openAITicketEgressSlot) release() {
	<-slot.inUse
	slot.mu.Lock()
	rotate := slot.rotateFlag
	slot.rotateFlag = false
	slot.lastActive = time.Now()
	if rotate {
		slot.ticketValue = ""
	}
	slot.mu.Unlock()
	if rotate {
		slot.transport.CloseIdleConnections()
		slog.Info("openai_ticket_egress_rotate",
			"account_id", slot.accountID, "slot", slot.index, "reason", "http_403")
	}
}

func (slot *openAITicketEgressSlot) markRotate() {
	slot.mu.Lock()
	slot.rotateFlag = true
	slot.mu.Unlock()
}

func (slot *openAITicketEgressSlot) currentGeneration() int64 {
	slot.mu.Lock()
	defer slot.mu.Unlock()
	return slot.generation
}

// attachTicket 附带槽位票据；返回附带时的连接代数。仅在票据有效、代数一致、
// 未过期（含安全余量）且请求未自带 turn-state（客户端回带的会话状态优先）时附带。
func (slot *openAITicketEgressSlot) attachTicket(header http.Header, now time.Time) (int64, bool) {
	slot.mu.Lock()
	defer slot.mu.Unlock()
	if slot.ticketValue == "" || slot.ticketGen != slot.generation {
		return 0, false
	}
	if !now.Add(openAITicketEgressAttachMargin).Before(slot.ticketExpAt) {
		return 0, false
	}
	if header.Get(openAICodexTurnStateHeader) != "" {
		return 0, false
	}
	header.Set(openAICodexTurnStateHeader, slot.ticketValue)
	return slot.ticketGen, true
}

func (slot *openAITicketEgressSlot) invalidateTicket() {
	slot.mu.Lock()
	slot.ticketValue = ""
	slot.mu.Unlock()
}

// setTicket 记录一次成功铸造：票据与其铸造时的连接代数绑定。
func (slot *openAITicketEgressSlot) setTicket(ticket *OpenAITicket, gen int64, settings OpenAITicketGrabSettings) {
	slot.mu.Lock()
	defer slot.mu.Unlock()
	slot.ticketValue = ticket.Value
	slot.ticketGen = gen
	slot.ticketFP = ticket.Fingerprint
	slot.ticketExit = ticket.ExitIP
	slot.ticketColo = ticket.ExitColo
	slot.ticketIssAt = ticket.IssuedAt
	slot.ticketExpAt = ticket.ExpiresAt
	slot.ticketRfAt = ticket.IssuedAt.Add(time.Duration(settings.TTLSeconds-settings.LeadSeconds) * time.Second)
}

// needsMint 判断槽位是否需要铸造：无票据 / 代数失配（连接已重建）/ 进入提前窗口。
func (slot *openAITicketEgressSlot) needsMint(settings OpenAITicketGrabSettings, now time.Time) bool {
	slot.mu.Lock()
	defer slot.mu.Unlock()
	if now.Before(slot.nextMintAt) {
		return false
	}
	if slot.ticketValue == "" || slot.ticketGen != slot.generation {
		return true
	}
	return now.After(slot.ticketRfAt)
}

func (slot *openAITicketEgressSlot) setNextMint(at time.Time) {
	slot.mu.Lock()
	slot.nextMintAt = at
	slot.mu.Unlock()
}

// keepalive 空闲槽位补一个 trace 保活连接（GET 无 body，可被 transport 安全重试）。
// 先占信号量：槽位忙（请求/铸造中）时跳过，避免 trace 排在长流响应后面拖慢巡检。
func (slot *openAITicketEgressSlot) keepalive(parent context.Context) {
	slot.mu.Lock()
	idleFor := time.Since(slot.lastActive)
	slot.mu.Unlock()
	if idleFor < openAITicketEgressKeepaliveEvery {
		return
	}
	if !slot.tryAcquire() {
		return
	}
	defer slot.release()
	ctx, cancel := context.WithTimeout(parent, openAITicketEgressKeepaliveTimeout)
	defer cancel()
	openAITicketTraceExit(ctx, slot.client)
}

func (slot *openAITicketEgressSlot) close() {
	slot.transport.CloseIdleConnections()
}

// snapshot 状态视图（管理端展示）。注意先复制字段再探测忙闲：
// 不能持 mu 去碰 inUse（与铸造路径的 inUse→mu 顺序相反）。
func (slot *openAITicketEgressSlot) snapshot() *OpenAITicketEgressSlotStatus {
	slot.mu.Lock()
	st := &OpenAITicketEgressSlotStatus{
		Index:      slot.index,
		Generation: slot.generation,
		TicketOK:   slot.ticketValue != "" && slot.ticketGen == slot.generation,
	}
	if !slot.ticketExpAt.IsZero() {
		st.TicketExpiresUnix = slot.ticketExpAt.Unix()
	}
	if !slot.nextMintAt.IsZero() {
		st.NextMintUnix = slot.nextMintAt.Unix()
	}
	if st.TicketOK {
		st.ExitIP, st.ExitColo = slot.ticketExit, slot.ticketColo
	}
	slot.mu.Unlock()
	select {
	case slot.inUse <- struct{}{}:
		<-slot.inUse
		st.Busy = false
	default:
		st.Busy = true
	}
	return st
}

// OpenAITicketEgressSlotStatus 槽位状态视图。
type OpenAITicketEgressSlotStatus struct {
	Index             int    `json:"index"`
	ExitIP            string `json:"exit_ip"`
	ExitColo          string `json:"exit_colo"`
	Generation        int64  `json:"generation"`
	TicketOK          bool   `json:"ticket_ok"`
	TicketExpiresUnix int64  `json:"ticket_expires_unix"`
	NextMintUnix      int64  `json:"next_mint_unix"`
	Busy              bool   `json:"busy"`
}

// openAITicketEgressManager 每账号的槽位池。
type openAITicketEgressManager struct {
	accountID int64
	k         int
	slots     []*openAITicketEgressSlot
}

func newOpenAITicketEgressManager(account *Account, proxyURL *url.URL, profile *tlsfingerprint.Profile) *openAITicketEgressManager {
	k := account.Concurrency
	if k < 1 {
		k = 1
	}
	if k > openAITicketEgressMaxSlotsPerAccount {
		k = openAITicketEgressMaxSlotsPerAccount
	}
	m := &openAITicketEgressManager{accountID: account.ID, k: k, slots: make([]*openAITicketEgressSlot, k)}
	for i := range m.slots {
		m.slots[i] = newOpenAITicketEgressSlot(account.ID, i, proxyURL, profile)
	}
	return m
}

// acquire 顺序找一个空闲槽位；全忙返回 nil（调用方回落原路径）。
func (m *openAITicketEgressManager) acquire() *OpenAITicketEgressHandle {
	for _, slot := range m.slots {
		if slot.tryAcquire() {
			return &OpenAITicketEgressHandle{slot: slot}
		}
	}
	return nil
}

func (m *openAITicketEgressManager) snapshot() []*OpenAITicketEgressSlotStatus {
	out := make([]*OpenAITicketEgressSlotStatus, 0, len(m.slots))
	for _, slot := range m.slots {
		out = append(out, slot.snapshot())
	}
	return out
}

func (m *openAITicketEgressManager) close() {
	for _, slot := range m.slots {
		slot.close()
	}
}

// --- OpenAITicketGrabService 的出口槽位接入实现 ---

// openAITicketAttachEnabled 判断账号是否在接入灰度名单内。
func openAITicketAttachEnabled(settings OpenAITicketGrabSettings, accountID int64) bool {
	for _, id := range settings.AttachAccountIDs {
		if id == accountID {
			return true
		}
	}
	return false
}

// AcquireTicketEgress 实现 OpenAITicketEgressRouter：网关出站热路径调用。
func (s *OpenAITicketGrabService) AcquireTicketEgress(ctx context.Context, account *Account) *OpenAITicketEgressHandle {
	if s == nil || account == nil {
		return nil
	}
	settings := s.loadSettings(ctx)
	if !settings.Enabled || !settings.AttachToForward {
		return nil
	}
	if !openAITicketAttachEnabled(settings, account.ID) {
		return nil
	}
	s.egressMu.RLock()
	m := s.egress[account.ID]
	s.egressMu.RUnlock()
	if m == nil {
		// 槽位池由调度循环创建；尚未建池（刚启动/刚开启灰度）时回落原路径。
		return nil
	}
	return m.acquire()
}

// egressTicketsReady 判断账号所有槽位是否都有可用票据（手动打票结果判定用）。
func (s *OpenAITicketGrabService) egressTicketsReady(accountID int64) bool {
	s.egressMu.RLock()
	m := s.egress[accountID]
	s.egressMu.RUnlock()
	if m == nil || len(m.slots) == 0 {
		return false
	}
	for _, slot := range m.slots {
		slot.mu.Lock()
		ok := slot.ticketValue != "" && slot.ticketGen == slot.generation
		slot.mu.Unlock()
		if !ok {
			return false
		}
	}
	return true
}

// resetEgress 清空全部槽位池（配置变更后由下一轮调度按新配置重建）。
func (s *OpenAITicketGrabService) resetEgress() {
	s.egressMu.Lock()
	managers := s.egress
	s.egress = make(map[int64]*openAITicketEgressManager)
	s.egressMu.Unlock()
	for _, m := range managers {
		m.close()
	}
}

// egressManagerFor 取（或建）账号槽位池。池一旦建立即固定槽位数与指纹模板；
// 代理地址 / 槽位数 / 指纹模板的变更通过更新配置触发 resetEgress 生效。
func (s *OpenAITicketGrabService) egressManagerFor(account *Account, proxyURL *url.URL) *openAITicketEgressManager {
	s.egressMu.Lock()
	defer s.egressMu.Unlock()
	if m := s.egress[account.ID]; m != nil {
		return m
	}
	m := newOpenAITicketEgressManager(account, proxyURL, s.resolveTicketEgressProfile(account))
	s.egress[account.ID] = m
	slog.Info("openai_ticket_egress_manager_created", "account_id", account.ID, "slots", m.k)
	return m
}

// resolveTicketEgressProfile 槽位连接使用的 TLS 指纹：与账号真实出站一致；
// 账号未启用指纹时按 Codex CLI 形态出站（接入模式即代表以 Codex 客户端身份行走）。
func (s *OpenAITicketGrabService) resolveTicketEgressProfile(account *Account) *tlsfingerprint.Profile {
	if s.profileResolver != nil {
		if profile := s.profileResolver(account); profile != nil {
			return profile
		}
	}
	return tlsfingerprint.CodexProfile
}

// reconcileEgressAccount 一轮槽位维护：保活、按需铸造、失配重铸。
// force=true（手动「立即打票」）时忽略补票节奏，对所有槽位重新铸造。
func (s *OpenAITicketGrabService) reconcileEgressAccount(ctx context.Context, account *Account, settings OpenAITicketGrabSettings, proxyURL *url.URL, force bool) {
	if strings.EqualFold(proxyURL.Scheme, "https") {
		// 指纹拨号器发的是明文 CONNECT，无法与 https 代理握手。
		s.warnTicketEgressHTTPS(account.ID)
		return
	}
	m := s.egressManagerFor(account, proxyURL)
	rt := s.runtime(account.ID)
	rt.mu.Lock()
	cooling := time.Now().Before(rt.cooldownUntil)
	rt.mu.Unlock()
	for _, slot := range m.slots {
		slot.keepalive(ctx)
		if cooling {
			continue
		}
		if !force && !slot.needsMint(settings, time.Now()) {
			continue
		}
		if !slot.tryAcquire() {
			continue // 真实转发占用优先，本轮跳过
		}
		s.mintTicketOnSlot(ctx, account, settings, slot)
		slot.release()
	}
}

// warnTicketEgressHTTPS https 动态代理告警（节流）。
func (s *OpenAITicketGrabService) warnTicketEgressHTTPS(accountID int64) {
	s.egressMu.Lock()
	last := s.egressHTTPSWarnAt[accountID]
	now := time.Now()
	if now.Sub(last) >= openAITicketEgressHTTPSWarnEvery {
		s.egressHTTPSWarnAt[accountID] = now
	}
	s.egressMu.Unlock()
	if now.Sub(last) >= openAITicketEgressHTTPSWarnEvery {
		slog.Warn("openai_ticket_egress_https_proxy_unsupported",
			"account_id", accountID, "hint", "https 动态代理不支持指纹槽位，接入转发未生效")
	}
}

// mintTicketOnSlot 在槽位连接上铸造票据（探测复用槽位连接 ⇒ 票据与出口绑定）。
// 调用方保证已持有槽位信号量。
func (s *OpenAITicketGrabService) mintTicketOnSlot(ctx context.Context, account *Account, settings OpenAITicketGrabSettings, slot *openAITicketEgressSlot) {
	rt := s.runtime(account.ID)
	rt.mu.Lock()
	rt.probing = true
	rt.mu.Unlock()

	outcome := openAITicketProbeOutcome{result: "network_error"}
	httpStatus := 0
	var ticket *OpenAITicket
	var meta *openAITicketGrabLogMeta
	defer func() {
		outcome.detail = openAITicketSlotDetail(outcome.detail, slot.index)
		s.recordGrabLog(ctx, account.ID, outcome, httpStatus, meta)
		rt := s.runtime(account.ID)
		rt.mu.Lock()
		rt.lastResult, rt.lastProbeAt, rt.probing = outcome.result, time.Now(), false
		rt.mu.Unlock()
	}()

	if s.tokenProvider == nil {
		outcome.result, outcome.detail, outcome.retryNextRound = "no_token_provider", "token provider unavailable", true
		return
	}
	token, err := s.tokenProvider.GetAccessToken(ctx, account)
	if err != nil {
		outcome.result, outcome.detail, outcome.retryNextRound = "token_error", err.Error(), true
		return
	}

	probeCtx, cancel := context.WithTimeout(ctx, time.Duration(settings.ProbeTimeoutSecs)*time.Second)
	defer cancel()
	outcome, ticket, httpStatus, meta = s.probeCore(probeCtx, account, settings, token, slot.client)

	switch {
	case outcome.result == "accepted" && ticket != nil:
		gen := slot.currentGeneration()
		slot.setTicket(ticket, gen, settings)
		slot.setNextMint(ticket.IssuedAt.Add(time.Duration(settings.TTLSeconds-settings.LeadSeconds) * time.Second))
		if err := s.repo.UpsertTicket(ctx, ticket); err != nil {
			slog.Warn("openai_ticket_egress upsert ticket failed", "account_id", account.ID, "error", err)
		}
		slog.Info("openai_ticket_egress_minted",
			"account_id", account.ID, "slot", slot.index, "generation", gen,
			"exit_ip", ticket.ExitIP, "exit_colo", ticket.ExitColo,
			"state_len", ticket.StateLength)
	default:
		cooldown, kind := openAITicketGrabCooldownForResult(outcome.result, outcome.retryAfter, settings)
		slot.setNextMint(time.Now().Add(cooldown))
		if kind != "" { // 429/401 是账号级决定，全账号槽位停铸
			rt := s.runtime(account.ID)
			rt.mu.Lock()
			rt.cooldownUntil, rt.cooldownKind = time.Now().Add(cooldown), kind
			rt.mu.Unlock()
		}
		if outcome.result == "http_403" {
			// 出口被拒：关闭槽位连接换出口（释放语义外的直接轮换，
			// 此时槽位由铸造持有、无并发请求）。
			slot.mu.Lock()
			slot.ticketValue = ""
			slot.mu.Unlock()
			slot.transport.CloseIdleConnections()
		}
	}
}

// openAITicketSlotDetail 给打票日志详情附加槽位编号。
func openAITicketSlotDetail(detail string, index int) string {
	detail = strings.TrimSpace(detail)
	if detail != "" {
		detail += "; "
	}
	return detail + "slot=" + strconv.Itoa(index)
}
