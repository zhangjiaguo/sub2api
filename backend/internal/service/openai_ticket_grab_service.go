package service

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/openai"
	"github.com/Wei-Shaw/sub2api/internal/pkg/tlsfingerprint"
)

// 打票（OpenAI Codex turn-state 采集）：
// 用短探测请求（"Reply with OK."）经可配置的动态代理出口打上游
// /backend-api/codex/responses，从响应头 x-codex-turn-state 采集票据。
// 有效票据 = base64 封装合法（0x80 前缀 + 8 字节大端时间戳 + 16 字节块对齐）
// 且长度/块数符合配置期望（实测 gpt-6-astra 为 780 字符 / 33 块）。
// 出口 IP 通过同一 HTTP 连接上的 GET /cdn-cgi/trace 获取（连接复用保证
// trace 与打票请求共享同一代理隧道，展示的 IP 即该次打票的真实出口）。
const (
	// SettingKeyOpenAITicketGrab 打票配置（JSON）的设置键。
	SettingKeyOpenAITicketGrab = "openai_ticket_grab"

	// openAITicketGrabTick 调度巡检间隔。
	openAITicketGrabTick = 15 * time.Second
	// openAITicketGrabSettingsCacheTTL 配置缓存时长（PUT 时主动失效）。
	openAITicketGrabSettingsCacheTTL = 30 * time.Second
	// openAITicketGrabStatsWindow 成功率/有效率统计窗口。
	openAITicketGrabStatsWindow = 24 * time.Hour
	// openAITicketGrabAttemptGap 同一轮内两次探测之间的间隔（换出口重试前的喘息）。
	openAITicketGrabAttemptGap = 2 * time.Second
	// openAITicketGrabBodyLimit 探测响应体读取上限（探测回复很小，1MiB 足够）。
	openAITicketGrabBodyLimit = 1 << 20
	// openAITicketGrab429Cooldown 上游 429 后的账号冷却下限。
	openAITicketGrab429Cooldown = 10 * time.Minute
	// openAITicketGrabAuthCooldown 401 后的账号冷却（凭据失效不会因换出口自愈）。
	openAITicketGrabAuthCooldown = 30 * time.Minute
)

// OpenAITicketGrabSettings 打票配置。
type OpenAITicketGrabSettings struct {
	Enabled           bool    `json:"enabled"`
	ProxyURL          string  `json:"proxy_url"`
	Model             string  `json:"model"`
	AccountIDs        []int64 `json:"account_ids"`
	LeadSeconds       int     `json:"lead_seconds"`
	TTLSeconds        int     `json:"ttl_seconds"`
	MinIntervalSecond int     `json:"min_interval_seconds"`
	ProbeTimeoutSecs  int     `json:"probe_timeout_seconds"`
	ExpectedLength    int     `json:"expected_length"`
	ExpectedBlocks    int     `json:"expected_blocks"`
	MaxProbesPerRound int     `json:"max_probes_per_round"`
	// AttachToForward 把票据接到真实转发：出站走「打票的出口」槽位
	// （见 openai_ticket_egress.go），仅对 AttachAccountIDs 灰度账号生效。
	AttachToForward  bool    `json:"attach_to_forward"`
	AttachAccountIDs []int64 `json:"attach_account_ids"`
	// ForwardAccountIDs 转发出口覆盖名单（三态，必须是打票名单的子集）：
	// 未配置（nil，JSON 缺键）= 打票名单全部账号的转发出站走打票代理
	// （与历史版本行为一致）；空数组 = 不覆盖任何账号（转发回落各自
	// 静态代理，打票探测仍走打票代理）；非空 = 仅名单内账号被覆盖。
	// 打票探测路径不经此名单——它直接使用 ProxyURL，与转发出口解耦。
	ForwardAccountIDs []int64 `json:"forward_account_ids,omitempty"`
}

// DefaultOpenAITicketGrabSettings 默认值基于 2026-09-23 实测：
// gpt-6-astra 票据 780 字符 / 33 块；TTL 按上游实测 1 小时；
// 提前 1200 秒（20 分钟）补票；打票最小间隔 180 秒。
func DefaultOpenAITicketGrabSettings() OpenAITicketGrabSettings {
	return OpenAITicketGrabSettings{
		Enabled:           false,
		ProxyURL:          "",
		Model:             "gpt-6-astra",
		AccountIDs:        []int64{},
		LeadSeconds:       1200,
		TTLSeconds:        3600,
		MinIntervalSecond: 180,
		ProbeTimeoutSecs:  60,
		ExpectedLength:    780,
		ExpectedBlocks:    33,
		MaxProbesPerRound: 3,
		AttachToForward:   false,
		AttachAccountIDs:  []int64{},
	}
}

// Validate 校验并规范化配置。
func (s *OpenAITicketGrabSettings) Validate() error {
	if s.Model == "" {
		s.Model = "gpt-6-astra"
	}
	if s.LeadSeconds < 30 {
		s.LeadSeconds = 30
	}
	if s.LeadSeconds > s.TTLSeconds {
		s.TTLSeconds = s.LeadSeconds
	}
	if s.MinIntervalSecond < 30 {
		s.MinIntervalSecond = 30
	}
	if s.ProbeTimeoutSecs < 15 {
		s.ProbeTimeoutSecs = 15
	}
	if s.ProbeTimeoutSecs > 300 {
		s.ProbeTimeoutSecs = 300
	}
	if s.ExpectedLength <= 0 {
		s.ExpectedLength = 780
	}
	if s.ExpectedBlocks <= 0 {
		s.ExpectedBlocks = 33
	}
	if s.MaxProbesPerRound < 1 {
		s.MaxProbesPerRound = 1
	}
	if s.MaxProbesPerRound > 10 {
		s.MaxProbesPerRound = 10
	}
	if s.Enabled {
		if s.ProxyURL == "" {
			return errors.New("启用打票需要配置动态代理")
		}
		if _, err := parseOpenAITicketProxyURL(s.ProxyURL); err != nil {
			return err
		}
		if len(s.AccountIDs) == 0 {
			return errors.New("启用打票需要选择至少一个账号")
		}
	}
	// 关闭打票时联动关闭接入转发（真实转发立即回落账号原有出口出站），
	// 不再因「接入转发需要先启用打票」报错卡住保存——总开关必须永远可关。
	if !s.Enabled {
		s.AttachToForward = false
	}
	if s.AttachToForward {
		if len(s.AttachAccountIDs) == 0 {
			return errors.New("接入转发需要选择至少一个灰度账号")
		}
		accounts := make(map[int64]bool, len(s.AccountIDs))
		for _, id := range s.AccountIDs {
			accounts[id] = true
		}
		for _, id := range s.AttachAccountIDs {
			if !accounts[id] {
				return fmt.Errorf("接入转发的账号 %d 必须在打票账号列表内", id)
			}
		}
	} else {
		s.AttachAccountIDs = []int64{}
	}
	// 转发出口名单必须是打票名单子集；nil（未配置）与空数组语义不同
	// （全部覆盖 vs 全不覆盖），此处绝不把 nil 归一化成空数组。
	if s.ForwardAccountIDs != nil {
		accounts := make(map[int64]bool, len(s.AccountIDs))
		for _, id := range s.AccountIDs {
			accounts[id] = true
		}
		for _, id := range s.ForwardAccountIDs {
			if !accounts[id] {
				return fmt.Errorf("转发出口的账号 %d 必须在打票账号列表内", id)
			}
		}
	}
	if s.AccountIDs == nil {
		s.AccountIDs = []int64{}
	}
	if s.AttachAccountIDs == nil {
		s.AttachAccountIDs = []int64{}
	}
	return nil
}

func parseOpenAITicketProxyURL(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("代理地址无法解析: %w", err)
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https", "socks5", "socks5h":
	default:
		return nil, fmt.Errorf("代理协议必须是 http/https/socks5/socks5h，当前: %q", u.Scheme)
	}
	if u.Host == "" {
		return nil, errors.New("代理地址缺少主机")
	}
	return u, nil
}

// OpenAITicket 当前票据。
type OpenAITicket struct {
	AccountID   int64     `json:"account_id"`
	Value       string    `json:"value"`
	StateLength int       `json:"state_length"`
	Blocks      int       `json:"blocks"`
	IssuedAt    time.Time `json:"issued_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	ExitIP      string    `json:"exit_ip"`
	ExitColo    string    `json:"exit_colo"`
	Fingerprint string    `json:"fingerprint"`
	Model       string    `json:"model"`
	PlanType    string    `json:"plan_type"`
	UsedPercent string    `json:"used_percent"`
	HTTPStatus  int       `json:"http_status"`
	DurationMS  int       `json:"duration_ms"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// OpenAITicketGrabLog 单次打票记录。
type OpenAITicketGrabLog struct {
	ID          int64     `json:"id"`
	AccountID   int64     `json:"account_id"`
	Result      string    `json:"result"`
	HTTPStatus  int       `json:"http_status"`
	StateLength int       `json:"state_length"`
	Blocks      int       `json:"blocks"`
	ExitIP      string    `json:"exit_ip"`
	ExitColo    string    `json:"exit_colo"`
	Detail      string    `json:"detail,omitempty"`
	DurationMS  int       `json:"duration_ms"`
	CreatedAt   time.Time `json:"created_at"`
}

// OpenAITicketGrabStats 窗口内统计。
type OpenAITicketGrabStats struct {
	Total   int64 `json:"total"`
	Success int64 `json:"success"`
	Valid   int64 `json:"valid"`
}

// OpenAITicketGrabRepository 打票数据访问接口。
type OpenAITicketGrabRepository interface {
	GetTicket(ctx context.Context, accountID int64) (*OpenAITicket, error)
	UpsertTicket(ctx context.Context, t *OpenAITicket) error
	InsertGrabLog(ctx context.Context, log *OpenAITicketGrabLog) error
	ListGrabLogs(ctx context.Context, accountID int64, limit, offset int) ([]*OpenAITicketGrabLog, error)
	AccountGrabStats(ctx context.Context, accountIDs []int64, window time.Duration) (map[int64]*OpenAITicketGrabStats, error)
}

// openAITicketAccountRuntime 每账号调度运行时（内存态，重启即重建）。
type openAITicketAccountRuntime struct {
	mu            sync.Mutex
	cooldownUntil time.Time
	cooldownKind  string // "auth"=凭据冷却 "rate_limit"=上游限流 ""=常规轮换节奏
	nextProbeAt   time.Time
	lastResult    string
	lastProbeAt   time.Time
	probing       bool
}

// OpenAITicketGrabService 打票调度服务。
type OpenAITicketGrabService struct {
	repo            OpenAITicketGrabRepository
	accountRepo     AccountRepository
	tokenProvider   *OpenAITokenProvider
	settingRepo     SettingRepository
	profileResolver func(*Account) *tlsfingerprint.Profile

	settingsMu     sync.RWMutex
	settingsCache  OpenAITicketGrabSettings
	settingsLoaded time.Time

	runtimesMu sync.Mutex
	runtimes   map[int64]*openAITicketAccountRuntime

	// egress 接入转发的槽位池（openai_ticket_egress.go）。
	egressMu          sync.RWMutex
	egress            map[int64]*openAITicketEgressManager
	egressHTTPSWarnAt map[int64]time.Time

	stopCh   chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup
}

// NewOpenAITicketGrabService 构造打票服务。profileResolver 用于解析槽位连接的
// TLS 指纹模板，可为 nil（接入转发未启用时不依赖它）。
func NewOpenAITicketGrabService(
	repo OpenAITicketGrabRepository,
	accountRepo AccountRepository,
	tokenProvider *OpenAITokenProvider,
	settingRepo SettingRepository,
	profileResolver func(*Account) *tlsfingerprint.Profile,
) *OpenAITicketGrabService {
	return &OpenAITicketGrabService{
		repo:              repo,
		accountRepo:       accountRepo,
		tokenProvider:     tokenProvider,
		settingRepo:       settingRepo,
		profileResolver:   profileResolver,
		runtimes:          make(map[int64]*openAITicketAccountRuntime),
		egress:            make(map[int64]*openAITicketEgressManager),
		egressHTTPSWarnAt: make(map[int64]time.Time),
		stopCh:            make(chan struct{}),
	}
}

// Start 启动调度循环。
func (s *OpenAITicketGrabService) Start() {
	if s == nil || s.repo == nil || s.accountRepo == nil {
		return
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		ticker := time.NewTicker(openAITicketGrabTick)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				s.runOnce(context.Background())
			case <-s.stopCh:
				return
			}
		}
	}()
}

// Stop 停止调度循环。
func (s *OpenAITicketGrabService) Stop() {
	if s == nil {
		return
	}
	s.stopOnce.Do(func() { close(s.stopCh) })
	s.wg.Wait()
	s.resetEgress()
}

// loadSettings 读取配置（带缓存；PUT 后主动失效）。
func (s *OpenAITicketGrabService) loadSettings(ctx context.Context) OpenAITicketGrabSettings {
	s.settingsMu.RLock()
	if !s.settingsLoaded.IsZero() && time.Since(s.settingsLoaded) < openAITicketGrabSettingsCacheTTL {
		cached := s.settingsCache
		s.settingsMu.RUnlock()
		return cached
	}
	s.settingsMu.RUnlock()

	settings := DefaultOpenAITicketGrabSettings()
	if s.settingRepo != nil {
		if raw, err := s.settingRepo.GetValue(ctx, SettingKeyOpenAITicketGrab); err == nil && strings.TrimSpace(raw) != "" {
			if err := json.Unmarshal([]byte(raw), &settings); err != nil {
				slog.Warn("openai_ticket_grab settings decode failed, using defaults", "error", err)
				settings = DefaultOpenAITicketGrabSettings()
			}
		}
	} else {
		return settings
	}
	_ = settings.Validate()

	s.settingsMu.Lock()
	s.settingsCache, s.settingsLoaded = settings, time.Now()
	s.settingsMu.Unlock()
	return settings
}

// GetSettings 返回当前配置。
func (s *OpenAITicketGrabService) GetSettings(ctx context.Context) OpenAITicketGrabSettings {
	return s.loadSettings(ctx)
}

// UpdateSettings 校验并保存配置。
func (s *OpenAITicketGrabService) UpdateSettings(ctx context.Context, settings OpenAITicketGrabSettings) error {
	if err := settings.Validate(); err != nil {
		return err
	}
	raw, err := json.Marshal(settings)
	if err != nil {
		return err
	}
	if s.settingRepo == nil {
		return errors.New("setting repository unavailable")
	}
	if err := s.settingRepo.Set(ctx, SettingKeyOpenAITicketGrab, string(raw)); err != nil {
		return fmt.Errorf("save ticket grab settings: %w", err)
	}
	s.settingsMu.Lock()
	s.settingsCache, s.settingsLoaded = settings, time.Now()
	s.settingsMu.Unlock()
	// 配置变更后重建槽位池（代理地址 / 灰度名单 / 槽位相关设置均随之生效）。
	s.resetEgress()
	return nil
}

func (s *OpenAITicketGrabService) runtime(accountID int64) *openAITicketAccountRuntime {
	s.runtimesMu.Lock()
	defer s.runtimesMu.Unlock()
	rt := s.runtimes[accountID]
	if rt == nil {
		rt = &openAITicketAccountRuntime{}
		s.runtimes[accountID] = rt
	}
	return rt
}

// runOnce 一轮巡检：对每个启用账号判断是否需要补票。
// 接入转发（attach）的账号改走槽位维护：保活、按需在槽位连接上铸造、失配重铸。
func (s *OpenAITicketGrabService) runOnce(ctx context.Context) {
	settings := s.loadSettings(ctx)
	if !settings.Enabled {
		return
	}
	proxyURL, err := parseOpenAITicketProxyURL(settings.ProxyURL)
	if err != nil {
		return
	}
	for _, accountID := range settings.AccountIDs {
		if ctx.Err() != nil {
			return
		}
		account, err := s.accountRepo.GetByID(ctx, accountID)
		if err != nil || account == nil {
			continue
		}
		if account.Platform != PlatformOpenAI || account.Type != AccountTypeOAuth {
			continue
		}
		if settings.AttachToForward && openAITicketAttachEnabled(settings, accountID) {
			s.reconcileEgressAccount(ctx, account, settings, proxyURL, false)
			continue
		}
		rt := s.runtime(accountID)
		rt.mu.Lock()
		skip := rt.probing || time.Now().Before(rt.cooldownUntil) || time.Now().Before(rt.nextProbeAt)
		rt.mu.Unlock()
		if skip || !s.needsTicket(ctx, accountID, settings) {
			continue
		}
		s.grabRoundResult(ctx, account, settings, proxyURL)
	}
}

// needsTicket 判断账号是否需要补票：无票据或已进入提前窗口。
func (s *OpenAITicketGrabService) needsTicket(ctx context.Context, accountID int64, settings OpenAITicketGrabSettings) bool {
	ticket, err := s.repo.GetTicket(ctx, accountID)
	if err != nil {
		slog.Warn("openai_ticket_grab get ticket failed", "account_id", accountID, "error", err)
		return false
	}
	if ticket == nil {
		return true
	}
	refreshAt := ticket.IssuedAt.Add(time.Duration(settings.TTLSeconds-settings.LeadSeconds) * time.Second)
	return time.Now().After(refreshAt)
}

// grabRoundResult 执行一轮打票（最多 MaxProbesPerRound 次尝试，每次换一个动态出口）
// 并返回最终结果。429/401 是上游账号级决定：换出口不会改变结果，本轮终止；
// 403 多为出口 IP 被 Cloudflare/OpenAI 风控拒绝，本轮内继续换出口重试。
func (s *OpenAITicketGrabService) grabRoundResult(ctx context.Context, account *Account, settings OpenAITicketGrabSettings, proxyURL *url.URL) string {
	rt := s.runtime(account.ID)
	rt.mu.Lock()
	if rt.probing {
		rt.mu.Unlock()
		return "busy"
	}
	rt.probing = true
	rt.mu.Unlock()
	defer func() {
		rt.mu.Lock()
		rt.probing = false
		rt.mu.Unlock()
	}()

	for i := 0; i < settings.MaxProbesPerRound; i++ {
		outcome := s.probeOnce(ctx, account, settings, proxyURL)
		rt.mu.Lock()
		rt.lastResult, rt.lastProbeAt = outcome.result, time.Now()
		cooldown, kind := openAITicketGrabCooldownForResult(outcome.result, outcome.retryAfter, settings)
		switch {
		case outcome.result == "accepted":
			// 成功后按「提前秒数」计算下一次补票时间。
			rt.nextProbeAt = time.Now().Add(time.Duration(settings.TTLSeconds-settings.LeadSeconds) * time.Second)
			rt.mu.Unlock()
			return outcome.result
		default:
			rt.cooldownUntil = time.Now().Add(cooldown)
			rt.cooldownKind = kind
		}
		rt.mu.Unlock()
		if outcome.retryNextRound {
			return outcome.result
		}
		if ctx.Err() != nil {
			return outcome.result
		}
		select {
		case <-time.After(openAITicketGrabAttemptGap):
		case <-ctx.Done():
			return outcome.result
		}
	}
	return rt.lastResult
}

// openAITicketGrabCooldownForResult 计算一次失败探测后的账号冷却时长与原因：
// 429 尊重 Retry-After（下限 10 分钟）；401 凭据失效长冷却 30 分钟；
// 403 是出口 IP 被拒，仅按最小间隔节奏轮换出口继续打，不做长冷却。
func openAITicketGrabCooldownForResult(result string, retryAfter time.Duration, settings OpenAITicketGrabSettings) (time.Duration, string) {
	switch result {
	case "http_429":
		if retryAfter > openAITicketGrab429Cooldown {
			return retryAfter, "rate_limit"
		}
		return openAITicketGrab429Cooldown, "rate_limit"
	case "http_401":
		return openAITicketGrabAuthCooldown, "auth"
	default:
		// 含 http_403 / 网络错误 / 票据不合格等：常规轮换节奏。
		return time.Duration(settings.MinIntervalSecond) * time.Second, ""
	}
}

// openAITicketProbeOutcome 单次探测结果。
type openAITicketProbeOutcome struct {
	result         string
	retryAfter     time.Duration
	retryNextRound bool // 上游账号级拒绝（429/401/403），不应继续换出口重试
	detail         string
}

// probeOnce 执行一次「临时出口」打票并落库：独立 Transport = 新连接 = 新出口。
func (s *OpenAITicketGrabService) probeOnce(ctx context.Context, account *Account, settings OpenAITicketGrabSettings, proxyURL *url.URL) openAITicketProbeOutcome {
	outcome := openAITicketProbeOutcome{result: "network_error"}
	if s.tokenProvider == nil {
		outcome.result, outcome.detail = "no_token_provider", "token provider unavailable"
		s.recordGrabLog(ctx, account.ID, outcome, 0, nil)
		outcome.retryNextRound = true
		return outcome
	}
	token, err := s.tokenProvider.GetAccessToken(ctx, account)
	if err != nil {
		outcome.result, outcome.detail = "token_error", err.Error()
		outcome.retryNextRound = true
		s.recordGrabLog(ctx, account.ID, outcome, 0, nil)
		return outcome
	}

	// 每次探测独立拨号 = 新连接 = 新出口 IP。手工 H1 线格式写出器替换裸
	// http.Transport：连接经 CodexProfile utls 指纹拨号器建立（与真实转发
	// 同源；https 代理形态的指纹拨号器只发明文 CONNECT，回落原 Transport），
	// 请求头全小写固定序、请求体按 codex 字段序手工构造，探测流量与真实
	// Codex CLI 出站同构（TLS/HTTP/JSON 三层）。取连接走共享预热池，
	// 探测不用在关键路径上支付握手。
	var client *http.Client
	if strings.EqualFold(proxyURL.Scheme, "https") {
		transport := &http.Transport{
			Proxy:               http.ProxyURL(proxyURL),
			MaxIdleConns:        2,
			MaxIdleConnsPerHost: 2,
			IdleConnTimeout:     90 * time.Second,
		}
		client = &http.Client{Transport: transport}
		defer transport.CloseIdleConnections()
	} else {
		profile := s.resolveTicketEgressProfile(account)
		var dial func(ctx context.Context, network, addr string) (net.Conn, error)
		switch strings.ToLower(proxyURL.Scheme) {
		case "socks5", "socks5h":
			dial = tlsfingerprint.NewSOCKS5ProxyDialer(profile, proxyURL).DialTLSContext
		default:
			dial = tlsfingerprint.WarmHTTPProxyDialerFor(profile, proxyURL, nil)
		}
		wire := &openAITicketWireRoundTripper{dial: dial}
		defer wire.Close()
		client = &http.Client{Transport: wire}
	}

	probeCtx, cancel := context.WithTimeout(ctx, time.Duration(settings.ProbeTimeoutSecs)*time.Second)
	defer cancel()
	outcome, ticket, httpStatus, meta := s.probeCore(probeCtx, account, settings, token, client)

	if outcome.result == "accepted" && ticket != nil {
		if err := s.repo.UpsertTicket(ctx, ticket); err != nil {
			slog.Warn("openai_ticket_grab upsert ticket failed", "account_id", account.ID, "error", err)
		}
	}
	s.recordGrabLog(ctx, account.ID, outcome, httpStatus, meta)
	return outcome
}

// probeCore 在给定 client 上执行「trace 定位出口 + 短探测」，返回结果、
// 铸造出的票据（accepted 时非 nil）与落库日志上下文。client 的连接语义由
// 调用方决定：临时轮换出口（probeOnce）或固定出口槽位（mintTicketOnSlot）。
func (s *OpenAITicketGrabService) probeCore(ctx context.Context, account *Account, settings OpenAITicketGrabSettings, token string, client *http.Client) (openAITicketProbeOutcome, *OpenAITicket, int, *openAITicketGrabLogMeta) {
	outcome := openAITicketProbeOutcome{result: "network_error"}

	// 先 trace 拿出口 IP：同一 client 复用连接，打票请求将走同一代理隧道。
	exitIP, exitColo := openAITicketTraceExit(ctx, client)
	meta := &openAITicketGrabLogMeta{ip: exitIP, colo: exitColo}

	// 探测体按 codex-rs ResponsesApiRequest 字段序手工构造（map 序列化会按
	// 字母序重排且缺 reasoning/client_metadata 等真实字段）；身份头补齐到与
	// 真实转发同构（installation/session/thread/window + turn metadata）。
	identity := resolveOpenAITicketProbeIdentity(account)
	body := buildOpenAITicketProbeRequestBody(settings.Model, identity)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://chatgpt.com/backend-api/codex/responses", bytes.NewReader(body))
	if err != nil {
		outcome.result, outcome.detail = "request_error", err.Error()
		return outcome, nil, 0, meta
	}
	req.Host = "chatgpt.com"
	req.Header.Set("authorization", "Bearer "+token)
	if acctID := account.GetChatGPTAccountID(); acctID != "" {
		req.Header.Set("chatgpt-account-id", acctID)
	}
	// 与网关出站身份同源：UA/originator/version 使用规范 Codex 身份
	// （版本来自设置同步，落后会被上游 400 "requires a newer version of Codex"）。
	req.Header.Set("user-agent", CodexCanonicalUserAgent())
	req.Header.Set("originator", openai.CodexDefaultOriginator)
	req.Header.Set("version", CodexCanonicalClientVersion())
	req.Header.Set("openai-beta", "responses=experimental")
	req.Header.Set("session_id", identity.sessionID)
	req.Header.Set("conversation_id", identity.threadID)
	req.Header.Set("x-codex-installation-id", identity.installationID)
	req.Header.Set("x-codex-window-id", identity.windowID)
	req.Header.Set("x-codex-turn-metadata", buildOpenAITicketTurnMetadataJSON(identity))
	req.Header.Set("accept", "text/event-stream")
	req.Header.Set("content-type", "application/json")

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		outcome.result, outcome.detail = "network_error", err.Error()
		meta.dur = time.Since(start)
		return outcome, nil, 0, meta
	}
	defer resp.Body.Close()
	duration := time.Since(start)
	meta.dur = duration

	state := strings.TrimSpace(resp.Header.Get(openAICodexTurnStateHeader))
	data, _ := io.ReadAll(io.LimitReader(resp.Body, openAITicketGrabBodyLimit))

	if resp.StatusCode != http.StatusOK {
		outcome.result = "http_" + strconv.Itoa(resp.StatusCode)
		outcome.detail = openAITicketUpstreamErrorDetail(data)
		outcome.retryAfter = openAITicketParseRetryAfter(resp.Header.Get("Retry-After"))
		// 429/401 是账号级决定（限流/凭据失效），换出口无意义，本轮终止；
		// 403 多为出口 IP 被 Cloudflare/OpenAI 风控拒绝，继续换出口轮换重试。
		outcome.retryNextRound = resp.StatusCode == http.StatusTooManyRequests ||
			resp.StatusCode == http.StatusUnauthorized
		return outcome, nil, resp.StatusCode, meta
	}

	model := openAITicketStreamModel(data)
	completed := bytes.Contains(data, []byte(`"response.completed"`))

	outcome.result, outcome.detail = classifyOpenAITicketProbe(state, completed, time.Now(), settings)
	parsed, _ := parseOpenAITicketState(state)
	meta.state, meta.parsed = state, parsed

	var ticket *OpenAITicket
	if outcome.result == "accepted" {
		fingerprint := sha256.Sum256([]byte(state))
		ticket = &OpenAITicket{
			AccountID:   account.ID,
			Value:       state,
			StateLength: len(state),
			Blocks:      parsed.blocks,
			IssuedAt:    parsed.issuedAt,
			ExpiresAt:   parsed.issuedAt.Add(time.Duration(settings.TTLSeconds) * time.Second),
			ExitIP:      exitIP,
			ExitColo:    exitColo,
			Fingerprint: hex.EncodeToString(fingerprint[:8]),
			Model:       model,
			PlanType:    resp.Header.Get("x-codex-plan-type"),
			UsedPercent: resp.Header.Get("x-codex-primary-used-percent"),
			HTTPStatus:  resp.StatusCode,
			DurationMS:  int(duration.Milliseconds()),
		}
	}
	slog.Info("openai_ticket_grab_probe",
		"account_id", account.ID, "result", outcome.result,
		"exit_ip", exitIP, "exit_colo", exitColo,
		"state_len", len(state), "model", model,
		"duration_ms", duration.Milliseconds())
	return outcome, ticket, resp.StatusCode, meta
}

// openAITicketGrabLogMeta 落库日志所需的探测上下文。
type openAITicketGrabLogMeta struct {
	ip, colo string
	dur      time.Duration
	state    string
	parsed   openAITicketParsedState
}

func (s *OpenAITicketGrabService) recordGrabLog(ctx context.Context, accountID int64, outcome openAITicketProbeOutcome, httpStatus int, meta *openAITicketGrabLogMeta) {
	log := &OpenAITicketGrabLog{
		AccountID:  accountID,
		Result:     outcome.result,
		HTTPStatus: httpStatus,
		Detail:     outcome.detail,
	}
	if meta != nil {
		log.ExitIP, log.ExitColo = meta.ip, meta.colo
		log.DurationMS = int(meta.dur.Milliseconds())
		log.StateLength = len(meta.state)
		log.Blocks = meta.parsed.blocks
	}
	// 打码 detail：错误详情可能透出 URL/凭据片段，仅保留前 200 字符。
	if len(log.Detail) > 200 {
		log.Detail = log.Detail[:200]
	}
	if err := s.repo.InsertGrabLog(context.WithoutCancel(ctx), log); err != nil {
		slog.Warn("openai_ticket_grab insert log failed", "account_id", accountID, "error", err)
	}
}

// openAITicketStateFreshWindow 票据封装内时间戳的可信窗口：
// 上游在本轮探测时铸造的票据时间戳应贴近当前时刻（允许小幅时钟偏差）。
const (
	openAITicketStateFreshWindow = 10 * time.Minute
	openAITicketStateClockSkew   = 5 * time.Minute
)

// classifyOpenAITicketProbe 对 200 探测结果分级。
//
// 票据在响应头即已铸造——SSE 流是否跑到 response.completed 不影响票据本身
// （实测代理掐断流时 780/33 票据已完整送达）。因此采收标准为：
// 封装合法 + 形态符合期望 + 封装时间戳新鲜；流提前结束只作备注不再弃票。
func classifyOpenAITicketProbe(state string, completed bool, now time.Time, settings OpenAITicketGrabSettings) (result, detail string) {
	if state == "" {
		return "missing_state", "上游 200 但响应缺少 turn-state 头"
	}
	parsed, parseErr := parseOpenAITicketState(state)
	if parseErr != nil {
		return "state_invalid", parseErr.Error()
	}
	shapeOK := parsed.blocks == settings.ExpectedBlocks && len(state) == settings.ExpectedLength
	if !shapeOK {
		return "shape_mismatch", fmt.Sprintf("state %d 块 / %d 字符，期望 %d 块 / %d 字符",
			parsed.blocks, len(state), settings.ExpectedBlocks, settings.ExpectedLength)
	}
	fresh := parsed.issuedAt.After(now.Add(-openAITicketStateFreshWindow)) &&
		parsed.issuedAt.Before(now.Add(openAITicketStateClockSkew))
	if !fresh {
		return "stale_state", fmt.Sprintf("票据形态正确但签发时间异常（%s）", parsed.issuedAt.Format(time.RFC3339))
	}
	if !completed {
		return "accepted", "票据已铸造且形态正确，探测流提前结束"
	}
	return "accepted", ""
}

// openAITicketParsedState turn-state 封装解析结果。
type openAITicketParsedState struct {
	blocks   int
	issuedAt time.Time
}

// parseOpenAITicketState 解析 turn-state 封装：
// base64url（至多 2 个 padding 字符）→ 0x80 前缀 + 8 字节大端签发时间戳 +
// (57 + 16*blocks) 字节净荷。780 字符 ⇔ 33 块（实测 gpt-6-astra）。
func parseOpenAITicketState(value string) (openAITicketParsedState, error) {
	var parsed openAITicketParsedState
	value = strings.TrimSpace(value)
	if len(value) > 2048 || strings.ContainsAny(value, "\r\n\t ") {
		return parsed, errors.New("state 编码非法（长度或空白字符）")
	}
	core := strings.TrimRight(value, "=")
	if len(value)-len(core) > 2 {
		return parsed, errors.New("state padding 非法")
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(core)
	if err != nil || len(raw) < 73 || raw[0] != 0x80 || (len(raw)-57)%16 != 0 {
		return parsed, errors.New("state 封装格式无法识别")
	}
	issued := binary.BigEndian.Uint64(raw[1:9])
	if issued < 1577836800 || issued >= 4102444800 {
		return parsed, errors.New("state 时间戳超出合理范围")
	}
	return openAITicketParsedState{blocks: (len(raw) - 57) / 16, issuedAt: time.Unix(int64(issued), 0).UTC()}, nil
}

// openAITicketTraceExit 通过 /cdn-cgi/trace 获取当前代理隧道的出口 IP/colo。
// chatgpt.com 在 Cloudflare 后，trace 会回显出口地址；调用方保证与打票请求
// 共用同一 client（连接复用），因此这里拿到的就是打票连接的真实出口。
// 请求头保持 Codex 身份（UA 等）：裸 GET（Go 默认 "Go-http-client/1.1" UA）
// 紧挨着探测 POST 出现在同一连接上是明显的机器特征。
func openAITicketTraceExit(ctx context.Context, client *http.Client) (ip, colo string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://chatgpt.com/cdn-cgi/trace", nil)
	if err != nil {
		return "", ""
	}
	req.Host = "chatgpt.com"
	req.Header.Set("user-agent", CodexCanonicalUserAgent())
	req.Header.Set("accept", "*/*")
	resp, err := client.Do(req)
	if err != nil {
		return "", ""
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	for _, line := range strings.Split(string(data), "\n") {
		if v, ok := strings.CutPrefix(line, "ip="); ok {
			ip = strings.TrimSpace(v)
		}
		if v, ok := strings.CutPrefix(line, "colo="); ok {
			colo = strings.TrimSpace(v)
		}
	}
	return ip, colo
}

// openAITicketStreamModel 从 SSE 流中提取首个 model 声明（response.created）。
func openAITicketStreamModel(data []byte) string {
	for _, chunk := range bytes.Split(data, []byte("\n")) {
		line := strings.TrimSpace(string(chunk))
		if payload, ok := strings.CutPrefix(line, "data: "); !ok {
			continue
		} else {
			var ev struct {
				Type     string `json:"type"`
				Response struct {
					Model string `json:"model"`
				} `json:"response"`
			}
			if json.Unmarshal([]byte(payload), &ev) == nil && ev.Type == "response.created" && ev.Response.Model != "" {
				return ev.Response.Model
			}
		}
	}
	return ""
}

// openAITicketUpstreamErrorDetail 提取上游错误体的简短摘要。
func openAITicketUpstreamErrorDetail(data []byte) string {
	detail := strings.TrimSpace(string(data))
	if len(detail) > 200 {
		detail = detail[:200]
	}
	return detail
}

// openAITicketParseRetryAfter 解析 Retry-After（秒数或 HTTP 日期）。
func openAITicketParseRetryAfter(value string) time.Duration {
	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil && seconds > 0 {
		return time.Duration(seconds) * time.Second
	}
	if at, err := http.ParseTime(value); err == nil {
		if delay := time.Until(at); delay > 0 {
			return delay
		}
	}
	return 0
}

// TestProxy 连通性测试：连续 3 次独立连接取动态出口样本。
func (s *OpenAITicketGrabService) TestProxy(ctx context.Context, rawURL string) ([]map[string]any, error) {
	proxyURL, err := parseOpenAITicketProxyURL(rawURL)
	if err != nil {
		return nil, err
	}
	samples := make([]map[string]any, 0, 3)
	for i := 0; i < 3; i++ {
		transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
		client := &http.Client{Transport: transport, Timeout: 25 * time.Second}
		start := time.Now()
		ip, colo := openAITicketTraceExit(ctx, client)
		transport.CloseIdleConnections()
		sample := map[string]any{
			"ip":         ip,
			"colo":       colo,
			"latency_ms": time.Since(start).Milliseconds(),
			"ok":         ip != "",
		}
		samples = append(samples, sample)
		if i < 2 {
			select {
			case <-time.After(500 * time.Millisecond):
			case <-ctx.Done():
				return samples, ctx.Err()
			}
		}
	}
	return samples, nil
}

// RunNow 手动触发一次打票（尊重进行中的探测与 429/凭据冷却，但忽略常规频率间隔）。
func (s *OpenAITicketGrabService) RunNow(ctx context.Context, accountID int64) error {
	settings := s.loadSettings(ctx)
	if !settings.Enabled {
		return errors.New("打票未启用")
	}
	proxyURL, err := parseOpenAITicketProxyURL(settings.ProxyURL)
	if err != nil {
		return err
	}
	account, err := s.accountRepo.GetByID(ctx, accountID)
	if err != nil || account == nil {
		return errors.New("账号不存在")
	}
	if account.Platform != PlatformOpenAI || account.Type != AccountTypeOAuth {
		return errors.New("仅支持 OpenAI OAuth 账号")
	}
	rt := s.runtime(accountID)
	rt.mu.Lock()
	if rt.probing {
		rt.mu.Unlock()
		return errors.New("该账号正在打票中")
	}
	if time.Now().Before(rt.cooldownUntil) {
		seconds := int(time.Until(rt.cooldownUntil).Seconds()) + 1
		kind := rt.cooldownKind
		rt.mu.Unlock()
		switch kind {
		case "auth":
			return fmt.Errorf("账号冷却中（凭据问题，换出口无法自愈），请 %d 秒后再试", seconds)
		case "rate_limit":
			return fmt.Errorf("账号冷却中（上游限流），请 %d 秒后再试", seconds)
		default:
			return fmt.Errorf("出口轮换冷却中，请 %d 秒后再试", seconds)
		}
	}
	rt.mu.Unlock()

	// 接入转发的账号：手动打票 = 立即对所有槽位重新铸造（尊重账号冷却）。
	if settings.AttachToForward && openAITicketAttachEnabled(settings, accountID) {
		s.reconcileEgressAccount(ctx, account, settings, proxyURL, true)
		if s.egressTicketsReady(accountID) {
			return nil
		}
		rt := s.runtime(accountID)
		rt.mu.Lock()
		last := rt.lastResult
		rt.mu.Unlock()
		return fmt.Errorf("打票未成功: %s", last)
	}

	outcome := s.grabRoundResult(ctx, account, settings, proxyURL)
	if outcome == "accepted" {
		return nil
	}
	return fmt.Errorf("打票未成功: %s", outcome)
}

// AccountStatus 单账号打票状态视图。
type OpenAITicketGrabAccountStatus struct {
	AccountID       int64                           `json:"account_id"`
	AccountName     string                          `json:"account_name"`
	Status          string                          `json:"status"`
	Ticket          *OpenAITicket                   `json:"ticket,omitempty"`
	RemainingSecond int                             `json:"remaining_seconds"`
	NextProbeUnix   int64                           `json:"next_probe_unix"`
	CooldownUnix    int64                           `json:"cooldown_unix"`
	LastResult      string                          `json:"last_result"`
	Probing         bool                            `json:"probing"`
	Stats           *OpenAITicketGrabStats          `json:"stats,omitempty"`
	AttachMode      bool                            `json:"attach_mode"`
	EgressSlots     []*OpenAITicketEgressSlotStatus `json:"egress_slots,omitempty"`
}

// Status 汇总所有启用账号的状态。
func (s *OpenAITicketGrabService) Status(ctx context.Context) ([]*OpenAITicketGrabAccountStatus, error) {
	settings := s.loadSettings(ctx)
	statuses := make([]*OpenAITicketGrabAccountStatus, 0, len(settings.AccountIDs))
	if len(settings.AccountIDs) == 0 {
		return statuses, nil
	}
	stats, err := s.repo.AccountGrabStats(ctx, settings.AccountIDs, openAITicketGrabStatsWindow)
	if err != nil {
		slog.Warn("openai_ticket_grab stats failed", "error", err)
		stats = map[int64]*OpenAITicketGrabStats{}
	}
	for _, accountID := range settings.AccountIDs {
		st := &OpenAITicketGrabAccountStatus{AccountID: accountID}
		if account, err := s.accountRepo.GetByID(ctx, accountID); err == nil && account != nil {
			st.AccountName, st.Status = account.Name, account.Status
		} else {
			st.AccountName, st.Status = fmt.Sprintf("#%d", accountID), "missing"
		}
		if ticket, err := s.repo.GetTicket(ctx, accountID); err == nil && ticket != nil {
			st.Ticket = ticket
			remaining := int(time.Until(ticket.ExpiresAt).Seconds())
			if remaining < 0 {
				remaining = 0
			}
			st.RemainingSecond = remaining
		}
		rt := s.runtime(accountID)
		rt.mu.Lock()
		st.LastResult, st.Probing = rt.lastResult, rt.probing
		if !rt.nextProbeAt.IsZero() {
			st.NextProbeUnix = rt.nextProbeAt.Unix()
		}
		if !rt.cooldownUntil.IsZero() {
			st.CooldownUnix = rt.cooldownUntil.Unix()
		}
		rt.mu.Unlock()
		if v, ok := stats[accountID]; ok {
			st.Stats = v
		}
		if settings.AttachToForward && openAITicketAttachEnabled(settings, accountID) {
			st.AttachMode = true
			s.egressMu.RLock()
			m := s.egress[accountID]
			s.egressMu.RUnlock()
			if m != nil {
				st.EgressSlots = m.snapshot()
			}
		}
		statuses = append(statuses, st)
	}
	return statuses, nil
}

// ListLogs 查询打票日志。
func (s *OpenAITicketGrabService) ListLogs(ctx context.Context, accountID int64, limit, offset int) ([]*OpenAITicketGrabLog, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	return s.repo.ListGrabLogs(ctx, accountID, limit, offset)
}
