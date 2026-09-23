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
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/openai"
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
	// openAITicketGrabAuthCooldown 401/403 后的账号冷却（凭据/权限问题不会因换出口自愈）。
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
	if s.AccountIDs == nil {
		s.AccountIDs = []int64{}
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
	nextProbeAt   time.Time
	lastResult    string
	lastProbeAt   time.Time
	probing       bool
}

// OpenAITicketGrabService 打票调度服务。
type OpenAITicketGrabService struct {
	repo          OpenAITicketGrabRepository
	accountRepo   AccountRepository
	tokenProvider *OpenAITokenProvider
	settingRepo   SettingRepository

	settingsMu     sync.RWMutex
	settingsCache  OpenAITicketGrabSettings
	settingsLoaded time.Time

	runtimesMu sync.Mutex
	runtimes   map[int64]*openAITicketAccountRuntime

	stopCh   chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup
}

// NewOpenAITicketGrabService 构造打票服务。
func NewOpenAITicketGrabService(
	repo OpenAITicketGrabRepository,
	accountRepo AccountRepository,
	tokenProvider *OpenAITokenProvider,
	settingRepo SettingRepository,
) *OpenAITicketGrabService {
	return &OpenAITicketGrabService{
		repo:          repo,
		accountRepo:   accountRepo,
		tokenProvider: tokenProvider,
		settingRepo:   settingRepo,
		runtimes:      make(map[int64]*openAITicketAccountRuntime),
		stopCh:        make(chan struct{}),
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
// 并返回最终结果。429/401/403 是上游账号级决定：换出口不会改变结果，本轮终止。
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
		cooldown := time.Duration(settings.MinIntervalSecond) * time.Second
		switch {
		case outcome.result == "accepted":
			// 成功后按「提前秒数」计算下一次补票时间。
			rt.nextProbeAt = time.Now().Add(time.Duration(settings.TTLSeconds-settings.LeadSeconds) * time.Second)
			rt.mu.Unlock()
			return outcome.result
		case outcome.result == "http_429":
			if outcome.retryAfter > openAITicketGrab429Cooldown {
				cooldown = outcome.retryAfter
			} else {
				cooldown = openAITicketGrab429Cooldown
			}
		case outcome.result == "http_401" || outcome.result == "http_403":
			cooldown = openAITicketGrabAuthCooldown
		}
		rt.cooldownUntil = time.Now().Add(cooldown)
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

// openAITicketProbeOutcome 单次探测结果。
type openAITicketProbeOutcome struct {
	result         string
	retryAfter     time.Duration
	retryNextRound bool // 上游账号级拒绝（429/401/403），不应继续换出口重试
	detail         string
}

// probeOnce 执行一次「trace 定位出口 + 短探测」并落库。
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

	timeout := time.Duration(settings.ProbeTimeoutSecs) * time.Second
	// 每次探测用独立 Transport：动态代理按 TCP 连接轮换出口，
	// 新 Transport = 新连接 = 新出口 IP。
	transport := &http.Transport{
		Proxy:               http.ProxyURL(proxyURL),
		MaxIdleConns:        2,
		MaxIdleConnsPerHost: 2,
		IdleConnTimeout:     90 * time.Second,
	}
	client := &http.Client{Transport: transport, Timeout: timeout}
	defer transport.CloseIdleConnections()

	// 先 trace 拿出口 IP：同一 client 复用连接，打票请求将走同一代理隧道。
	exitIP, exitColo := openAITicketTraceExit(ctx, client)

	body, _ := json.Marshal(map[string]any{
		"model": settings.Model, "instructions": "Reply with OK.",
		"input":  []any{map[string]any{"type": "message", "role": "user", "content": []any{map[string]any{"type": "input_text", "text": "Reply with OK."}}}},
		"stream": true, "store": false, "parallel_tool_calls": true,
		"include": []string{"reasoning.encrypted_content"},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://chatgpt.com/backend-api/codex/responses", bytes.NewReader(body))
	if err != nil {
		outcome.result, outcome.detail = "request_error", err.Error()
		s.recordGrabLog(ctx, account.ID, outcome, 0, nil)
		return outcome
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
	req.Header.Set("accept", "text/event-stream")
	req.Header.Set("content-type", "application/json")

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		outcome.result, outcome.detail = "network_error", err.Error()
		s.recordGrabLog(ctx, account.ID, outcome, 0, &openAITicketGrabLogMeta{ip: exitIP, colo: exitColo, dur: time.Since(start)})
		return outcome
	}
	defer resp.Body.Close()
	duration := time.Since(start)

	state := strings.TrimSpace(resp.Header.Get(openAICodexTurnStateHeader))
	data, _ := io.ReadAll(io.LimitReader(resp.Body, openAITicketGrabBodyLimit))

	if resp.StatusCode != http.StatusOK {
		outcome.result = "http_" + strconv.Itoa(resp.StatusCode)
		outcome.detail = openAITicketUpstreamErrorDetail(data)
		outcome.retryAfter = openAITicketParseRetryAfter(resp.Header.Get("Retry-After"))
		outcome.retryNextRound = resp.StatusCode == http.StatusTooManyRequests ||
			resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden
		s.recordGrabLog(ctx, account.ID, outcome, resp.StatusCode, &openAITicketGrabLogMeta{ip: exitIP, colo: exitColo, dur: duration})
		return outcome
	}

	model := openAITicketStreamModel(data)
	completed := bytes.Contains(data, []byte(`"response.completed"`))

	outcome.result, outcome.detail = classifyOpenAITicketProbe(state, completed, time.Now(), settings)
	parsed, _ := parseOpenAITicketState(state)

	if outcome.result == "accepted" {
		fingerprint := sha256.Sum256([]byte(state))
		ticket := &OpenAITicket{
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
		if err := s.repo.UpsertTicket(ctx, ticket); err != nil {
			slog.Warn("openai_ticket_grab upsert ticket failed", "account_id", account.ID, "error", err)
		}
	}
	s.recordGrabLog(ctx, account.ID, outcome, resp.StatusCode, &openAITicketGrabLogMeta{
		ip: exitIP, colo: exitColo, dur: duration, state: state, parsed: parsed,
	})
	slog.Info("openai_ticket_grab_probe",
		"account_id", account.ID, "result", outcome.result,
		"exit_ip", exitIP, "exit_colo", exitColo,
		"state_len", len(state), "model", model,
		"duration_ms", duration.Milliseconds())
	return outcome
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
func openAITicketTraceExit(ctx context.Context, client *http.Client) (ip, colo string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://chatgpt.com/cdn-cgi/trace", nil)
	if err != nil {
		return "", ""
	}
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
		rt.mu.Unlock()
		return fmt.Errorf("账号冷却中（上游限流/凭据问题），请 %d 秒后再试", seconds)
	}
	rt.mu.Unlock()

	outcome := s.grabRoundResult(ctx, account, settings, proxyURL)
	if outcome == "accepted" {
		return nil
	}
	return fmt.Errorf("打票未成功: %s", outcome)
}

// AccountStatus 单账号打票状态视图。
type OpenAITicketGrabAccountStatus struct {
	AccountID       int64                  `json:"account_id"`
	AccountName     string                 `json:"account_name"`
	Status          string                 `json:"status"`
	Ticket          *OpenAITicket          `json:"ticket,omitempty"`
	RemainingSecond int                    `json:"remaining_seconds"`
	NextProbeUnix   int64                  `json:"next_probe_unix"`
	CooldownUnix    int64                  `json:"cooldown_unix"`
	LastResult      string                 `json:"last_result"`
	Probing         bool                   `json:"probing"`
	Stats           *OpenAITicketGrabStats `json:"stats,omitempty"`
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
