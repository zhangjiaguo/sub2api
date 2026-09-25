package tlsfingerprint

import (
	"context"
	"log/slog"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// WarmPoolConfig 预热连接池参数，零值字段使用默认值。
type WarmPoolConfig struct {
	// Size 每个目标地址维持的预热连接数。
	Size int
	// MaxAge 预热连接的最大闲置年龄，超过即视为过期（动态代理约
	// 30-100s 掐掉空闲隧道，默认值需显著低于该下限）。
	MaxAge time.Duration
	// ProbeTimeout 取用连接时的活性探测超时。
	ProbeTimeout time.Duration
}

const (
	warmPoolDefaultSize         = 3
	warmPoolDefaultMaxAge       = 20 * time.Second
	warmPoolDefaultProbeTimeout = 30 * time.Millisecond
	warmPoolDialTimeout         = 15 * time.Second
	warmPoolRefillBackoff       = 30 * time.Second
	warmPoolLogInterval         = time.Minute
	// warmPoolKillSwitchEnv 置 off/0/false 时禁用预热池（软关闭保险丝）。
	warmPoolKillSwitchEnv = "SUB2API_TLS_WARM_POOL"
)

func (c *WarmPoolConfig) resolve() WarmPoolConfig {
	resolved := WarmPoolConfig{
		Size:         warmPoolDefaultSize,
		MaxAge:       warmPoolDefaultMaxAge,
		ProbeTimeout: warmPoolDefaultProbeTimeout,
	}
	if c != nil {
		if c.Size > 0 {
			resolved.Size = c.Size
		}
		if c.MaxAge > 0 {
			resolved.MaxAge = c.MaxAge
		}
		if c.ProbeTimeout > 0 {
			resolved.ProbeTimeout = c.ProbeTimeout
		}
	}
	return resolved
}

// warmBaseDialer 抽象底层拨号（生产为 HTTPProxyDialer，测试注入假实现）。
type warmBaseDialer interface {
	DialTLSContext(ctx context.Context, network, addr string) (net.Conn, error)
}

type warmConn struct {
	conn    net.Conn
	readyAt time.Time
}

type warmAddrPool struct {
	conns      []warmConn
	filling    bool
	lastFailAt time.Time
}

// warmPoolDialer 在后台提前完成 TCP→代理 CONNECT→TLS 握手，把就绪连接按
// 目标地址缓存为一次性连接：取用即出池，请求方用完即关（配合
// request.Close=true 保持「每请求独立连接 = 独立出口」语义）。池空时回落
// 同步拨号（与无预热时行为一致），同时异步补充。
type warmPoolDialer struct {
	base warmBaseDialer
	cfg  WarmPoolConfig

	mu            sync.Mutex
	pools         map[string]*warmAddrPool
	lastDeadLogAt time.Time
	lastFailLogAt time.Time
}

func newWarmPoolDialer(base warmBaseDialer, cfg *WarmPoolConfig) *warmPoolDialer {
	return &warmPoolDialer{
		base:  base,
		cfg:   cfg.resolve(),
		pools: make(map[string]*warmAddrPool),
	}
}

func (d *warmPoolDialer) poolLocked(addr string) *warmAddrPool {
	pool, ok := d.pools[addr]
	if !ok {
		pool = &warmAddrPool{}
		d.pools[addr] = pool
	}
	return pool
}

// DialTLSContext 可直接作为 http.Transport.DialTLSContext 使用。
func (d *warmPoolDialer) DialTLSContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if conn, ok := d.acquireWarm(addr); ok {
		d.ensureRefill(addr)
		return conn, nil
	}
	slog.Debug("tls_fingerprint_warm_miss", "addr", addr)
	d.ensureRefill(addr)
	return d.base.DialTLSContext(ctx, network, addr)
}

// acquireWarm 取一条就绪连接：优先最新；过期或活性探测失败即丢弃并继续。
func (d *warmPoolDialer) acquireWarm(addr string) (net.Conn, bool) {
	for {
		d.mu.Lock()
		pool := d.poolLocked(addr)
		if len(pool.conns) == 0 {
			d.mu.Unlock()
			return nil, false
		}
		last := pool.conns[len(pool.conns)-1]
		pool.conns = pool.conns[:len(pool.conns)-1]
		d.mu.Unlock()

		if time.Since(last.readyAt) > d.cfg.MaxAge {
			_ = last.conn.Close()
			slog.Debug("tls_fingerprint_warm_discard", "addr", addr, "reason", "expired")
			continue
		}
		if !warmConnAlive(last.conn, d.cfg.ProbeTimeout) {
			_ = last.conn.Close()
			d.logRateLimited(&d.lastDeadLogAt, "tls_fingerprint_warm_discard", addr, "dead")
			continue
		}
		slog.Debug("tls_fingerprint_warm_hit", "addr", addr,
			"age_ms", time.Since(last.readyAt).Milliseconds())
		return last.conn, true
	}
}

// warmConnAlive 探测已握手连接是否仍可用。HTTP/1.1 服务端不会在收到请求前
// 发送任何数据，因此短超时读：超时 = 存活；EOF/错误/收到数据 = 不可用。
// 探测通过后必须把读超时重置为零再交给调用方。
func warmConnAlive(conn net.Conn, timeout time.Duration) bool {
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	var buf [1]byte
	n, err := conn.Read(buf[:])
	if n > 0 || err == nil {
		return false
	}
	netErr, ok := err.(net.Error)
	if !ok || !netErr.Timeout() {
		return false
	}
	_ = conn.SetReadDeadline(time.Time{})
	return true
}

// ensureRefill 单飞补充：拨到 Size 满即退出，无常驻循环；拨号失败退避
// warmPoolRefillBackoff，防止代理故障时高频重试。
func (d *warmPoolDialer) ensureRefill(addr string) {
	d.mu.Lock()
	pool := d.poolLocked(addr)
	if pool.filling || time.Since(pool.lastFailAt) < warmPoolRefillBackoff {
		d.mu.Unlock()
		return
	}
	pool.filling = true
	d.mu.Unlock()
	go d.refill(addr)
}

func (d *warmPoolDialer) refill(addr string) {
	defer func() {
		d.mu.Lock()
		d.poolLocked(addr).filling = false
		d.mu.Unlock()
	}()
	for {
		d.mu.Lock()
		pool := d.poolLocked(addr)
		now := time.Now()
		kept := pool.conns[:0]
		for _, wc := range pool.conns {
			if now.Sub(wc.readyAt) > d.cfg.MaxAge {
				_ = wc.conn.Close()
				continue
			}
			kept = append(kept, wc)
		}
		pool.conns = kept
		if len(pool.conns) >= d.cfg.Size {
			d.mu.Unlock()
			return
		}
		d.mu.Unlock()

		dialCtx, cancel := context.WithTimeout(context.Background(), warmPoolDialTimeout)
		conn, err := d.base.DialTLSContext(dialCtx, "tcp", addr)
		cancel()
		if err != nil {
			d.mu.Lock()
			d.poolLocked(addr).lastFailAt = time.Now()
			d.mu.Unlock()
			d.logRateLimited(&d.lastFailLogAt, "tls_fingerprint_warm_refill_failure", addr, err.Error())
			return
		}
		d.mu.Lock()
		d.poolLocked(addr).conns = append(d.poolLocked(addr).conns, warmConn{conn: conn, readyAt: time.Now()})
		d.mu.Unlock()
	}
}

// logRateLimited 以 Debug 记每次事件，并按 warmPoolLogInterval 限频输出一条
// Info（运维可见：死连/补充失败通常意味着代理侧在掐连接或故障）。
func (d *warmPoolDialer) logRateLimited(lastAt *time.Time, event, addr, reason string) {
	slog.Debug(event, "addr", addr, "reason", reason)
	d.mu.Lock()
	if time.Since(*lastAt) < warmPoolLogInterval {
		d.mu.Unlock()
		return
	}
	*lastAt = time.Now()
	d.mu.Unlock()
	slog.Info(event, "addr", addr, "reason", reason)
}

func warmPoolEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(warmPoolKillSwitchEnv))) {
	case "off", "0", "false", "disabled":
		return false
	}
	return true
}

// warmPoolRegistry 进程级注册表：同一 (代理, 指纹) 组合复用同一池实例。
var warmPoolRegistry sync.Map // string -> *warmPoolDialer

func warmPoolRegistryKey(profile *Profile, proxyURL *url.URL) string {
	name := ""
	if profile != nil {
		name = profile.Name
	}
	proxy := ""
	if proxyURL != nil {
		proxy = proxyURL.String()
	}
	return proxy + "|" + name
}

// WarmHTTPProxyDialerFor 返回带共享预热池的 DialTLSContext。同一 (代理,
// 指纹) 组合下的所有 transport（如打票覆盖的多个账号客户端）复用同一实例，
// 避免重复预热；代理配置变更后旧池自然闲置（无流量即无补充）。
// SUB2API_TLS_WARM_POOL=off 时退回裸 HTTPProxyDialer。
func WarmHTTPProxyDialerFor(profile *Profile, proxyURL *url.URL, cfg *WarmPoolConfig) func(context.Context, string, string) (net.Conn, error) {
	base := NewHTTPProxyDialer(profile, proxyURL)
	if !warmPoolEnabled() {
		return base.DialTLSContext
	}
	key := warmPoolRegistryKey(profile, proxyURL)
	if cached, ok := warmPoolRegistry.Load(key); ok {
		return cached.(*warmPoolDialer).DialTLSContext
	}
	stored, loaded := warmPoolRegistry.LoadOrStore(key, newWarmPoolDialer(base, cfg))
	dialer := stored.(*warmPoolDialer)
	if !loaded {
		proxyHost, profileName := "", ""
		if proxyURL != nil {
			proxyHost = proxyURL.Host
		}
		if profile != nil {
			profileName = profile.Name
		}
		slog.Info("tls_fingerprint_warm_pool_created",
			"proxy", proxyHost, "profile", profileName,
			"size", dialer.cfg.Size, "max_age", dialer.cfg.MaxAge.String())
	}
	return dialer.DialTLSContext
}
