package tlsfingerprint

import (
	"context"
	"errors"
	"net"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeWarmBase 可注入的假底层拨号：从预制连接队列顺序发放，耗尽即报错。
type fakeWarmBase struct {
	mu    sync.Mutex
	calls int
	conns chan net.Conn
}

func newFakeWarmBase(conns ...net.Conn) *fakeWarmBase {
	base := &fakeWarmBase{conns: make(chan net.Conn, len(conns))}
	for _, c := range conns {
		base.conns <- c
	}
	return base
}

func (f *fakeWarmBase) DialTLSContext(_ context.Context, _, _ string) (net.Conn, error) {
	f.mu.Lock()
	f.calls++
	f.mu.Unlock()
	select {
	case c := <-f.conns:
		return c, nil
	default:
		return nil, errors.New("dial exhausted")
	}
}

func (f *fakeWarmBase) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func warmPoolSize(t *testing.T, d *warmPoolDialer, addr string) int {
	t.Helper()
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.pools[addr].conns)
}

// 等待条件成立或超时（refill 是异步的）。
func warmWaitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// 命中：池内就绪连接直接返回，底层零拨号，且读超时已重置。
func TestWarmPoolHit(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	base := newFakeWarmBase()
	d := newWarmPoolDialer(base, &WarmPoolConfig{Size: 2, MaxAge: 10 * time.Second, ProbeTimeout: 20 * time.Millisecond})
	d.mu.Lock()
	d.pools["chatgpt.com:443"] = &warmAddrPool{conns: []warmConn{{conn: client, readyAt: time.Now()}}}
	d.mu.Unlock()

	got, err := d.DialTLSContext(t.Context(), "tcp", "chatgpt.com:443")
	if err != nil {
		t.Fatal(err)
	}
	if got != client {
		t.Fatal("应返回池内连接")
	}
	if base.callCount() != 0 {
		t.Fatalf("命中时底层不应拨号，实际 %d 次", base.callCount())
	}
	// 读超时必须已重置：写入一字节后应能读到（否则 Read 会超时）。
	go func() { _, _ = server.Write([]byte("x")) }()
	buf := make([]byte, 1)
	if _, err := got.Read(buf); err != nil {
		t.Fatalf("读超时未重置: %v", err)
	}
	_ = got.Close()
}

// 过期连接：丢弃并关闭，回落同步拨号。
func TestWarmPoolExpiredDiscarded(t *testing.T) {
	staleClient, staleServer := net.Pipe()
	defer staleServer.Close()
	freshClient, _ := net.Pipe()
	defer freshClient.Close()
	base := newFakeWarmBase(freshClient)
	d := newWarmPoolDialer(base, &WarmPoolConfig{Size: 2, MaxAge: 50 * time.Millisecond, ProbeTimeout: 20 * time.Millisecond})
	d.mu.Lock()
	d.pools["a:443"] = &warmAddrPool{conns: []warmConn{{
		conn:    staleClient,
		readyAt: time.Now().Add(-time.Second), // 远超 MaxAge
	}}}
	d.mu.Unlock()

	got, err := d.DialTLSContext(t.Context(), "tcp", "a:443")
	if err != nil {
		t.Fatal(err)
	}
	if got != freshClient {
		t.Fatal("过期连接应丢弃并回落同步拨号")
	}
	if base.callCount() != 1 {
		t.Fatalf("应恰好一次同步拨号，实际 %d", base.callCount())
	}
	// 过期连接应被关闭：对端读应得 EOF。
	staleServer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := staleServer.Read(make([]byte, 1)); err == nil {
		t.Fatal("过期连接未关闭")
	}
}

// 死连接（对端已关）：活性探测发现 EOF，丢弃换同步拨号。
func TestWarmPoolDeadConnDiscarded(t *testing.T) {
	deadClient, deadServer := net.Pipe()
	_ = deadServer.Close() // 对端先关 → Read 立即 EOF
	freshClient, _ := net.Pipe()
	defer freshClient.Close()
	base := newFakeWarmBase(freshClient)
	d := newWarmPoolDialer(base, &WarmPoolConfig{Size: 2, MaxAge: 10 * time.Second, ProbeTimeout: 50 * time.Millisecond})
	d.mu.Lock()
	d.pools["a:443"] = &warmAddrPool{conns: []warmConn{{conn: deadClient, readyAt: time.Now()}}}
	d.mu.Unlock()

	got, err := d.DialTLSContext(t.Context(), "tcp", "a:443")
	if err != nil {
		t.Fatal(err)
	}
	if got != freshClient {
		t.Fatal("死连接应丢弃并回落同步拨号")
	}
}

// 服务端抢先发数据（协议异常）：探测读到数据即视为不可用，丢弃。
func TestWarmPoolUnexpectedDataDiscarded(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	freshClient, _ := net.Pipe()
	defer freshClient.Close()
	base := newFakeWarmBase(freshClient)
	d := newWarmPoolDialer(base, &WarmPoolConfig{Size: 2, MaxAge: 10 * time.Second, ProbeTimeout: 100 * time.Millisecond})
	go func() { _, _ = server.Write([]byte("unexpected")) }()
	time.Sleep(20 * time.Millisecond) // 确保数据已入管道
	d.mu.Lock()
	d.pools["a:443"] = &warmAddrPool{conns: []warmConn{{conn: client, readyAt: time.Now()}}}
	d.mu.Unlock()

	got, err := d.DialTLSContext(t.Context(), "tcp", "a:443")
	if err != nil {
		t.Fatal(err)
	}
	if got != freshClient {
		t.Fatal("抢先发数据的连接应丢弃")
	}
}

// 异步补充：取用后池应恢复到 Size（refill 单飞 goroutine）。
func TestWarmPoolRefillRestoresSize(t *testing.T) {
	conns := make([]net.Conn, 0, 4)
	for i := 0; i < 4; i++ {
		c, s := net.Pipe()
		defer c.Close()
		defer s.Close()
		conns = append(conns, c)
	}
	base := newFakeWarmBase(conns...)
	d := newWarmPoolDialer(base, &WarmPoolConfig{Size: 3, MaxAge: 10 * time.Second, ProbeTimeout: 20 * time.Millisecond})

	if _, err := d.DialTLSContext(t.Context(), "tcp", "a:443"); err != nil {
		t.Fatal(err)
	}
	warmWaitFor(t, 2*time.Second, func() bool { return warmPoolSize(t, d, "a:443") == 3 })
	if base.callCount() != 4 { // 1 次同步 + 3 次补充
		t.Fatalf("应共 4 次拨号（1 同步 + 3 补充），实际 %d", base.callCount())
	}
	// 池满后不再拨号。
	time.Sleep(100 * time.Millisecond)
	if base.callCount() != 4 {
		t.Fatalf("池满后不应继续拨号，实际 %d", base.callCount())
	}
}

// 拨号失败退避：refill 失败后短时间内不再尝试补充，也不死循环。
func TestWarmPoolRefillBackoffOnFailure(t *testing.T) {
	base := newFakeWarmBase() // 无连接，全部失败
	d := newWarmPoolDialer(base, &WarmPoolConfig{Size: 3, MaxAge: 10 * time.Second, ProbeTimeout: 20 * time.Millisecond})

	if _, err := d.DialTLSContext(t.Context(), "tcp", "a:443"); err == nil {
		t.Fatal("同步拨号失败应返回错误")
	}
	warmWaitFor(t, 2*time.Second, func() bool { return base.callCount() >= 2 })
	time.Sleep(200 * time.Millisecond)
	calls := base.callCount()
	if calls > 3 { // 1 同步 + 1 补充尝试，退避期内不再增加
		t.Fatalf("退避未生效，拨号 %d 次", calls)
	}
}

// 注册表：同 (代理, 指纹) 复用实例，不同代理各自成池；kill switch 退回裸拨号。
func TestWarmPoolRegistryDedupe(t *testing.T) {
	proxy := mustParseProxyURL(t, "http://user:pass@proxy.example:10000")
	profile := &Profile{Name: "p1"}

	a := WarmHTTPProxyDialerFor(profile, proxy, nil)
	b := WarmHTTPProxyDialerFor(profile, proxy, nil)
	if a == nil || b == nil {
		t.Fatal("应返回非空拨号函数")
	}
	first, ok := warmPoolRegistry.Load(warmPoolRegistryKey(profile, proxy))
	if !ok {
		t.Fatal("注册表应有实例")
	}
	second, _ := warmPoolRegistry.Load(warmPoolRegistryKey(profile, proxy))
	if first != second {
		t.Fatal("同 (代理, 指纹) 应复用同一实例")
	}

	other := WarmHTTPProxyDialerFor(profile, mustParseProxyURL(t, "http://user:pass@proxy2.example:10000"), nil)
	if other == nil {
		t.Fatal("不同代理也应返回非空拨号函数")
	}
	if _, ok := warmPoolRegistry.Load(warmPoolRegistryKey(profile, mustParseProxyURL(t, "http://user:pass@proxy2.example:10000"))); !ok {
		t.Fatal("不同代理应各自注册")
	}
}

func TestWarmPoolKillSwitch(t *testing.T) {
	t.Setenv(warmPoolKillSwitchEnv, "off")
	proxy := mustParseProxyURL(t, "http://user:pass@proxy-killed.example:10000")
	got := WarmHTTPProxyDialerFor(&Profile{Name: "p2"}, proxy, nil)
	if got == nil {
		t.Fatal("应退回裸拨号函数")
	}
	warmPoolRegistry.Range(func(key, _ any) bool {
		if k, _ := key.(string); strings.Contains(k, "proxy-killed") {
			t.Fatalf("kill switch 下不应注册实例: %s", k)
		}
		return true
	})
}

func mustParseProxyURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}
