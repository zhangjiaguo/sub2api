package repository

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/pkg/tlsfingerprint"
)

// 本文件用「模拟上游 + 模拟代理 + 真实 DoWithTLS」做 OpenAI 出站 TLS 指纹的
// 全链路数据测试：mock TLS 服务端捕获原始 ClientHello 字节，随后完成真实
// TLS1.3 握手并处理 HTTP 请求；请求分别走直连 / SOCKS5 / HTTP-CONNECT 三条
// 生产路径（5 个官号代理为 4×socks5 + 1×http），断言每条路径上：
//  1. ClientHello 与 codex-cli 0.155.1（OpenSSL 3.6.3）抓包 ground truth 一致
//  2. 无 ALPN，请求/响应均为 HTTP/1.1（真实 codex 不协商 h2）
//  3. 模拟的 /v1/responses 请求头与请求体完整送达上游
//  4. 同客户端第二次请求复用连接（不再产生新握手）
//
// 证书信任：进程内生成自签 CA + leaf，通过 SSL_CERT_FILE 注入根池（仅 Linux
// 生效；Windows 跳过本测试，部署前在服务器容器内运行测试二进制完成验证）。

// wantCodexHello：codex-cli 0.155.1 真实抓包的独立副本（与 tlsfingerprint
// 包内 ground truth 双盲互校）。IP 目标形态（无 server_name）。
var wantCodexHello = struct {
	extOrder     []uint16
	cipherSuites []uint16
	groups       []uint16
	keyShareGrps []uint16
	sigAlgs      []uint16
	versions     []uint16
}{
	extOrder:     []uint16{65281, 11, 10, 35, 22, 23, 13, 43, 45, 51},
	cipherSuites: []uint16{0x1302, 0x1303, 0x1301, 0xc02c, 0xc030, 0x009f, 0xcca9, 0xcca8, 0xccaa, 0xc02b, 0xc02f, 0x009e, 0xc024, 0xc028, 0x006b, 0xc023, 0xc027, 0x0067, 0xc00a, 0xc014, 0x0039, 0xc009, 0xc013, 0x0033, 0x009d, 0x009c, 0x003d, 0x003c, 0x0035, 0x002f},
	groups:       []uint16{0x11ec, 0x001d, 0x0017, 0x001e, 0x0018, 0x0019, 0x0100, 0x0101},
	keyShareGrps: []uint16{0x11ec, 0x001d},
	sigAlgs:      []uint16{0x0905, 0x0906, 0x0904, 0x0403, 0x0503, 0x0603, 0x0807, 0x0808, 0x081a, 0x081b, 0x081c, 0x0809, 0x080a, 0x080b, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0303, 0x0301, 0x0302, 0x0402, 0x0502, 0x0602},
	versions:     []uint16{0x0304, 0x0303},
}

type capturedRequest struct {
	helloRaw []byte // 本连接首个请求对应的原始 ClientHello（复用连接为 nil）
	method   string
	path     string
	headers  http.Header
	body     []byte
	proto    string // 服务端看到的请求协议（无 ALPN 协商时应为 HTTP/1.1）
}

// --- mock 上游：捕获 ClientHello → 回放 → 真实 TLS 握手 → HTTP 服务 ---

// replayConn 把已读的原始字节回放给 tls.Server，使其能继续完整握手。
type replayConn struct {
	net.Conn
	r io.Reader
}

func (c *replayConn) Read(b []byte) (int, error) { return c.r.Read(b) }

// readClientHelloRaw 读取完整的 ClientHello（可能跨多个 TLS 记录），返回
// 原始字节流（含记录头，用于回放）与拼接后的握手消息（不含记录头）。
func readClientHelloRaw(conn net.Conn) (rawStream, msg []byte, err error) {
	var pending []byte
	for {
		hdr := make([]byte, 5)
		if _, err = io.ReadFull(conn, hdr); err != nil {
			return nil, nil, err
		}
		if hdr[0] != 0x16 {
			return nil, nil, fmt.Errorf("not a handshake record: %d", hdr[0])
		}
		rawStream = append(rawStream, hdr...)
		recLen := int(hdr[3])<<8 | int(hdr[4])
		payload := make([]byte, recLen)
		if _, err = io.ReadFull(conn, payload); err != nil {
			return nil, nil, err
		}
		rawStream = append(rawStream, payload...)
		pending = append(pending, payload...)
		if len(pending) < 4 {
			continue
		}
		msgLen := int(pending[1])<<16 | int(pending[2])<<8 | int(pending[3])
		if len(pending) >= 4+msgLen {
			return rawStream, pending[:4+msgLen], nil
		}
	}
}

type helloCaptureListener struct {
	net.Listener
	cert tls.Certificate

	mu         sync.Mutex
	helloByAddr map[string][]byte // 客户端 RemoteAddr → 原始 ClientHello
	handshakes  int32             // 完成的 TLS 握手总数（连接复用不增加）
}

func (l *helloCaptureListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		conn, ok := l.captureAndHandshake(c)
		if !ok {
			continue // 握手失败已关闭连接，继续 accept 下一个
		}
		return conn, nil
	}
}

func (l *helloCaptureListener) captureAndHandshake(c net.Conn) (net.Conn, bool) {
	_ = c.SetDeadline(time.Now().Add(15 * time.Second))
	rawStream, msg, err := readClientHelloRaw(c)
	if err != nil {
		_ = c.Close()
		return nil, false
	}
	l.mu.Lock()
	if l.helloByAddr == nil {
		l.helloByAddr = make(map[string][]byte)
	}
	l.helloByAddr[c.RemoteAddr().String()] = msg
	l.mu.Unlock()

	replay := &replayConn{Conn: c, r: io.MultiReader(bytes.NewReader(rawStream), c)}
	tlsConn := tls.Server(replay, &tls.Config{
		Certificates: []tls.Certificate{l.cert},
		MinVersion:   tls.VersionTLS12,
		// 故意不配置 NextProtos：客户端不发 ALPN 时无协商，走 HTTP/1.1。
	})
	if err := tlsConn.Handshake(); err != nil {
		_ = tlsConn.Close()
		return nil, false
	}
	atomic.AddInt32(&l.handshakes, 1)
	_ = c.SetDeadline(time.Time{})
	return tlsConn, true
}

// takeHello 取走该 RemoteAddr 对应的原始 ClientHello（一次性，复用连接返回 nil）。
func (l *helloCaptureListener) takeHello(remoteAddr string) []byte {
	l.mu.Lock()
	defer l.mu.Unlock()
	raw := l.helloByAddr[remoteAddr]
	delete(l.helloByAddr, remoteAddr)
	return raw
}

func (l *helloCaptureListener) handshakeCount() int32 {
	return atomic.LoadInt32(&l.handshakes)
}

type mockCodexUpstream struct {
	addr string
	ln   *helloCaptureListener

	mu       sync.Mutex
	requests []capturedRequest
}

// newMockCodexUpstream 启动 mock 上游：捕获 ClientHello 原始字节 → 回放并完成
// 真实 TLS1.3 握手 → 以 HTTP 服务处理请求并返回模拟 SSE。
func newMockCodexUpstream(t *testing.T, leaf tls.Certificate) *mockCodexUpstream {
	t.Helper()
	rawLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen upstream: %v", err)
	}
	m := &mockCodexUpstream{addr: rawLn.Addr().String(), ln: &helloCaptureListener{Listener: rawLn, cert: leaf}}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		hello := m.ln.takeHello(r.RemoteAddr)
		rec := http.Header{}
		for k, v := range r.Header {
			rec[k] = append([]string(nil), v...)
		}
		m.mu.Lock()
		m.requests = append(m.requests, capturedRequest{
			helloRaw: hello,
			method:   r.Method,
			path:     r.URL.Path,
			headers:  rec,
			body:     body,
			proto:    r.Proto,
		})
		m.mu.Unlock()

		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "data: {\"type\":\"response.created\",\"response\":{\"id\":\"resp_mock\"}}\n\ndata: [DONE]\n\n")
	})

	srv := &http.Server{Handler: handler, ReadHeaderTimeout: 15 * time.Second}
	go func() {
		_ = srv.Serve(m.ln)
	}()
	t.Cleanup(func() {
		_ = rawLn.Close()
		_ = srv.Close()
	})
	return m
}

func (m *mockCodexUpstream) snapshot() []capturedRequest {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]capturedRequest, len(m.requests))
	copy(out, m.requests)
	return out
}

func (m *mockCodexUpstream) reset() {
	m.mu.Lock()
	m.requests = nil
	m.mu.Unlock()
}

// --- ClientHello 解析与断言 ---

type parsedMockHello struct {
	extOrder       []uint16
	cipherSuites   []uint16
	groups         []uint16
	keyShareGroups []uint16
	sigAlgs        []uint16
	versions       []uint16
	pskModes       []byte
	points         []byte
	sessionIDLen   int
	alpnPresent    bool
}

func parseMockHello(msg []byte) (*parsedMockHello, error) {
	if len(msg) < 4 || msg[0] != 0x01 {
		return nil, errors.New("not ClientHello")
	}
	out := &parsedMockHello{}
	b := msg[4:]
	off := 34
	sidLen := int(b[off])
	out.sessionIDLen = sidLen
	off += 1 + sidLen
	csLen := int(b[off])<<8 | int(b[off+1])
	off += 2
	for i := 0; i < csLen; i += 2 {
		out.cipherSuites = append(out.cipherSuites, binary.BigEndian.Uint16(b[off:off+2]))
		off += 2
	}
	compLen := int(b[off])
	off += 1 + compLen
	extTotal := int(b[off])<<8 | int(b[off+1])
	off += 2
	end := off + extTotal
	for off+4 <= end {
		et := binary.BigEndian.Uint16(b[off : off+2])
		el := int(b[off+2])<<8 | int(b[off+3])
		data := b[off+4 : off+4+el]
		out.extOrder = append(out.extOrder, et)
		switch et {
		case 10:
			l := int(data[0])<<8 | int(data[1])
			for i := 0; i < l; i += 2 {
				out.groups = append(out.groups, binary.BigEndian.Uint16(data[2+i:4+i]))
			}
		case 11:
			out.points = append([]byte{}, data[1:]...)
		case 13:
			l := int(data[0])<<8 | int(data[1])
			for i := 0; i < l; i += 2 {
				out.sigAlgs = append(out.sigAlgs, binary.BigEndian.Uint16(data[2+i:4+i]))
			}
		case 16:
			out.alpnPresent = true
		case 43:
			l := int(data[0])
			for i := 0; i < l; i += 2 {
				out.versions = append(out.versions, binary.BigEndian.Uint16(data[1+i:3+i]))
			}
		case 45:
			out.pskModes = append([]byte{}, data[1:]...)
		case 51:
			l := int(data[0])<<8 | int(data[1])
			i := 0
			for i < l {
				g := binary.BigEndian.Uint16(data[2+i : 4+i])
				out.keyShareGroups = append(out.keyShareGroups, g)
				klen := int(data[4+i])<<8 | int(data[5+i])
				i += 4 + klen
			}
		}
		off += 4 + el
	}
	return out, nil
}

func requireEqualU16Mock(t *testing.T, label string, got, want []uint16) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s length mismatch: got %d want %d", label, len(got), len(want))
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("%s[%d] mismatch: got %#04x want %#04x", label, i, got[i], want[i])
		}
	}
}

func assertCodexHello(t *testing.T, helloRaw []byte) {
	t.Helper()
	h, err := parseMockHello(helloRaw)
	if err != nil {
		t.Fatalf("parse ClientHello: %v", err)
	}
	requireEqualU16Mock(t, "ext_order", h.extOrder, wantCodexHello.extOrder)
	requireEqualU16Mock(t, "cipher_suites", h.cipherSuites, wantCodexHello.cipherSuites)
	requireEqualU16Mock(t, "supported_groups", h.groups, wantCodexHello.groups)
	requireEqualU16Mock(t, "key_share_groups", h.keyShareGroups, wantCodexHello.keyShareGrps)
	requireEqualU16Mock(t, "signature_algorithms", h.sigAlgs, wantCodexHello.sigAlgs)
	requireEqualU16Mock(t, "supported_versions", h.versions, wantCodexHello.versions)
	if h.sessionIDLen != 32 {
		t.Fatalf("session_id length: got %d want 32", h.sessionIDLen)
	}
	if len(h.pskModes) != 1 || h.pskModes[0] != 1 {
		t.Fatalf("psk_modes: got %v want [1]", h.pskModes)
	}
	if len(h.points) != 1 || h.points[0] != 0 {
		t.Fatalf("ec_point_formats: got %v want [0]", h.points)
	}
	if h.alpnPresent {
		t.Fatalf("ALPN must NOT be offered (real codex = no ALPN, HTTP/1.1)")
	}
}

// --- 测试证书：自签 CA + leaf（SAN 含 127.0.0.1），CA 通过 SSL_CERT_FILE 信任 ---

func genTestCerts(t *testing.T) (tls.Certificate, string) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen ca key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "sub2api-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create ca cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse ca cert: %v", err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen leaf key: %v", err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}
	leaf := tls.Certificate{
		Certificate: [][]byte{leafDER},
		PrivateKey:  leafKey,
	}

	caFile := t.TempDir() + "/test-ca.pem"
	_ = os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o600)
	return leaf, caFile
}

// --- 迷你 SOCKS5 代理（RFC1928 最小实现：无认证 + CONNECT） ---

func startMiniSOCKS5Proxy(t *testing.T) *url.URL {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen socks5: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go handleMiniSOCKS5(c)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return &url.URL{Scheme: "socks5", Host: ln.Addr().String()}
}

func handleMiniSOCKS5(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(15 * time.Second))
	// 客户端问候：VER NMETHODS METHODS...
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return
	}
	methods := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}
	if _, err := c.Write([]byte{0x05, 0x00}); err != nil { // 选中"无认证"
		return
	}
	// 请求：VER CMD RSV ATYP ADDR PORT
	req := make([]byte, 4)
	if _, err := io.ReadFull(c, req); err != nil {
		return
	}
	if req[1] != 0x01 { // 仅支持 CONNECT
		_, _ = c.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	var host string
	switch req[3] {
	case 0x01:
		b := make([]byte, 4)
		if _, err := io.ReadFull(c, b); err != nil {
			return
		}
		host = net.IP(b).String()
	case 0x03:
		l := make([]byte, 1)
		if _, err := io.ReadFull(c, l); err != nil {
			return
		}
		b := make([]byte, int(l[0]))
		if _, err := io.ReadFull(c, b); err != nil {
			return
		}
		host = string(b)
	case 0x04:
		b := make([]byte, 16)
		if _, err := io.ReadFull(c, b); err != nil {
			return
		}
		host = net.IP(b).String()
	default:
		return
	}
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(c, portBytes); err != nil {
		return
	}
	port := int(portBytes[0])<<8 | int(portBytes[1])

	upstream, err := net.Dial("tcp", net.JoinHostPort(host, fmt.Sprintf("%d", port)))
	if err != nil {
		_, _ = c.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer upstream.Close()
	if _, err := c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	_ = c.SetDeadline(time.Time{})
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(upstream, c); done <- struct{}{} }()
	_, _ = io.Copy(c, upstream)
	<-done
}

// --- 迷你 HTTP CONNECT 代理 ---

func startMiniHTTPConnectProxy(t *testing.T) *url.URL {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen http proxy: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go handleMiniHTTPConnect(c)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return &url.URL{Scheme: "http", Host: ln.Addr().String()}
}

func handleMiniHTTPConnect(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(15 * time.Second))
	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil || req.Method != http.MethodConnect {
		return
	}
	upstream, err := net.Dial("tcp", req.URL.Host)
	if err != nil {
		_, _ = c.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer upstream.Close()
	if _, err := c.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}
	_ = c.SetDeadline(time.Time{})
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(upstream, c); done <- struct{}{} }()
	_, _ = io.Copy(c, upstream)
	<-done
}

// --- 模拟 codex /v1/responses 请求数据 ---

func buildSimulatedCodexRequest(t *testing.T, upstreamAddr, sessionID string) *http.Request {
	t.Helper()
	payload := map[string]any{
		"model": "gpt-5.2-codex",
		"instructions": "You are a coding agent running in the Codex CLI. " +
			"Use the shell tool to inspect the repository and make minimal, focused edits.",
		"input": []any{
			map[string]any{
				"type": "message",
				"role": "user",
				"content": []any{
					map[string]any{
						"type": "input_text",
						"text": "模拟数据：请阅读 internal/repository/http_upstream.go 并总结 DoWithTLS 的调用路径。" +
							"随后运行 go test ./internal/repository/ -run TestDoWithTLS -v 验证。（中文+特殊字符 ümläut ñ emoji 🧪）",
					},
				},
			},
		},
		"tools": []any{
			map[string]any{"type": "function", "name": "shell", "description": "Runs a shell command."},
			map[string]any{"type": "function", "name": "apply_patch", "description": "Applies a patch."},
		},
		"reasoning":        map[string]any{"effort": "medium", "summary": "auto"},
		"store":            false,
		"stream":           true,
		"include":          []string{"reasoning.encrypted_content"},
		"prompt_cache_key": sessionID,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal simulated payload: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, "https://"+upstreamAddr+"/backend-api/codex/responses", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+strings.Repeat("sk-simul-", 8)+"tok")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("User-Agent", "codex_cli_rs/0.155.1 (Windows 11; x86_64) sub2api-integration-test")
	req.Header.Set("originator", "codex_cli_rs")
	req.Header.Set("OpenAI-Beta", "responses=experimental")
	req.Header.Set("session_id", sessionID)
	req.Header.Set("chatgpt-account-id", "acc-simul-000000000000000000000000")
	req.Header.Set("Conversation-Id", sessionID)
	return req
}

// --- 主测试：三条生产代理路径 × 全链路断言 ---

func TestDoWithTLSCodexProfileFullChain(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows 系统根证书存储忽略 SSL_CERT_FILE，完整握手测试在 Linux 容器内运行（见部署流程）")
	}
	if testing.Short() {
		t.Skip("short mode")
	}

	leaf, caFile := genTestCerts(t)
	// SSL_CERT_FILE 必须在进程第一次证书校验之前设置（crypto/x509 根池按
	// sync.Once 加载）。
	_ = os.Setenv("SSL_CERT_FILE", caFile)

	up := newMockCodexUpstream(t, leaf)
	socksProxy := startMiniSOCKS5Proxy(t)
	httpProxy := startMiniHTTPConnectProxy(t)

	paths := []struct {
		name     string
		proxyURL string
	}{
		{name: "direct", proxyURL: ""},
		{name: "socks5", proxyURL: socksProxy.String()},
		{name: "http_connect", proxyURL: httpProxy.String()},
	}

	for _, p := range paths {
		t.Run(p.name, func(t *testing.T) {
			up.reset()
			svc := NewHTTPUpstream(&config.Config{})

			// 第一条请求：完整 TLS 握手 + codex 形态 ClientHello
			req1 := buildSimulatedCodexRequest(t, up.addr, "sess-simul-0001")
			before := up.ln.handshakeCount()
			resp1, err := svc.DoWithTLS(req1, p.proxyURL, 133, 4, tlsfingerprint.CodexProfile)
			if err != nil {
				t.Fatalf("DoWithTLS (first): %v", err)
			}
			body1, err := io.ReadAll(resp1.Body)
			_ = resp1.Body.Close()
			if err != nil {
				t.Fatalf("read first body: %v", err)
			}
			if resp1.StatusCode != http.StatusOK {
				t.Fatalf("first status: got %d want 200", resp1.StatusCode)
			}
			if resp1.Proto != "HTTP/1.1" {
				t.Fatalf("first proto: got %s want HTTP/1.1 (codex 不协商 ALPN)", resp1.Proto)
			}
			if !bytes.Contains(body1, []byte("response.created")) || !bytes.Contains(body1, []byte("[DONE]")) {
				t.Fatalf("first SSE body incomplete: %q", body1)
			}

			// 第二条请求：应复用连接（不产生新握手）
			req2 := buildSimulatedCodexRequest(t, up.addr, "sess-simul-0002")
			resp2, err := svc.DoWithTLS(req2, p.proxyURL, 133, 4, tlsfingerprint.CodexProfile)
			if err != nil {
				t.Fatalf("DoWithTLS (second): %v", err)
			}
			body2, err := io.ReadAll(resp2.Body)
			_ = resp2.Body.Close()
			if err != nil {
				t.Fatalf("read second body: %v", err)
			}
			if resp2.StatusCode != http.StatusOK || resp2.Proto != "HTTP/1.1" {
				t.Fatalf("second response: status=%d proto=%s", resp2.StatusCode, resp2.Proto)
			}
			if !bytes.Contains(body2, []byte("[DONE]")) {
				t.Fatalf("second SSE body incomplete: %q", body2)
			}

			after := up.ln.handshakeCount()
			if after-before != 1 {
				t.Fatalf("两次顺序请求应只产生 1 次握手（连接复用），got %d", after-before)
			}

			reqs := up.snapshot()
			if len(reqs) != 2 {
				t.Fatalf("captured requests: got %d want 2", len(reqs))
			}
			r1, r2 := reqs[0], reqs[1]

			// ClientHello 与 codex-cli 抓包逐字段一致
			if r1.helloRaw == nil {
				t.Fatal("first request must carry the captured ClientHello")
			}
			assertCodexHello(t, r1.helloRaw)
			if r2.helloRaw != nil {
				t.Fatal("second request reused the connection; no new ClientHello expected")
			}

			// HTTP 层：请求完整送达
			for i, r := range []capturedRequest{r1, r2} {
				label := fmt.Sprintf("req[%d]", i)
				if r.method != http.MethodPost {
					t.Fatalf("%s method: got %s want POST", label, r.method)
				}
				if r.path != "/backend-api/codex/responses" {
					t.Fatalf("%s path: got %s", label, r.path)
				}
				if r.proto != "HTTP/1.1" {
					t.Fatalf("%s proto: got %s want HTTP/1.1", label, r.proto)
				}
				if got := r.headers.Get("Authorization"); !strings.HasPrefix(got, "Bearer sk-simul-") {
					t.Fatalf("%s Authorization header lost: %q", label, got)
				}
				if got := r.headers.Get("User-Agent"); !strings.HasPrefix(got, "codex_cli_rs/0.155.1") {
					t.Fatalf("%s User-Agent: %q", label, got)
				}
				if got := r.headers.Get("originator"); got != "codex_cli_rs" {
					t.Fatalf("%s originator: %q", label, got)
				}
				wantSession := "sess-simul-0001"
				if i == 1 {
					wantSession = "sess-simul-0002"
				}
				if got := r.headers.Get("session_id"); got != wantSession {
					t.Fatalf("%s session_id: got %q want %q", label, got, wantSession)
				}
				if got := r.headers.Get("chatgpt-account-id"); got != "acc-simul-000000000000000000000000" {
					t.Fatalf("%s chatgpt-account-id: %q", label, got)
				}
				if got := r.headers.Get("Content-Type"); got != "application/json" {
					t.Fatalf("%s Content-Type: %q", label, got)
				}

				var payload map[string]any
				if err := json.Unmarshal(r.body, &payload); err != nil {
					t.Fatalf("%s body not JSON (%d bytes): %v", label, len(r.body), err)
				}
				if payload["model"] != "gpt-5.2-codex" {
					t.Fatalf("%s model: %v", label, payload["model"])
				}
				if payload["stream"] != true {
					t.Fatalf("%s stream: %v", label, payload["stream"])
				}
				input, _ := payload["input"].([]any)
				if len(input) != 1 {
					t.Fatalf("%s input items: got %d want 1", label, len(input))
				}
				msg, _ := input[0].(map[string]any)
				content, _ := msg["content"].([]any)
				if len(content) != 1 {
					t.Fatalf("%s input content items: got %d want 1", label, len(content))
				}
				text, _ := content[0].(map[string]any)["text"].(string)
				if !strings.Contains(text, "DoWithTLS") || !strings.Contains(text, "ümläut") || !strings.Contains(text, "🧪") {
					t.Fatalf("%s input text mangled: %q", label, text)
				}
				tools, _ := payload["tools"].([]any)
				if len(tools) != 2 {
					t.Fatalf("%s tools: got %d want 2", label, len(tools))
				}
				if payload["prompt_cache_key"] != wantSession {
					t.Fatalf("%s prompt_cache_key: %v", label, payload["prompt_cache_key"])
				}
			}
		})
	}
}

// TestDoWithTLSPlainHTTPTargetSkipsFingerprint：http:// 明文目标即使传了
// CodexProfile 也必须走普通 Do 路径（无 TLS 可指纹化），且不绕过代理配置；
// profile=nil 同样降级为 Do。该测试不依赖证书信任，全平台可跑（含 Windows）。
func TestDoWithTLSPlainHTTPTargetSkipsFingerprint(t *testing.T) {
	var mu sync.Mutex
	var paths []string
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	})}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() {
		_ = ln.Close()
		_ = srv.Close()
	})

	svc := NewHTTPUpstream(&config.Config{})

	cases := []struct {
		name    string
		profile *tlsfingerprint.Profile
	}{
		{name: "codex_profile_http_target", profile: tlsfingerprint.CodexProfile},
		{name: "nil_profile", profile: nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodPost, "http://"+ln.Addr().String()+"/plain/do", strings.NewReader("{}"))
			if err != nil {
				t.Fatalf("new request: %v", err)
			}
			resp, err := svc.DoWithTLS(req, "", 133, 4, tc.profile)
			if err != nil {
				t.Fatalf("DoWithTLS over plain http: %v", err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status: got %d want 200", resp.StatusCode)
			}
			if resp.Proto != "HTTP/1.1" {
				t.Fatalf("proto: got %s want HTTP/1.1", resp.Proto)
			}
		})
	}

	mu.Lock()
	defer mu.Unlock()
	if len(paths) != 2 {
		t.Fatalf("upstream received %d requests, want 2: %v", len(paths), paths)
	}
	for _, p := range paths {
		if p != "/plain/do" {
			t.Fatalf("unexpected path: %s", p)
		}
	}
}
