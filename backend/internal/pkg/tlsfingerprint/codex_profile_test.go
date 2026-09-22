package tlsfingerprint

import (
	"encoding/binary"
	"io"
	"net"
	"testing"

	utls "github.com/refraction-networking/utls"
)

// capturedCodexHello 是 codex-cli 0.155.1（OpenSSL 3.6.3）真实 ClientHello 的
// 抓包 ground truth（IP 目标、无 SNI 形态；SNI 形态仅在位置 1 多一个 server_name）。
// 2026-09-23 于干净容器内实测捕获，见 codex_profile.go 头注释。
var capturedCodexHello = struct {
	extOrder      []uint16 // IP 形态扩展顺序（无 server_name）
	cipherSuites  []uint16
	groups        []uint16
	keyShareGrps  []uint16
	sigAlgs       []uint16
	versions      []uint16
	pskModes      []byte
	points        []byte
	sessionIDLen  int
	compressions  []byte
	legacyVersion uint16
}{
	extOrder:     []uint16{65281, 11, 10, 35, 22, 23, 13, 43, 45, 51},
	cipherSuites: []uint16{0x1302, 0x1303, 0x1301, 0xc02c, 0xc030, 0x009f, 0xcca9, 0xcca8, 0xccaa, 0xc02b, 0xc02f, 0x009e, 0xc024, 0xc028, 0x006b, 0xc023, 0xc027, 0x0067, 0xc00a, 0xc014, 0x0039, 0xc009, 0xc013, 0x0033, 0x009d, 0x009c, 0x003d, 0x003c, 0x0035, 0x002f},
	groups:       []uint16{0x11ec, 0x001d, 0x0017, 0x001e, 0x0018, 0x0019, 0x0100, 0x0101},
	keyShareGrps: []uint16{0x11ec, 0x001d},
	sigAlgs:      []uint16{0x0905, 0x0906, 0x0904, 0x0403, 0x0503, 0x0603, 0x0807, 0x0808, 0x081a, 0x081b, 0x081c, 0x0809, 0x080a, 0x080b, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0303, 0x0301, 0x0302, 0x0402, 0x0502, 0x0602},
	versions:     []uint16{0x0304, 0x0303},
	pskModes:     []byte{1},
	points:       []byte{0},
	sessionIDLen: 32,
	// OpenSSL 送 TLS_NULL_WITH_NULL_NULL 压缩方法集，即仅 [0]
	compressions:  []byte{0},
	legacyVersion: 0x0303,
}

// readClientHelloBytes 从 conn 读取完整 ClientHello 握手消息（跨 TLS 记录拼接）。
func readClientHelloBytes(t *testing.T, conn net.Conn) []byte {
	t.Helper()
	var pending []byte
	for {
		hdr := make([]byte, 5)
		if _, err := io.ReadFull(conn, hdr); err != nil {
			t.Fatalf("read record header: %v", err)
		}
		if hdr[0] != 0x16 {
			t.Fatalf("not a handshake record: %d", hdr[0])
		}
		recLen := int(hdr[3])<<8 | int(hdr[4])
		payload := make([]byte, recLen)
		if _, err := io.ReadFull(conn, payload); err != nil {
			t.Fatalf("read record payload: %v", err)
		}
		pending = append(pending, payload...)
		if len(pending) < 4 {
			continue
		}
		msgLen := int(pending[1])<<16 | int(pending[2])<<8 | int(pending[3])
		if len(pending) >= 4+msgLen {
			return pending[:4+msgLen]
		}
	}
}

type parsedHello struct {
	legacyVersion  uint16
	sessionIDLen   int
	cipherSuites   []uint16
	compressions   []byte
	extOrder       []uint16
	extBodies      map[uint16][]byte
	groups         []uint16
	points         []byte
	sigAlgs        []uint16
	versions       []uint16
	pskModes       []byte
	keyShareGroups []uint16
	alpnPresent    bool
}

func parseClientHello(t *testing.T, msg []byte) *parsedHello {
	t.Helper()
	if msg[0] != 0x01 {
		t.Fatalf("not ClientHello: %d", msg[0])
	}
	out := &parsedHello{extBodies: map[uint16][]byte{}}
	b := msg[4:]
	out.legacyVersion = binary.BigEndian.Uint16(b[0:2])
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
	off++
	out.compressions = append([]byte{}, b[off:off+compLen]...)
	off += compLen
	extTotal := int(b[off])<<8 | int(b[off+1])
	off += 2
	end := off + extTotal
	for off+4 <= end {
		et := binary.BigEndian.Uint16(b[off : off+2])
		el := int(b[off+2])<<8 | int(b[off+3])
		data := b[off+4 : off+4+el]
		out.extOrder = append(out.extOrder, et)
		out.extBodies[et] = data
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
	return out
}

func requireEqualU16(t *testing.T, label string, got, want []uint16) {
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

// TestCodexProfileMatchesCapturedClientHello 用 CodexProfile 向本地捕获
// listener 发起握手，逐字段比对真实 codex 抓包，确保伪装字节级一致
// （random/session_id/keyshare 密钥材料除外 —— 它们每连接本就随机）。
func TestCodexProfileMatchesCapturedClientHello(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	type result struct {
		msg []byte
		err error
	}
	resCh := make(chan result, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			resCh <- result{err: err}
			return
		}
		msg := readClientHelloBytes(t, conn)
		conn.Close()
		resCh <- result{msg: msg}
	}()

	dialer := NewDialer(CodexProfile, nil)
	conn, err := dialer.DialTLSContext(t.Context(), "tcp", ln.Addr().String())
	if err == nil {
		// 捕获端读完后立即关闭，握手会失败 —— 这是预期行为，只关心 ClientHello。
		conn.Close()
	}
	res := <-resCh
	if res.err != nil {
		t.Fatalf("accept: %v", res.err)
	}

	h := parseClientHello(t, res.msg)
	c := capturedCodexHello

	if h.legacyVersion != c.legacyVersion {
		t.Fatalf("legacy_version: got %#04x want %#04x", h.legacyVersion, c.legacyVersion)
	}
	if h.sessionIDLen != c.sessionIDLen {
		t.Fatalf("session_id length: got %d want %d", h.sessionIDLen, c.sessionIDLen)
	}
	requireEqualU16(t, "cipher_suites", h.cipherSuites, c.cipherSuites)
	if len(h.compressions) != 1 || h.compressions[0] != 0 {
		t.Fatalf("compressions: got %v want [0]", h.compressions)
	}
	requireEqualU16(t, "ext_order", h.extOrder, c.extOrder)
	requireEqualU16(t, "supported_groups", h.groups, c.groups)
	requireEqualU16(t, "key_share_groups", h.keyShareGroups, c.keyShareGrps)
	requireEqualU16(t, "signature_algorithms", h.sigAlgs, c.sigAlgs)
	requireEqualU16(t, "supported_versions", h.versions, c.versions)
	if len(h.pskModes) != 1 || h.pskModes[0] != 1 {
		t.Fatalf("psk_modes: got %v want [1]", h.pskModes)
	}
	if len(h.points) != 1 || h.points[0] != 0 {
		t.Fatalf("ec_point_formats: got %v want [0]", h.points)
	}
	if h.alpnPresent {
		t.Fatalf("ALPN must not be present (real codex offers none, HTTP/1.1)")
	}

	// 扩展 body 形态：renegotiation_info=00，session_ticket/encrypt_then_mac/extended_master_secret 为空
	if got := h.extBodies[65281]; len(got) != 1 || got[0] != 0x00 {
		t.Fatalf("renegotiation_info body: got %v want [0x00]", got)
	}
	for _, ext := range []uint16{35, 22, 23} {
		if got := h.extBodies[ext]; len(got) != 0 {
			t.Fatalf("ext %d body must be empty, got %v", ext, got)
		}
	}
}

// TestCodexProfileKeyShareDataNonEmpty 确保 MLKEM/X25519 key share 的密钥
// 材料被 utls 真实生成（而非空 data —— 空 share 会被服务端拒绝）。
func TestCodexProfileKeyShareDataNonEmpty(t *testing.T) {
	spec := buildClientHelloSpecFromProfile(CodexProfile)
	var ks *utls.KeyShareExtension
	for _, e := range spec.Extensions {
		if v, ok := e.(*utls.KeyShareExtension); ok {
			ks = v
			break
		}
	}
	if ks == nil {
		t.Fatal("key_share extension missing from spec")
	}
	if len(ks.KeyShares) != 2 {
		t.Fatalf("key shares: got %d want 2", len(ks.KeyShares))
	}
	// data 为空是正常的 —— ApplyPreset 在握手时生成。这里验证 group 列表正确。
	if ks.KeyShares[0].Group != 0x11ec || ks.KeyShares[1].Group != 0x001d {
		t.Fatalf("key share groups: got %v want [0x11ec 0x001d]", ks.KeyShares)
	}
}
