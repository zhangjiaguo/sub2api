package tlsfingerprint

// CodexProfile 是从真实 Codex CLI 抓包提取的内置 TLS 指纹。
//
// 抓包环境：codex-cli 0.155.1（npm @openai/codex 平台二进制，Linux musl），
// TLS 栈为 native-tls → OpenSSL 3.6.3（reqwest 默认后端，非 rustls）。
// 2026-09-23 在干净容器内通过本地 ClientHello 捕获服务器实测获得，
// SNI 与非 SNI 两种形态（域名 / IP）除 server_name 外逐字段一致。
//
// 关键特征：
//   - 无 ALPN（codex 以 HTTP/1.1 直连 chatgpt.com，不协商 h2）
//   - 无 GREASE、无证书压缩、无 OCSP/SCT
//   - X25519MLKEM768 (0x11ec) 为首选 group，且同时携带 X25519 key share
//   - 30 个密码套件（含 CAMELLIA/DHE 等 OpenSSL 全家桶）
//   - 26 个签名算法（含 ML-DSA 试行码点 0x0904-0x0906）
//
// 精确值（顺序即线上出现顺序）：
//
//	扩展顺序:      65281, 0(SNI), 11, 10, 35, 22, 23, 13, 43, 45, 51
//	密码套件:      1302,1303,1301,c02c,c030,009f,cca9,cca8,ccaa,c02b,c02f,009e,
//	               c024,c028,006b,c023,c027,0067,c00a,c014,0039,c009,c013,0033,
//	               009d,009c,003d,003c,0035,002f
//	Groups:        11ec,001d,0017,001e,0018,0019,0100,0101
//	KeyShare:      11ec,001d
//	签名算法:      0905,0906,0904,0403,0503,0603,0807,0808,081a,081b,081c,
//	               0809,080a,080b,0804,0805,0806,0401,0501,0601,0303,0301,
//	               0302,0402,0502,0602
//	SupportedVers: 0304,0303
//	PSKModes:      01    Points: 00    session_id: 32 字节随机
//
// 注意：扩展顺序中不含 16(alpn)，因此该 profile 不会发送 ALPN；
// 22(encrypt_then_mac) 走 GenericExtension 空 body，与 OpenSSL 行为一致；
// KeyShare 的 MLKEM768/X25519 密钥材料由 utls ApplyPreset 每连接现生成。
var CodexProfile = &Profile{
	Name: "Built-in Codex CLI (OpenSSL 3.6, codex-cli 0.155.1)",
	CipherSuites: []uint16{
		0x1302, // TLS_AES_256_GCM_SHA384
		0x1303, // TLS_CHACHA20_POLY1305_SHA256
		0x1301, // TLS_AES_128_GCM_SHA256

		0xc02c, // ECDHE-ECDSA-AES256-GCM-SHA384
		0xc030, // ECDHE-RSA-AES256-GCM-SHA384
		0x009f, // DHE-RSA-AES256-GCM-SHA384
		0xcca9, // ECDHE-ECDSA-CHACHA20-POLY1305
		0xcca8, // ECDHE-RSA-CHACHA20-POLY1305
		0xccaa, // DHE-RSA-CHACHA20-POLY1305
		0xc02b, // ECDHE-ECDSA-AES128-GCM-SHA256
		0xc02f, // ECDHE-RSA-AES128-GCM-SHA256
		0x009e, // DHE-RSA-AES128-GCM-SHA256

		0xc024, // ECDHE-ECDSA-CAMELLIA256-SHA384
		0xc028, // ECDHE-RSA-CAMELLIA256-SHA384
		0x006b, // DHE-RSA-CAMELLIA256-SHA256
		0xc023, // ECDHE-ECDSA-CAMELLIA128-SHA256
		0xc027, // ECDHE-RSA-CAMELLIA128-SHA256
		0x0067, // DHE-RSA-CAMELLIA128-SHA

		0xc00a, // ECDHE-ECDSA-AES256-CBC-SHA
		0xc014, // ECDHE-RSA-AES256-CBC-SHA
		0x0039, // DHE-RSA-AES256-CBC-SHA
		0xc009, // ECDHE-ECDSA-AES128-CBC-SHA
		0xc013, // ECDHE-RSA-AES128-CBC-SHA
		0x0033, // DHE-RSA-AES128-CBC-SHA

		0x009d, // RSA-AES256-GCM-SHA384
		0x009c, // RSA-AES128-GCM-SHA256
		0x003d, // RSA-AES256-CBC-SHA256
		0x003c, // RSA-AES128-CBC-SHA256
		0x0035, // RSA-AES256-CBC-SHA
		0x002f, // RSA-AES128-CBC-SHA
	},
	Curves: []uint16{
		0x11ec, // X25519MLKEM768
		0x001d, // x25519
		0x0017, // secp256r1
		0x001e, // x448
		0x0018, // secp384r1
		0x0019, // secp521r1
		0x0100, // ffdhe2048
		0x0101, // ffdhe3072
	},
	PointFormats: []uint16{0},
	SignatureAlgorithms: []uint16{
		0x0905, 0x0906, 0x0904, // ML-DSA 试行码点（仅列出，服务端不会选择）
		0x0403, // ecdsa_secp256r1_sha256
		0x0503, // ecdsa_secp384r1_sha384
		0x0603, // ecdsa_secp521r1_sha512
		0x0807, // ed25519
		0x0808, // ed448
		0x081a, // rsa_pss_pss_sha256
		0x081b, // rsa_pss_pss_sha384
		0x081c, // rsa_pss_pss_sha512
		0x0809, // ecdsa_brainpoolP256r1tls13_sha256
		0x080a, // ecdsa_brainpoolP384r1tls13_sha384
		0x080b, // ecdsa_brainpoolP512r1tls13_sha512
		0x0804, // rsa_pss_rsae_sha256
		0x0805, // rsa_pss_rsae_sha384
		0x0806, // rsa_pss_rsae_sha512
		0x0401, // rsa_pkcs1_sha256
		0x0501, // rsa_pkcs1_sha384
		0x0601, // rsa_pkcs1_sha512
		0x0303, // ecdsa_sha224
		0x0301, // rsa_pkcs1_sha224
		0x0302, // dsa_sha224
		0x0402, // dsa_sha256
		0x0502, // dsa_sha384
		0x0602, // dsa_sha512
	},
	SupportedVersions: []uint16{0x0304, 0x0303},
	KeyShareGroups: []uint16{
		0x11ec, // X25519MLKEM768（首选，ApplyPreset 生成 ML-KEM + X25519 组合 share）
		0x001d, // x25519 兜底 share
	},
	PSKModes: []uint16{1},
	// 顺序即抓包扩展顺序；不含 16(alpn) —— codex 不协商 ALPN，HTTP/1.1 直连。
	// 22(encrypt_then_mac) 无 case，走 GenericExtension 空 body。
	Extensions: []uint16{
		65281, // renegotiation_info
		0,     // server_name（由 utls 按 ServerName 填充；IP 目标时 OpenSSL 同样省略）
		11,    // ec_point_formats
		10,    // supported_groups
		35,    // session_ticket（空）
		22,    // encrypt_then_mac（空）
		23,    // extended_master_secret（空）
		13,    // signature_algorithms
		43,    // supported_versions
		45,    // psk_key_exchange_modes
		51,    // key_share
	},
}
