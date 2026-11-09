package scanner

import (
	"bytes"
	"strings"
)

// 协议探针表。顺序即优先级：被动 banner 型协议（连上就自报家门）先判，
// 再按主动探针逐个试。每个 prober 用一条独立 TCP 连接，命中即停。
//
// 代价：最坏情况每个开放端口 N 次连接（N = len(probers)）。
// 收益：每种协议的判定互不干扰，HTTP/1.0 服务读完就关连接也不会
// 影响后续探针。限速器按「连接」计数，因此总发包速率仍受控。

// probeKind 是被动读取还是主动发送。
type prober struct {
	name    string
	payload []byte // nil = 只被动读 banner
	match   func([]byte) bool
	label   func([]byte) string
}

// printBanner 把二进制 banner 变成可读摘要：可打印字符保留，其余转点号并截断。
func printBanner(b []byte, limit int) string {
	if len(b) > limit {
		b = b[:limit]
	}
	var sb strings.Builder
	for _, c := range b {
		if c == '\r' || c == '\n' || c == '\t' {
			sb.WriteByte(' ')
		} else if c >= 0x20 && c < 0x7f {
			sb.WriteByte(c)
		} else {
			sb.WriteByte('.')
		}
	}
	return strings.TrimSpace(sb.String())
}

// mysqlGreeting: MySQL 握手包 = 3 字节长度 + 1 字节序号 + 协议版本(10)
// 或 9.x，随后是 "x.y.z" 版本串。
func mysqlGreeting(b []byte) bool {
	if len(b) < 6 {
		return false
	}
	ver := b[4]
	if ver != 10 && ver != 9 {
		return false
	}
	return bytes.IndexByte(b[5:], 0) > 0
}

// tlsClientHello 构造一个最小 TLS 1.2 ClientHello。
// random 全零在探测场景足够：服务端要么回 ServerHello(0x16)，要么回
// Alert(0x15)，两者都能证明这是 TLS 端口。不依赖 crypto/tls 是为了
// 避免握手超时受证书校验影响，也让探测包完全可控。
func tlsClientHello() []byte {
	body := []byte{0x03, 0x03}               // client_version = TLS 1.2
	body = append(body, make([]byte, 32)...) // random，探测用全零
	body = append(body, 0x00)                // session_id 长度 0
	body = append(body, 0x00, 0x02)          // cipher_suites 长度 2
	body = append(body, 0x00, 0x2f)          // TLS_RSA_WITH_AES_128_CBC_SHA
	body = append(body, 0x01, 0x00)          // compression_methods: null
	hs := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)
	rec := []byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}
	return append(rec, hs...)
}

var probers = []prober{
	{
		name:    "passive-banner",
		payload: nil,
		match: func(b []byte) bool {
			s := string(b)
			return strings.HasPrefix(s, "SSH-") ||
				strings.HasPrefix(s, "220 ") ||
				strings.HasPrefix(s, "421 ") ||
				mysqlGreeting(b)
		},
		label: func(b []byte) string {
			s := string(b)
			switch {
			case strings.HasPrefix(s, "SSH-"):
				return "ssh"
			case mysqlGreeting(b):
				return "mysql"
			case strings.HasPrefix(s, "220 "), strings.HasPrefix(s, "421 "):
				return "smtp-or-ftp"
			default:
				return "unknown"
			}
		},
	},
	{
		name:    "http",
		payload: []byte("GET / HTTP/1.0\r\nHost: localhost\r\nUser-Agent: fleetkeeper-scanner/1.0\r\n\r\n"),
		match: func(b []byte) bool {
			return bytes.HasPrefix(b, []byte("HTTP/")) || bytes.Contains(b[:min(len(b), 512)], []byte("HTTP/1."))
		},
		label: func(b []byte) string { return "http" },
	},
	{
		name:    "redis",
		payload: []byte("PING\r\n"),
		match: func(b []byte) bool {
			return bytes.Contains(b, []byte("+PONG")) || bytes.Contains(b, []byte("-ERR"))
		},
		label: func(b []byte) string { return "redis" },
	},
	{
		name:    "tls",
		payload: tlsClientHello(),
		match: func(b []byte) bool {
			return len(b) >= 5 && (b[0] == 0x16 || b[0] == 0x15) && b[1] == 0x03
		},
		label: func(b []byte) string { return "tls" },
	},
}
