// atrust-proxy —— aTrust tcpTunnel 协议 PoC（SOCKS5 前端）
//
// 用途：把 tcpTunnel 的"每连接一次握手 + 裸字节中继"包装成标准 SOCKS5 代理，
//
//	便于用浏览器 / curl / 任意程序验证协议理解是否正确。
//
// 仅用于你本人已授权的账号与设备；sid 等价登录态，勿外传。
package main

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ---------- 配置 ----------

type Config struct {
	Listen   string `json:"listen"`   // SOCKS5 监听地址
	Gateway  string `json:"gateway"`  // 隧道网关 ip:port（本校 441）
	SNI      string `json:"sni"`      // TLS SNI，必须是门户域名
	DeviceID string `json:"-"`        // 32 hex，存在 <config>.state.json
	AppID    string `json:"appId"`    // "auto" = 按资源表自动选；也可写死 UUID
	User     string `json:"user"`     // 账号
	Password string `json:"password"` // 密码（只放配置文件里）
	ProcName string `json:"procName"` // 伪装的目标进程名（影响 procHash）
	ProcPath string `json:"procPath"` // 伪装的目标进程路径
	Lang     string `json:"lang"`     // zh-CN / en-US
	DestIP   string `json:"destIP"`   // 可选：显式 destIP；留空与官方客户端一致
	Verbose  bool   `json:"verbose"`

	// 不在资源表里的目标：false（默认）= 直接拒绝；true = 像官方客户端那样直连
	DirectFallback bool `json:"directFallback"`

	// 设备身份与网关 cookie：全部落在 <config>.state.json，不进用户配置
	TID         string `json:"-"`
	TIDSig      string `json:"-"`
	StraceID    string `json:"-"`
	StraceIDSig string `json:"-"`
	LimitTag    string `json:"-"`
	LimitTagSig string `json:"-"`

	LoginListen string `json:"loginListen"` // 需人工过验证码时的本地网页地址

	// Clash rule-provider：空 = 不启动；默认 127.0.0.1:18090
	RuleListen string `json:"ruleListen"`
	RuleName   string `json:"ruleName"` // 文件名/规则集名，默认 aTrust

	// 预握手连接池大小（0 = 关闭）。默认 2
	PoolSize int `json:"poolSize"`

	Res  *ResourceIndex `json:"-"` // 资源表（内存）
	path string         `json:"-"` // 配置文件路径（回写 tid 用）
}

func defaultConfig() Config {
	return Config{
		Listen:   "127.0.0.1:1080",
		Gateway:  "221.203.22.52:441",
		SNI:      "vpn.ustl.edu.cn",
		Lang:     "zh-CN",
		ProcName: "chrome.exe",
		ProcPath: `C:\Program Files\Google\Chrome\Application\chrome.exe`,
	}
}

// ---------- AuthRequest（字段名 = Go struct tag，已由伪 C / 实测确认） ----------

type procInfo struct {
	Name             string `json:"name"`
	Path             string `json:"path"`
	Version          string `json:"version"`
	DigitalSignature string `json:"digital_signature"`
	Platform         string `json:"platform"`
	Fingerprint      string `json:"fingerprint"`
	Description      string `json:"description"`
	SecurityEnv      string `json:"security_env"`
}

type runtimeInfo struct {
	Process        procInfo `json:"process"`
	ProcessTrusted string   `json:"process_trusted"`
}

type appInfo struct {
	Runtime runtimeInfo `json:"runtime"`
}

type envWrap struct {
	Application appInfo `json:"application"`
}

type authReq struct {
	SID           string  `json:"sid"`
	AppID         string  `json:"appId"`
	URL           string  `json:"url"`
	DeviceID      string  `json:"deviceId"`
	ConnectionID  string  `json:"connectionId"`
	ProcHash      string  `json:"procHash"`
	UserName      string  `json:"userName"`
	RcAppliedInfo int     `json:"rcAppliedInfo"`
	Lang          string  `json:"lang"`
	DestAddr      string  `json:"destAddr"`
	DestIP        string  `json:"destIP,omitempty"`
	Env           envWrap `json:"env"`
	XRequestSig   string  `json:"xRequestSig"`
}

type authResp struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
}

// ---------- 隧道客户端 ----------

type Client struct {
	cfg     Config
	connSeq uint64
	baseID  string
	pool    *tlsPool
}

func NewClient(cfg Config) *Client {
	if cfg.Lang == "" {
		cfg.Lang = "zh-CN"
	}
	return &Client{cfg: cfg, baseID: randHex(16), pool: newTLSPool(cfg)}
}

func randHex(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(rand.Intn(256))
	}
	return strings.ToUpper(hex.EncodeToString(b))
}

func sha256hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return strings.ToUpper(hex.EncodeToString(h[:]))
}

func be16(n int) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, uint16(n))
	return b
}

var errNoRoute = errors.New("no route")

// Dial 建立一条到网关的隧道，并对 dest 完成握手。返回可直接读写的连接。
func (c *Client) Dial(destHost string, destPort int) (net.Conn, error) {
	// 先判定路由：不在资源表里就直接失败（不建 TLS、不打网关），
	// 否则会把上一次命中的 appId 泄漏给任意域名。
	id, ok := c.cfg.appIDFor(destHost, destPort)
	if !ok {
		if c.cfg.DirectFallback {
			c.logf("direct dial -> %s:%d (not a resource)", destHost, destPort)
			return net.DialTimeout("tcp", net.JoinHostPort(destHost, strconv.Itoa(destPort)), 10*time.Second)
		}
		return nil, fmt.Errorf("%w: %s:%d", errNoRoute, destHost, destPort)
	}
	if c.cfg.Res != nil {
		if dh, dp := c.cfg.Res.dialHost(id, destHost, destPort); dh != destHost || dp != destPort {
			c.logf("dial target -> %s:%d (resource address)", dh, dp)
			destHost, destPort = dh, dp
		}
	}

	body, err := c.buildAuthRequest(destHost, destPort, id)
	if err != nil {
		return nil, err
	}
	// 流水线：greeting + auth + CONNECT 一次写出，服务端按序处理，按序读回三个应答。
	frame := make([]byte, 0, 3+4+len(body)+8+len(destHost))
	frame = append(frame, 0x05, 0x01, 0x81)
	frame = append(frame, 0x53, 0x03)
	frame = append(frame, be16(len(body))...)
	frame = append(frame, body...)
	frame = append(frame, buildConnect(destHost, destPort)...)

	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		tc, pooled := c.pool.take()
		if tc == nil {
			tc, err = c.pool.dial()
			if err != nil {
				return nil, fmt.Errorf("dial gateway %s: %w", c.cfg.Gateway, err)
			}
		}
		conn := &tunnelConn{Conn: tc, r: bufio.NewReaderSize(tc, 64*1024)}
		if err := c.handshake(conn, frame, len(body)); err != nil {
			conn.Close()
			lastErr = err
			if pooled {
				continue // 池里的旧连接可能已被服务端回收，换一条新拨的重试一次
			}
			return nil, err
		}
		if pooled {
			c.logf("tunnel ready (pooled, %d bytes)", len(frame))
		}
		return conn, nil
	}
	return nil, lastErr
}

// handshake 读回 greeting / auth / connect 三个应答，全部通过才算隧道可用。
func (c *Client) handshake(conn *tunnelConn, frame []byte, bodyLen int) error {
	if err := writeAll(conn, frame); err != nil {
		return fmt.Errorf("write pipelined frame: %w", err)
	}
	c.logf("pipelined: greeting+auth(%d)+connect %d bytes", bodyLen, len(frame))

	greet := make([]byte, 2)
	if err := readFull(conn.r, greet); err != nil {
		return fmt.Errorf("read greeting reply: %w", err)
	}
	if greet[0] != 0x05 {
		return fmt.Errorf("bad greeting reply: % x", greet)
	}

	hdr := make([]byte, 4)
	if err := readFull(conn.r, hdr); err != nil {
		return fmt.Errorf("read auth header: %w", err)
	}
	if hdr[0] != 0x53 {
		return fmt.Errorf("bad auth header: % x", hdr)
	}
	blen := int(binary.BigEndian.Uint16(hdr[2:4]))
	rbody := make([]byte, blen)
	if blen > 0 {
		if err := readFull(conn.r, rbody); err != nil {
			return fmt.Errorf("read auth body: %w", err)
		}
	}
	var ar authResp
	_ = json.Unmarshal(rbody, &ar)
	c.logf("auth reply: status=%d code=%d msg=%q bodylen=%d", hdr[1], ar.Code, ar.Message, blen)
	if hdr[1] != 0x00 || (ar.Message != "" && ar.Code != 0) {
		if ar.Message != "" {
			return fmt.Errorf("auth rejected: code=%d message=%q", ar.Code, ar.Message)
		}
		return fmt.Errorf("auth rejected: status=%d body=%s", hdr[1], truncate(rbody, 300))
	}
	return nil
}

func buildConnect(host string, port int) []byte {
	out := []byte{0x05, 0x01, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			out = append(out, 0x01)
			out = append(out, v4...)
		} else {
			out = append(out, 0x04)
			out = append(out, ip.To16()...)
		}
	} else {
		out = append(out, 0x03, byte(len(host)))
		out = append(out, []byte(host)...)
	}
	return append(out, be16(port)...)
}

func (c *Client) buildAuthRequest(destHost string, destPort int, appID string) ([]byte, error) {
	n := atomic.AddUint64(&c.connSeq, 1)
	procHash := sha256hex("atrust-poc:" + c.cfg.ProcName)
	// 官方客户端对资源域名发的 destIP 是空串（日志里 destIP:empty），
	// 本地解析只会拿到 fake IP 198.18.0.x，反而可能被服务端判为不一致。
	destIP := c.cfg.DestIP
	curSID := sidNow()
	req := authReq{
		SID:           curSID,
		AppID:         appID,
		URL:           fmt.Sprintf("tcp://%s", net.JoinHostPort(destHost, strconv.Itoa(destPort))),
		DeviceID:      c.cfg.DeviceID,
		ConnectionID:  fmt.Sprintf("%s-%08X", c.baseID, n),
		ProcHash:      procHash,
		UserName:      c.cfg.User,
		RcAppliedInfo: 0,
		Lang:          c.cfg.Lang,
		DestAddr:      net.JoinHostPort(destHost, strconv.Itoa(destPort)),
		DestIP:        destIP,
		Env: envWrap{Application: appInfo{Runtime: runtimeInfo{
			Process: procInfo{
				Name:        c.cfg.ProcName,
				Path:        c.cfg.ProcPath,
				Platform:    "windows",
				Fingerprint: procHash,
				SecurityEnv: "normal",
			},
			ProcessTrusted: "UNKNOWN",
		}}},
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	// 服务端验签方式（实测，见 04 §7A）：待签数据 = 把 xRequestSig 置空后的整份 JSON 字节，
	// 算法 = HMAC-SHA256(signKey, data) 输出大写 hex；signKey 在内存里（登录时由 challenge 推导）。
	if kh := sigKeyNow(); kh != "" {
		kb, err := hex.DecodeString(kh)
		if err != nil {
			return nil, err
		}
		mac := hmac.New(sha256.New, kb)
		mac.Write(body)
		sig := strings.ToUpper(hex.EncodeToString(mac.Sum(nil)))
		body = bytes.Replace(body, []byte(`"xRequestSig":""`), []byte(`"xRequestSig":"`+sig+`"`), 1)
	}
	return body, nil
}

func (c *Client) logf(format string, args ...any) {
	if c.cfg.Verbose {
		log.Printf("[tunnel] "+format, args...)
	}
}

// ---------- 连接封装 ----------

type tunnelConn struct {
	net.Conn
	r       *bufio.Reader
	ackDone bool
}

// Read 在第一次读之前把 CONNECT 的应答吃掉。放在这里而不是握手末尾，
// 是为了让 SOCKS 成功应答尽快返回给客户端：ack 的 RTT 与客户端的请求 RTT 重叠。
func (t *tunnelConn) Read(p []byte) (int, error) {
	if !t.ackDone {
		t.ackDone = true
		_ = t.consumeConnectAck()
	}
	return t.r.Read(p)
}

// consumeConnectAck 读 CONNECT 应答：0x05 开头是 SOCKS5 应答，两字节 00 00 是网关的简化 ack；
// 60ms 内什么都没有就当服务端不回应答，数据留给 relay。
func (t *tunnelConn) consumeConnectAck() error {
	t.Conn.SetReadDeadline(time.Now().Add(60 * time.Millisecond))
	defer t.Conn.SetReadDeadline(time.Time{})

	b, err := t.r.Peek(2)
	if err != nil {
		if len(b) == 1 && b[0] == 0x00 {
			_, _ = t.r.Discard(1)
		}
		return nil
	}
	if b[0] == 0x00 && b[1] == 0x00 {
		_, _ = t.r.Discard(2)
		return nil
	}
	if b[0] != 0x05 {
		return nil
	}
	head := make([]byte, 4)
	if _, err := io.ReadFull(t.r, head); err != nil {
		return err
	}
	switch head[3] {
	case 0x01:
		_, err = t.r.Discard(4 + 2)
	case 0x03:
		l, e := t.r.ReadByte()
		if e != nil {
			return e
		}
		_, err = t.r.Discard(int(l) + 2)
	case 0x04:
		_, err = t.r.Discard(16 + 2)
	default:
		return nil
	}
	return err
}

func writeAll(w io.Writer, b []byte) error {
	_, err := w.Write(b)
	return err
}

func readFull(r io.Reader, b []byte) error {
	_, err := io.ReadFull(r, b)
	return err
}

func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "…"
}

// ---------- SOCKS5 服务端 ----------

func serve(cfg Config) error {
	cl := NewClient(cfg)
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}
	log.Printf("SOCKS5 listening on %s -> gateway %s (sni=%s, appId=%s)",
		cfg.Listen, cfg.Gateway, cfg.SNI, cfg.AppID)
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go handleSocks(c, cl)
	}
}

func handleSocks(c net.Conn, cl *Client) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(30 * time.Second))
	br := bufio.NewReader(c)

	// 握手：VER NMETHODS METHODS
	head := make([]byte, 2)
	if _, err := io.ReadFull(br, head); err != nil || head[0] != 0x05 {
		return
	}
	methods := make([]byte, int(head[1]))
	if _, err := io.ReadFull(br, methods); err != nil {
		return
	}
	if _, err := c.Write([]byte{0x05, 0x00}); err != nil { // 无认证
		return
	}

	// 请求：VER CMD RSV ATYP
	req := make([]byte, 4)
	if _, err := io.ReadFull(br, req); err != nil || req[0] != 0x05 {
		return
	}
	if req[1] != 0x01 { // 只支持 CONNECT
		c.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	host, err := readSocksAddr(br, req[3])
	if err != nil {
		replySocksErr(c, 0x08)
		return
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(br, pb); err != nil {
		return
	}
	port := int(binary.BigEndian.Uint16(pb))
	c.SetDeadline(time.Time{})

	dest := net.JoinHostPort(host, strconv.Itoa(port))
	tun, err := cl.Dial(host, port)
	if err != nil {
		log.Printf("[%s] FAILED: %v", dest, err)
		if errors.Is(err, errNoRoute) {
			replySocksErr(c, 0x04) // host unreachable: 不在资源表里
		} else {
			replySocksErr(c, 0x05) // connection refused
		}
		return
	}
	defer tun.Close()
	log.Printf("[%s] tunnel established", dest)
	if _, err := c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	relay(c, br, tun)
}

func readSocksAddr(r *bufio.Reader, atyp byte) (string, error) {
	switch atyp {
	case 0x01:
		b := make([]byte, 4)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		return net.IP(b).String(), nil
	case 0x04:
		b := make([]byte, 16)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		return net.IP(b).String(), nil
	case 0x03:
		l, err := r.ReadByte()
		if err != nil {
			return "", err
		}
		b := make([]byte, int(l))
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		return string(b), nil
	}
	return "", errors.New("bad atyp")
}

func replySocksErr(c net.Conn, code byte) {
	c.Write([]byte{0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
}

// relay 双向复制；客户端 → 隧道时要把 SOCKS 遗留缓冲一起写出。
func relay(client net.Conn, cbuf *bufio.Reader, tun net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() { // client -> tunnel
		defer wg.Done()
		io.Copy(tun, cbuf)
		if tc, ok := tun.(*tls.Conn); ok {
			tc.CloseWrite()
		}
	}()
	go func() { // tunnel -> client
		defer wg.Done()
		io.Copy(client, tun)
		if cw, ok := client.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
	}()
	wg.Wait()
}

// ---------- main ----------

func main() {
	log.SetFlags(log.Ltime)

	// 唯一的输入是一个 config*.json：`atrust-proxy config.json` 或 `-config config.json`
	args := os.Args[1:]
	path := "config.json"
	if len(args) > 0 {
		if args[0] == "-config" || args[0] == "--config" {
			if len(args) < 2 {
				log.Fatalf("usage: %s <config.json>", os.Args[0])
			}
			path = args[1]
		} else if !strings.HasPrefix(args[0], "-") {
			path = args[0]
		}
	}
	cfg, err := loadConfig(path)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	if err := run(cfg); err != nil {
		log.Fatalf("run: %v", err)
	}
}
