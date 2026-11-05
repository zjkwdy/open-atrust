package main

import (
	"crypto/tls"
	"net"
	"sync"
	"time"
)

// tlsPool 常备几条已握手完成的到网关连接。隧道协议里 auth 帧绑定目的地，
// 所以只能预握 TLS，不能预认证；省掉的是 TCP+TLS 那一个 RTT 和密钥交换 CPU。
//
// 网关的连接在空闲 20s 内实测仍可用，池里超过 idleMax 的连接直接丢弃。
type tlsPool struct {
	cfg  Config
	idle chan pooledConn
	once sync.Once
}

type pooledConn struct {
	c     net.Conn
	built time.Time
}

const idleMax = 15 * time.Second

func newTLSPool(cfg Config) *tlsPool {
	n := cfg.PoolSize
	if n < 0 {
		n = 0
	}
	p := &tlsPool{cfg: cfg, idle: make(chan pooledConn, n)}
	if n > 0 {
		go p.fill()
	}
	return p
}

func (p *tlsPool) take() (net.Conn, bool) {
	for {
		select {
		case pc, ok := <-p.idle:
			if !ok || pc.c == nil {
				return nil, false
			}
			if time.Since(pc.built) > idleMax {
				pc.c.Close()
				continue
			}
			return pc.c, true
		default:
			return nil, false
		}
	}
}

func (p *tlsPool) put(c net.Conn) {
	select {
	case p.idle <- pooledConn{c: c, built: time.Now()}:
	default:
		c.Close()
	}
}

// fill 持续补到满员。取走一条后最多 100ms 就会补上新的，避免"池子空了才现拨"。
func (p *tlsPool) fill() {
	for {
		if len(p.idle) >= cap(p.idle) {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		c, err := p.dial()
		if err != nil {
			time.Sleep(500 * time.Millisecond)
			continue
		}
		p.put(c)
	}
}

func (p *tlsPool) dial() (net.Conn, error) {
	raw, err := net.DialTimeout("tcp", p.cfg.Gateway, 10*time.Second)
	if err != nil {
		return nil, err
	}
	tc := tls.Client(raw, tlsClientConfig(p.cfg))
	tc.SetDeadline(time.Now().Add(15 * time.Second))
	if err := tc.Handshake(); err != nil {
		raw.Close()
		return nil, err
	}
	tc.SetDeadline(time.Time{})
	return tc, nil
}

var sessionCache = tls.NewLRUClientSessionCache(16)

func tlsClientConfig(cfg Config) *tls.Config {
	return &tls.Config{
		ServerName:         cfg.SNI,
		InsecureSkipVerify: true, // 网关证书自签/过期，官方客户端同样不校验
		MinVersion:         tls.VersionTLS12,
		ClientSessionCache: sessionCache,
	}
}
