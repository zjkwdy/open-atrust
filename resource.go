package main

import (
	"encoding/json"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

// ResourceIndex 是从 /controller/v1/user/clientResource 拉到的资源表：
// 每个 app 有 appId（= 资源 id）、若干访问地址（域名或 IP + 端口）。
// 官方客户端就是靠这张表把"任意内网访问"映射到对应 appId 的，用户不需要点任何图标。
var globalRes *ResourceIndex

type ResourceIndex struct {
	byHostPort map[string]string         // "host:port" -> appId
	byHost     map[string]string         // "host"      -> appId
	byDomPort  map[string]map[int]string // ".suffix" -> port -> appId（端口 0 = 域名级）
	byIP       map[string]string         // "1.2.3.4"   -> appId（端口无关）
	addrs      map[string][]resAddr      // appId -> 访问地址（用于把域名换成网关能解析的 IP）
	rawHosts   []resEntry                // 规则集导出用：每个 address/domain 一条
	Apps       int
}

// resEntry 是规则集导出的原始条目：一条 address 或一条 domain。
type resEntry struct {
	hosts       []string
	domains     []string
	port        int
	appID       string
	accessModel string
}

type resAddr struct {
	Host string
	Port int
}

type resApp struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	AccessModel string `json:"accessModel"`
	AddressList []struct {
		Protocol string `json:"protocol"`
		Port     string `json:"port"`
		Host     string `json:"host"`
	} `json:"addressList"`
	DomainList            []string `json:"domainList"`
	WebRelativeDomainList []string `json:"webRelativeDomainList"`
}

func newResourceIndex() *ResourceIndex {
	return &ResourceIndex{
		byHostPort: map[string]string{},
		byHost:     map[string]string{},
		byDomPort:  map[string]map[int]string{},
		byIP:       map[string]string{},
		addrs:      map[string][]resAddr{},
	}
}

// parseResources 解析 clientResource 响应：{code,data:{appList:{data:{appInfo:[{apps:[...]}]}}}}
func parseResources(raw []byte) (*ResourceIndex, error) {
	var top struct {
		Code int `json:"code"`
		Data struct {
			AppList struct {
				Data struct {
					AppInfo []struct {
						Apps []resApp `json:"apps"`
					} `json:"appInfo"`
				} `json:"data"`
			} `json:"appList"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &top); err != nil {
		return nil, err
	}
	ri := newResourceIndex()
	for _, g := range top.Data.AppList.Data.AppInfo {
		for _, a := range g.Apps {
			if a.ID == "" {
				continue
			}
			ri.Apps++
			for _, ad := range a.AddressList {
				h := strings.ToLower(strings.TrimSpace(ad.Host))
				if h == "" {
					continue
				}
				pt := 0
				if ad.Port != "" {
					pt = atoi(ad.Port)
					ri.byHostPort[h+":"+ad.Port] = a.ID
				}
				ri.addrs[a.ID] = append(ri.addrs[a.ID], resAddr{Host: h, Port: pt})
				ri.rawHosts = append(ri.rawHosts, resEntry{hosts: []string{h}, port: pt, appID: a.ID, accessModel: a.AccessModel})
				if strings.Contains(h, "*") {
					// *.cnki.net 只能按后缀匹配；写成字面量会导致 cnki.net 本身匹配不到。
					// 同一个域名在不同端口可能属于不同 app（cnki 的 80/443 就是两个 appId），
					// 所以后缀索引必须带端口。
					if suf := strings.Trim(h, "*."); suf != "" {
						key := "." + suf
						if ri.byDomPort[key] == nil {
							ri.byDomPort[key] = map[int]string{}
						}
						ri.byDomPort[key][pt] = a.ID
					}
					continue
				}
				if _, ok := ri.byHost[h]; !ok {
					ri.byHost[h] = a.ID
				}
				if isIPv4(h) {
					if _, ok := ri.byIP[h]; !ok {
						ri.byIP[h] = a.ID
					}
				}
			}
			for _, d := range a.DomainList {
				d = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(d, "*")))
				d = strings.TrimPrefix(d, ".")
				if d != "" {
					if ri.byDomPort["."+d] == nil {
						ri.byDomPort["."+d] = map[int]string{}
					}
					if _, ok := ri.byDomPort["."+d][0]; !ok {
						ri.byDomPort["."+d][0] = a.ID
					}
					ri.rawHosts = append(ri.rawHosts, resEntry{domains: []string{d}, appID: a.ID, accessModel: a.AccessModel})
				}
			}
			for _, w := range a.WebRelativeDomainList {
				w = strings.ToLower(w)
				if i := strings.Index(w, "://"); i >= 0 {
					w = w[i+3:]
				}
				if i := strings.IndexAny(w, "/?#"); i >= 0 {
					w = w[:i]
				}
				if i := strings.Index(w, ":"); i >= 0 {
					w = w[:i]
				}
				if w != "" {
					if ri.byDomPort["."+w] == nil {
						ri.byDomPort["."+w] = map[int]string{}
					}
					if _, ok := ri.byDomPort["."+w][0]; !ok {
						ri.byDomPort["."+w][0] = a.ID
					}
					ri.rawHosts = append(ri.rawHosts, resEntry{domains: []string{w}, appID: a.ID, accessModel: a.AccessModel})
				}
			}
		}
	}
	return ri, nil
}

func isIPv4(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if p == "" || len(p) > 3 {
			return false
		}
		for _, c := range p {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	return true
}

// lookup 按 host / host:port / 域名后缀依次匹配。
func (r *ResourceIndex) lookup(host string, port int) (string, bool) {
	if r == nil {
		return "", false
	}
	h := strings.ToLower(host)
	hp := h + ":" + itoa(port)
	if id, ok := r.byHostPort[hp]; ok {
		return id, true
	}
	if id, ok := r.byHost[h]; ok {
		return id, true
	}
	if id, ok := r.byIP[h]; ok {
		return id, true
	}
	for suffix, m := range r.byDomPort {
		if !(strings.HasSuffix(h, suffix) || h == strings.TrimPrefix(suffix, ".")) {
			continue
		}
		if pid, ok := m[port]; ok {
			return pid, true
		}
		if pid, ok := m[0]; ok {
			return pid, true
		}
		for _, pid := range m {
			return pid, true
		}
	}
	return "", false
}

// appIDFor 决定这次连接用哪个 appId：显式配置优先（host:port 级 > 域名级），
// 配置里写 "auto" 或留空时完全依赖资源表。
type dnsEntry struct {
	ips []string
	exp time.Time
}

var (
	dnsMu    sync.Mutex
	dnsCache = map[string]dnsEntry{}
)

const (
	dnsTTL    = 10 * time.Minute
	dnsNegTTL = 30 * time.Second
)

// resolveHostIPs 只给"资源表里按 IP 登记"的场景补一条 DNS 查询，带 TTL，
// 避免每条新连接都打一次系统解析器。
func resolveHostIPs(host string) []string {
	dnsMu.Lock()
	if e, ok := dnsCache[host]; ok && time.Now().Before(e.exp) {
		dnsMu.Unlock()
		return e.ips
	}
	dnsMu.Unlock()

	ips, err := net.LookupHost(host)
	entry := dnsEntry{ips: ips, exp: time.Now().Add(dnsTTL)}
	if err != nil || len(ips) == 0 {
		entry = dnsEntry{ips: nil, exp: time.Now().Add(dnsNegTTL)}
	}
	dnsMu.Lock()
	dnsCache[host] = entry
	dnsMu.Unlock()
	return entry.ips
}

func (c Config) appIDFor(host string, port int) (string, bool) {
	if c.Res == nil {
		return "", false
	}
	// 域名可能只在资源表里登记了 IP，先按 host，再按解析出的 IP 匹配。
	if id, ok := c.Res.lookup(host, port); ok {
		if c.Verbose {
			log.Printf("[res] %s:%d -> appId %s", host, port, id)
		}
		return id, true
	}
	for _, ip := range resolveHostIPs(host) {
		if id, ok := c.Res.lookup(ip, port); ok {
			if c.Verbose {
				log.Printf("[res] %s(%s):%d -> appId %s", host, ip, port, id)
			}
			return id, true
		}
	}
	// 显式钉死 appId 时才兜底；"auto" 或空表示"只按资源表"，未命中必须失败，
	// 否则会把上一个命中过的 appId 泄漏给任意域名（实测会把 baidu 解析成内网 IP）。
	if c.AppID != "" && c.AppID != "auto" {
		return c.AppID, true
	}
	return "", false
}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	return n
}

// dialHost 决定实际拨号目标：域名常被网关侧解析不了，而资源表登记的是 IP，
// 这里优先换成 IP:port（官方客户端 addrPretend 做的是同一件事）。
func (r *ResourceIndex) dialHost(appID, host string, port int) (string, int) {
	if r == nil || appID == "" || isIPv4(host) {
		return host, port
	}
	entries := r.addrs[appID]
	if len(entries) == 0 {
		return host, port
	}
	ips := resolveHostIPs(host)
	for _, e := range entries {
		if e.Port != 0 && e.Port != port {
			continue
		}
		if isIPv4(e.Host) {
			for _, ip := range ips {
				if ip == e.Host {
					return e.Host, port
				}
			}
		}
	}
	var cand []string
	for _, e := range entries {
		if (e.Port == 0 || e.Port == port) && isIPv4(e.Host) {
			cand = append(cand, e.Host)
		}
	}
	if len(cand) == 1 {
		return cand[0], port
	}
	return host, port
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [8]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
