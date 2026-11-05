package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Clash rule-provider：把资源表导出成 payload 形式的规则集。
//
// 设计取舍（和官方客户端的"重定向"等价，但更保守）：
//   - 域名：DOMAIN-SUFFIX（覆盖子域），另给一份 DOMAIN 精确匹配；
//   - IP：IP-CIDR /32 或 IP-CIDR6 /128，一律 no-resolve（避免 Clash 自己反查 DNS）；
//   - 端口：非 80/443 的 (host,port) 额外生成 AND 规则，避免把整台机器都代理走。
//
// 规则集是按请求现算的（资源表在续期后可能变），所以这里只缓存渲染结果 30s。

var (
	resMu     sync.RWMutex
	ruleCache struct {
		body []byte
		at   time.Time
	}
)

// setGlobalRes 在登录/续期后更新资源表。
func setGlobalRes(ri *ResourceIndex) {
	resMu.Lock()
	globalRes = ri
	resMu.Unlock()
}

func getGlobalRes() *ResourceIndex {
	resMu.RLock()
	defer resMu.RUnlock()
	return globalRes
}

const ruleCacheTTL = 30 * time.Second

// renderRules 把资源表渲染成 clash rule-provider 的 YAML。
func renderRules(name string) []byte {
	ri := getGlobalRes()
	domSuffix := map[string]struct{}{}
	domExact := map[string]struct{}{}
	ip4 := map[string]struct{}{}
	ip6 := map[string]struct{}{}
	andRules := map[string]struct{}{}

	if ri != nil {
		for _, e := range ri.rawHosts {
			for _, d := range e.domains {
				d = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(d, ".")))
				if d != "" {
					domSuffix[d] = struct{}{}
				}
			}
			for _, h := range e.hosts {
				h = strings.ToLower(strings.TrimSpace(h))
				if h == "" {
					continue
				}
				// 通配主机（*.example.com / *.*.example.com）只能当后缀规则，
				// 直接写成 DOMAIN 会让 clash 报 "unsupported rule"。
				if strings.Contains(h, "*") {
					suf := strings.Trim(h, "*.")
					if suf != "" {
						domSuffix[suf] = struct{}{}
						if e.port != 0 && e.port != 80 && e.port != 443 {
							andRules[fmt.Sprintf("AND,((DOMAIN-SUFFIX,%s),(DST-PORT,%d))", suf, e.port)] = struct{}{}
						}
					}
					continue
				}
				if ip := net.ParseIP(h); ip != nil {
					if ip.To4() != nil {
						ip4[ip.String()] = struct{}{}
					} else {
						ip6[ip.String()] = struct{}{}
					}
					continue
				}
				domExact[h] = struct{}{}
				// 非标准端口的域名访问：AND((DOMAIN,x),(DST-PORT,p))
				if e.port != 0 && e.port != 80 && e.port != 443 {
					andRules[fmt.Sprintf("AND,((DOMAIN,%s),(DST-PORT,%d))", h, e.port)] = struct{}{}
				}
			}
			for _, h := range e.hosts {
				if ip := net.ParseIP(strings.TrimSpace(h)); ip != nil && e.port != 0 && e.port != 80 && e.port != 443 {
					andRules[fmt.Sprintf("AND,((IP-CIDR,%s/32),(DST-PORT,%d))", ip.String(), e.port)] = struct{}{}
				}
			}
		}
	}

	suffixList := sortedKeys(domSuffix)
	exactList := sortedKeys(domExact)
	v4List := sortedKeys(ip4)
	v6List := sortedKeys(ip6)
	andList := sortedKeys(andRules)

	var b strings.Builder
	fmt.Fprintf(&b, "# NAME: %s\n", name)
	fmt.Fprintf(&b, "# AUTHOR: atrust-proxy\n")
	fmt.Fprintf(&b, "# REPO: local (generated from aTrust clientResource)\n")
	fmt.Fprintf(&b, "# UPDATED: %s\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Fprintf(&b, "# DOMAIN: %d\n", len(exactList))
	fmt.Fprintf(&b, "# DOMAIN-SUFFIX: %d\n", len(suffixList))
	fmt.Fprintf(&b, "# IP-CIDR: %d\n", len(v4List))
	fmt.Fprintf(&b, "# IP-CIDR6: %d\n", len(v6List))
	fmt.Fprintf(&b, "# AND: %d\n", len(andList))
	fmt.Fprintf(&b, "# TOTAL: %d\n", len(exactList)+len(suffixList)+len(v4List)+len(v6List)+len(andList))
	b.WriteString("payload:\n")
	for _, d := range exactList {
		fmt.Fprintf(&b, "  - DOMAIN,%s\n", d)
	}
	for _, d := range suffixList {
		fmt.Fprintf(&b, "  - DOMAIN-SUFFIX,%s\n", d)
	}
	for _, ip := range v4List {
		fmt.Fprintf(&b, "  - IP-CIDR,%s/32,no-resolve\n", ip)
	}
	for _, ip := range v6List {
		fmt.Fprintf(&b, "  - IP-CIDR6,%s/128,no-resolve\n", ip)
	}
	for _, r := range andList {
		fmt.Fprintf(&b, "  - %s\n", r)
	}
	return []byte(b.String())
}

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// startRuleServer 起一个只读 HTTP 服务：GET / 或 /<name>.yaml 返回规则集。
func startRuleServer(cfg Config) *http.Server {
	if cfg.RuleListen == "" {
		return nil
	}
	name := cfg.RuleName
	if name == "" {
		name = "aTrust"
	}
	path := "/" + name + ".yaml"

	mux := http.NewServeMux()
	serve := func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		resMu.Lock()
		cached := ruleCache.body
		fresh := time.Since(ruleCache.at) < ruleCacheTTL
		resMu.Unlock()
		if !fresh || cached == nil {
			cached = renderRules(name)
			resMu.Lock()
			ruleCache.body = cached
			ruleCache.at = time.Now()
			resMu.Unlock()
		}
		w.Header().Set("Content-Type", "text/yaml; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Content-Length", strconv.Itoa(len(cached)))
		if r.Method == http.MethodHead {
			return
		}
		_, _ = w.Write(cached)
	}
	mux.HandleFunc(path, serve)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, path, http.StatusFound)
	})

	srv := &http.Server{Addr: cfg.RuleListen, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		log.Printf("RULES listening on http://%s%s", cfg.RuleListen, path)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[rules] server: %v", err)
		}
	}()
	return srv
}
