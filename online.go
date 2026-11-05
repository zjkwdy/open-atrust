package main

// 无客户端模式（breaking change）：不再依赖本机 54630 agent。
// 登录后由我们自己完成 antiMITMRequest → reportEnv(pre-login) → authCheck → onlineInfo。

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
)

// mustHexKey 解析 64 hex 的 signKey。
func mustHexKey(k string) []byte {
	b, err := hex.DecodeString(k)
	if err != nil || len(b) == 0 {
		return []byte(k)
	}
	return b
}

// signRequest 给请求加 X-Request-Sig。
// 逆向结论（04-tunnel-spa.md §7B.14）：待签数据 = 请求行里的 path?query，
// 算法 HMAC-SHA256(signKey, msg)，输出大写 hex。
func (s *loginSession) signRequest(req *http.Request) {
	if s.signKey == "" {
		return
	}
	// 待签数据形态按 sigMode 切换，默认 1；probeSignature 会在线找出服务端接受的那一种。
	var msg string
	switch sigMode {
	case 2:
		msg = req.URL.RequestURI()
		if req.GetBody != nil {
			if b, err := req.GetBody(); err == nil {
				if d, err := io.ReadAll(b); err == nil {
					msg += string(d)
				}
			}
		}
	case 3:
		if req.GetBody != nil {
			if b, err := req.GetBody(); err == nil {
				if d, err := io.ReadAll(b); err == nil {
					msg = string(d)
				}
			}
		}
	case 4:
		msg = req.URL.Path
	case 5:
		msg = req.Method + " " + req.URL.RequestURI()
	default:
		msg = req.URL.RequestURI()
	}
	mac := hmac.New(sha256.New, mustHexKey(s.signKey))
	mac.Write([]byte(msg))
	req.Header.Set("X-Request-Sig", strings.ToUpper(hex.EncodeToString(mac.Sum(nil))))
}

// sigMode: 1=http path?query（默认）, 2=+body, 3=body, 4=path only, 5=method+uri
var sigMode = 2

// deviceEnv 生成 reportEnv 的 env 字段（对齐官方客户端的 key 集合）。
// 缺的字段放进 failure，服务端接受部分字段（官方自己也会报 endpoint.edr_agentid 缺失）。
func (s *loginSession) deviceEnv() (map[string]any, []string) {
	host, _ := os.Hostname()
	env := map[string]any{
		"endpoint.os.hostname":                   host,
		"endpoint.device_id":                     s.deviceId,
		"endpoint.atrust_client.version":         "2.5.16.20",
		"endpoint.os.family":                     osFamily(),
		"endpoint.os.version":                    osVersion(),
		"endpoint.os.arch":                       runtime.GOARCH,
		"endpoint.device.type":                   host,
		"endpoint.device_model":                  host,
		"endpoint.device_brand":                  "",
		"endpoint.mac_addresses":                 localMACs(),
		"endpoint.client_ips":                    localIPs(),
		"endpoint.domain_name":                   "",
		"endpoint.security.is_firewall_enabled":  false,
		"endpoint.security.is_antivirus_enabled": false,
		"endpoint.security.is_domain":            false,
		"endpoint.sandboxType":                   "",
		"endpoint.os.sub_os":                     osFamily(),
	}
	failure := []string{"endpoint.edr_agentid", "endpoint.uem_client.version"}
	return env, failure
}

func osFamily() string {
	switch runtime.GOOS {
	case "windows":
		return "windows"
	case "linux":
		return "linux"
	case "darwin":
		return "macos"
	}
	return runtime.GOOS
}

func osVersion() string {
	if b, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		return strings.TrimSpace(string(b))
	}
	return runtime.GOOS
}

func localMACs() []string {
	var out []string
	ifs, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, it := range ifs {
		if it.Flags&net.FlagLoopback != 0 || len(it.HardwareAddr) == 0 {
			continue
		}
		out = append(out, strings.ToUpper(it.HardwareAddr.String()))
	}
	return out
}

func localIPs() []string {
	var out []string
	ifs, _ := net.Interfaces()
	for _, it := range ifs {
		addrs, _ := it.Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && !ipn.IP.IsLoopback() {
				out = append(out, ipn.IP.String())
			}
		}
	}
	return out
}

func (s *loginSession) fetchResources() (*ResourceIndex, error) {
	q := "/controller/v1/user/clientResource?platform=Windows&clientType=SDPClient"
	payload := map[string]any{"resourceType": map[string]any{"appList": map[string]any{}}}
	raw, st, err := s.do("POST", q, payload, nil)
	if err != nil {
		return nil, err
	}
	if st != 200 {
		return nil, fmt.Errorf("clientResource http=%d", st)
	}
	ri, err := parseResources(raw)
	if err != nil {
		return nil, err
	}
	log.Printf("[res] apps=%d hostPort=%d host=%d ip=%d domain=%d", ri.Apps, len(ri.byHostPort), len(ri.byHost), len(ri.byIP), len(ri.byDomPort))
	return ri, nil
}

func (s *loginSession) antiMITMRequest(ticket string) {
	body := map[string]any{"nonce": strings.ToUpper(randHex(32)), "ticket": ticket}
	raw, st, err := s.do("POST",
		"/controller/v1/public/antiMITMRequest?lang="+s.cfg.Lang+"&platform=Windows&clientType=SDPClient",
		body, nil)
	if err != nil {
		log.Printf("[online] antiMITMRequest err=%v", err)
		return
	}
	log.Printf("[online] antiMITMRequest http=%d code=%d", st, codeOf(raw))
}

// reportEnvPreLogin: 登录前环境上报。这一步是 online 的必要条件
// （psw 响应里 env.need=true / timing=pre-login）。
func (s *loginSession) reportEnvPreLogin(ticket string) error {
	env, failure := s.deviceEnv()
	body := map[string]any{
		"deviceId": s.deviceId,
		"accessIp": "",
		"env":      env,
		"failure":  failure,
		"ticket":   ticket,
		"timing":   "pre-login",
	}
	raw, st, err := s.do("POST",
		"/controller/v1/public/reportEnv?platform=Windows&clientType=SDPClient", body, nil)
	if err != nil {
		return err
	}
	log.Printf("[online] reportEnv http=%d code=%d", st, codeOf(raw))
	if st != 200 {
		return fmt.Errorf("reportEnv http %d", st)
	}
	return nil
}

// promoteOnline: psw 成功后立刻走 antiMITM → reportEnv → authCheck → onlineInfo。
// 全程不访问 127.0.0.1:54630，干净 Linux 上同样成立。
func (s *loginSession) promoteOnline(ticket string) error {
	s.antiMITMRequest(ticket)
	if err := s.reportEnvPreLogin(ticket); err != nil {
		log.Printf("[online] reportEnv failed: %v", err)
	}
	qs := "?clientType=SDPClient&platform=Windows&lang=" + s.cfg.Lang
	raw, st, err := s.do("GET", "/passport/v1/auth/authCheck"+qs, nil, nil)
	if err != nil {
		return err
	}
	log.Printf("[online] authCheck http=%d code=%d isOnline=%t", st, codeOf(raw), isOnlineOf(raw))
	if st != 200 {
		return fmt.Errorf("authCheck http %d", st)
	}
	var ac struct {
		Code int `json:"code"`
		Data struct {
			OnlineInfo struct {
				IsOnline bool `json:"isOnline"`
			} `json:"onlineInfo"`
		} `json:"data"`
	}
	if json.Unmarshal(raw, &ac) == nil && ac.Code != 0 {
		return fmt.Errorf("authCheck code=%d", ac.Code)
	}
	raw, st, err = s.do("GET", "/passport/v1/user/onlineInfo"+qs, nil, nil)
	if err != nil {
		return err
	}
	log.Printf("[online] onlineInfo http=%d code=%d isOnline=%t", st, codeOf(raw), isOnlineOf(raw))
	return nil
}

// codeOf / isOnlineOf：日志只打关键字段，绝不整段 body（避免刷屏）。
func codeOf(raw []byte) int {
	var v struct {
		Code int `json:"code"`
	}
	if json.Unmarshal(raw, &v) != nil {
		return -1
	}
	return v.Code
}

func isOnlineOf(raw []byte) bool {
	var v struct {
		Data struct {
			IsOnline   bool `json:"isOnline"`
			OnlineInfo struct {
				IsOnline bool `json:"isOnline"`
			} `json:"onlineInfo"`
		} `json:"data"`
	}
	if json.Unmarshal(raw, &v) != nil {
		return false
	}
	return v.Data.IsOnline || v.Data.OnlineInfo.IsOnline
}
