package main

// login.go — 自建会话：authConfig -> psw(RSA) -> 图形验证码(网页由本机 HTTP 服务承载) -> 登录
//
// 设计要点：
//   * 验证码不靠本地窗口，而是由本进程起一个极小 HTTP 服务，任何带浏览器的机器
//     （包括从另一台电脑访问无头 Linux）都能完成点选；命令行只打印 URL。
//   * 所有请求与验证码图片共用同一个 cookie jar，否则图片与会话不匹配。
//   * antiReplayRand 每次响应都会变，所以每轮都重新拉 authConfig、重新加密。

import (
	randpkg "crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// 与官方客户端逐字一致的 UA：服务端会按 UA 分流 clientType/版本。
const trayUA = "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) aTrustTray/2.5.16.20 Chrome/87.0.4280.141 Electron/11.5.0 Safari/537.36 aTrustTray-Windows-Plat SPCClientType"

type loginCfg struct {
	Base        string
	User        string
	Pass        string
	Listen      string
	Lang        string
	Device      string
	TID         string // 上次网关下发的设备 cookie，用于免验证码
	TIDSig      string
	StraceID    string
	StraceIDSig string
	LimitTag    string
	LimitTagSig string
}

type authConfigResp struct {
	Code int    `json:"code"`
	Msg  string `json:"message"`
	Data struct {
		PubKey           string `json:"pubKey"`
		PubKeyExp        string `json:"pubKeyExp"`
		AntiReplayRand   string `json:"antiReplayRand"`
		ClientVerifyCode string `json:"clientVerifyCode"`
		GUID             string `json:"guid"`
		UnitID           string `json:"unitid"`
		DefaultDomain    string `json:"defaultDomain"`
		Security         struct {
			CSRFToken string `json:"csrfToken"`
		} `json:"security"`
		AntiMITMAttackData json.RawMessage `json:"antiMITMAttackData"`
		AuthServerInfoList []struct {
			AuthName    string `json:"authName"`
			AuthID      string `json:"authId"`
			LoginDomain string `json:"loginDomain"`
			SubType     string `json:"subType"`
			LoginType   string `json:"loginType"`
		} `json:"authServerInfoList"`
		GraphCheckCodeEnable int `json:"graphCheckCodeEnable"`
	} `json:"data"`
}

type pswResp struct {
	Code int    `json:"code"`
	Msg  string `json:"message"`
	Data struct {
		GraphCheckCodeEnable int    `json:"graphCheckCodeEnable"`
		NextService          string `json:"nextService"`
		CurrentService       string `json:"currentService"`
		SIDTicket            string `json:"sidTicket"`
		AntiReplayRand       string `json:"antiReplayRand"`
		RemainedSkipTimes    int    `json:"remainedSkipTimes"`
		DefaultRedirectURL   string `json:"defaultRedirectUrl"`
	} `json:"data"`
	Raw json.RawMessage `json:"-"`
}

type loginSession struct {
	authId string
	cfg    loginCfg
	hc     *http.Client
	token  string
	domain string
	sub    string
	graph  chan string // 浏览器提交的 graphCode JSON
	done   chan string // 成功后的 sidTicket
	// 本地 agent init 需要的两个凭据（都来自 authConfig）
	verifyCode string
	pubKey     string
	guid       string
	mitm       json.RawMessage // authConfig.antiMITMAttackData 原样转发给本地 agent
	signKey    string          // 本地推导的会话 signKey（见 sigkey.go）
	deviceId   string          // 设备 id（来自 -device / 环境）
}

func newLoginSession(cfg loginCfg) (*loginSession, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	tr := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives:   false,
		MaxIdleConnsPerHost: 4,
	}
	// 设备 cookie 由网关下发；存回配置后从这里灌进 jar，登录便不再要验证码。
	if u, err := url.Parse(cfg.Base); err == nil {
		if cfg.TID != "" {
			jar.SetCookies(u, []*http.Cookie{{Name: "tid", Value: cfg.TID, Path: "/"}})
		}
		if cfg.TIDSig != "" {
			jar.SetCookies(u, []*http.Cookie{{Name: "tid.sig", Value: cfg.TIDSig, Path: "/"}})
		}
		if cfg.StraceID != "" {
			jar.SetCookies(u, []*http.Cookie{{Name: "straceid", Value: cfg.StraceID, Path: "/"}})
		}
		if cfg.StraceIDSig != "" {
			jar.SetCookies(u, []*http.Cookie{{Name: "straceid.sig", Value: cfg.StraceIDSig, Path: "/"}})
		}
		if cfg.LimitTag != "" {
			jar.SetCookies(u, []*http.Cookie{{Name: "sdp_limit_auth_tag", Value: cfg.LimitTag, Path: "/"}})
		}
		if cfg.LimitTagSig != "" {
			jar.SetCookies(u, []*http.Cookie{{Name: "sdp_limit_auth_tag.sig", Value: cfg.LimitTagSig, Path: "/"}})
		}
	}
	return &loginSession{
		cfg:      cfg,
		deviceId: cfg.Device,
		hc:       &http.Client{Jar: jar, Transport: tr, Timeout: 30 * time.Second},
		graph:    make(chan string, 4),
		done:     make(chan string, 1),
	}, nil
}

func traceID() string {
	b := make([]byte, 4)
	randpkg.Read(b)
	return hex.EncodeToString(b)
}

func (s *loginSession) do(method, path string, body any, extra http.Header) ([]byte, int, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, 0, err
		}
		rd = strings.NewReader(string(b))
	}
	u := s.cfg.Base + path
	req, err := http.NewRequest(method, u, rd)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/json;charset=utf-8")
	if method == "POST" {
		req.Header.Set("clientType", "SDPClient")
		req.Header.Set("platform", "Windows")
		req.Header.Set("lang", s.cfg.Lang)
	}
	req.Header.Set("x-sdp-traceid", traceID())
	req.Header.Set("User-Agent", trayUA)
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Origin", s.cfg.Base)
	req.Header.Set("Referer", s.cfg.Base+"/portal/")
	if s.token != "" {
		req.Header.Set("x-csrf-token", s.token)
	}
	s.signRequest(req)
	for k, v := range extra {
		req.Header[k] = v
	}
	resp, err := s.hc.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	return data, resp.StatusCode, err
}

func (s *loginSession) fetchAuthConfig() (*authConfigResp, error) {
	raw, st, err := s.do("GET", "/passport/v1/public/authConfig?mod=1", nil, nil)
	if err != nil {
		return nil, err
	}
	if st != 200 {
		return nil, fmt.Errorf("authConfig http %d: %s", st, string(raw))
	}
	var ac authConfigResp
	if err := json.Unmarshal(raw, &ac); err != nil {
		return nil, fmt.Errorf("authConfig json: %v (%s)", err, string(raw))
	}
	s.token = ac.Data.Security.CSRFToken
	s.verifyCode = ac.Data.ClientVerifyCode
	s.pubKey = ac.Data.PubKey
	s.guid = ac.Data.GUID
	s.mitm = ac.Data.AntiMITMAttackData

	// 本地推导会话 signKey：devicePubKeyMod + challenge 都来自这份 authConfig。
	// 见 sigkey.go / _re_docs/04-tunnel-spa.md §7B.20。
	var mi struct {
		DevicePubKeyMod string `json:"devicePubKeyMod"`
		Challenge       string `json:"challenge"`
	}
	if len(s.mitm) > 0 && json.Unmarshal(s.mitm, &mi) == nil && mi.DevicePubKeyMod != "" && mi.Challenge != "" {
		s.signKey = calcSignKey(mi.DevicePubKeyMod, mi.Challenge)
		log.Printf("[signkey] derived=%s", s.signKey)
	} else {
		log.Printf("[signkey] skip: no devicePubKeyMod/challenge")
	}
	if ac.Data.AntiReplayRand == "" {
		return nil, fmt.Errorf("authConfig missing antiReplayRand")
	}
	return &ac, nil
}

// encryptPwd: RSA/PKCS#1 v1.5，明文 = password + "_" + antiReplayRand，输出 hex
func encryptPwd(pubHex, expDec, pwd, nonce string) (string, error) {
	nb, err := hex.DecodeString(strings.TrimSpace(pubHex))
	if err != nil {
		return "", fmt.Errorf("pubKey hex: %w", err)
	}
	e, err := strconv.Atoi(expDec)
	if err != nil {
		// 兼容 "65537" 或 "0x10001"
		v, e2 := new(big.Int).SetString(strings.TrimPrefix(expDec, "0x"), 16)
		if !e2 {
			return "", fmt.Errorf("pubKeyExp: %w", err)
		}
		e = int(v.Int64())
	}
	pub := &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: e}
	out, err := rsa.EncryptPKCS1v15(randpkg.Reader, pub, []byte(pwd+"_"+nonce))
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(out), nil
}

func (s *loginSession) pickLDAP(ac *authConfigResp) {
	s.domain, s.sub = "wisedu.com", "ldap"
	for _, a := range ac.Data.AuthServerInfoList {
		if strings.EqualFold(a.SubType, "ldap") {
			s.sub = a.SubType
			s.authId = a.AuthID
			if a.LoginDomain != "" {
				s.domain = a.LoginDomain
			}
			log.Printf("[login] auth provider: %s (authId=%s, domain=%s, subType=%s)", a.AuthName, a.AuthID, a.LoginDomain, a.SubType)
			return
		}
	}
	log.Printf("[login] no ldap provider; fallback domain=%s subType=%s", s.domain, s.sub)
}

func (s *loginSession) postPSW(ac *authConfigResp, graphCode string) (*pswResp, string, error) {
	pwdHex, err := encryptPwd(ac.Data.PubKey, ac.Data.PubKeyExp, s.cfg.Pass, ac.Data.AntiReplayRand)
	if err != nil {
		return nil, "", err
	}
	// 2026-11-04 实测（Frida 抓官方客户端 TLS 明文）：
	//   POST /passport/v1/auth/psw?clientType=SDPClient&platform=Windows&lang=zh-CN
	//   {"username":"<学号>@<loginDomain>","password":"<512 hex>","rememberPwd":"0"}
	// 用户名必须带 @loginDomain 后缀（ldap 源是 @wisedu.com），否则服务端按本地密码校验并回
	// 「用户名或密码错误」。body 里**不需要** loginDomain/subType/authId/antiReplayRand。
	username := s.cfg.User
	if s.domain != "" && !strings.Contains(username, "@") {
		username = username + "@" + s.domain
	}
	body := map[string]any{
		"username":    username,
		"password":    pwdHex,
		"rememberPwd": "0",
	}
	if graphCode != "" {
		body["graphCheckCode"] = graphCode
		body["graphCode"] = graphCode
	}
	q := url.Values{}
	q.Set("clientType", "SDPClient")
	q.Set("platform", "Windows")
	q.Set("lang", s.cfg.Lang)
	path := "/passport/v1/auth/psw?" + q.Encode()
	raw, st, err := s.do("POST", path, body, nil)
	if err != nil {
		return nil, "", err
	}
	var pr pswResp
	_ = json.Unmarshal(raw, &pr)
	if st != 200 && pr.Code == 0 {
		return nil, string(raw), fmt.Errorf("psw http %d", st)
	}
	return &pr, string(raw), nil
}

// ---------- 验证码网页 ----------

const captchaHTML = `<!doctype html><html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>aTrust 登录 · 图形验证码</title>
<style>
 body{font-family:system-ui,-apple-system,"Segoe UI",sans-serif;background:#f6f7f9;margin:0;padding:24px;color:#1f2329}
 .card{max-width:560px;margin:0 auto;background:#fff;border-radius:14px;padding:22px;box-shadow:0 6px 24px rgba(0,0,0,.08)}
 h1{font-size:18px;margin:0 0 6px}
 p.tip{color:#5c6470;font-size:13px;margin:6px 0 14px;line-height:1.6}
 #wrap{position:relative;display:inline-block;cursor:crosshair;user-select:none}
 img{display:block;border-radius:8px;width:272px;height:192px}
 .mark{position:absolute;width:26px;height:26px;margin:-13px 0 0 -13px;border:2px solid #2b6cff;
        border-radius:50%;color:#2b6cff;font:700 12px/22px system-ui;text-align:center;background:rgba(43,108,255,.14)}
 .row{display:flex;gap:10px;margin-top:14px;align-items:center;flex-wrap:wrap}
 button{background:#2b6cff;color:#fff;border:0;border-radius:8px;padding:9px 16px;font-size:14px;cursor:pointer}
 button.ghost{background:#eef1f5;color:#333}
 #st{font-size:13px;color:#5c6470}
 code{background:#f2f4f8;padding:2px 6px;border-radius:6px}
</style></head><body>
<div class="card">
 <h1>aTrust 图形验证码</h1>
 <p class="tip">按图片底部文字的**顺序**依次点击图中对应汉字，点满 3 个会自动提交。
 每次提交后图片会刷新；若提示过期，直接重新点击即可。</p>
 <div id="wrap"><img id="img" src="/img?t=0" alt="captcha"><span id="marks"></span></div>
 <div class="row">
   <button class="ghost" onclick="refresh()">换一张</button>
   <button class="ghost" onclick="reset()">重来</button>
   <span id="st">准备就绪</span>
 </div>
</div>
<script>
const img=document.getElementById('img'),wrap=document.getElementById('wrap'),marks=document.getElementById('marks'),st=document.getElementById('st');
let pts=[];
function reset(){pts=[];marks.innerHTML='';st.textContent='准备就绪';}
function refresh(){reset();img.src='/img?t='+Date.now();}
img.addEventListener('click',e=>{
  if(pts.length>=3)return;
  const r=img.getBoundingClientRect();
  pts.push([Math.round(e.clientX-r.left),Math.round(e.clientY-r.top)]);
  const m=document.createElement('span');m.className='mark';m.textContent=pts.length;
  m.style.left=(e.clientX-r.left)+'px';m.style.top=(e.clientY-r.top)+'px';marks.appendChild(m);
  st.textContent='已点 '+pts.length+'/3';
  if(pts.length===3)submit();
});
async function submit(){
  st.textContent='提交中…';
  const payload={coordinates:pts,width:272,height:192};
  try{
    const r=await fetch('/submit',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(payload)});
    const j=await r.json();
    st.textContent=j.message||'已提交，等待校验…';
    setTimeout(poll,800);
  }catch(err){st.textContent='提交失败: '+err;}
}
async function poll(){
  try{
    const r=await fetch('/result');const j=await r.json();
    st.textContent=j.message||'';
    if(j.state==='need_more'){refresh();}
    if(j.state==='ok'){st.textContent='login ok：'+j.message;}
    if(j.state==='fail'){refresh();}
  }catch(e){}
}
// 不在页面加载时就取图：图片必须在下一次 psw 失败之后生成，否则服务端会判「已超时」。
(async function boot(){
  for(;;){
    await new Promise(r=>setTimeout(r,600));
    try{
      const j=await (await fetch('/result')).json();
      if(j.state==='need_more' && !img.getAttribute('src')){ refresh(); st.textContent='请点选验证码'; }
      if(j.state==='ok'){ st.textContent='login ok：'+j.message; break; }
    }catch(e){}
  }
})();
</script></body></html>`

type captchaState struct {
	mu       sync.Mutex
	state    string // idle | pending | ok | fail
	message  string
	lastJSON string
}

func (s *loginSession) startCaptchaServer(st *captchaState) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "text/html; charset=utf-8")
		io.WriteString(w, captchaHTML)
	})
	mux.HandleFunc("/img", func(w http.ResponseWriter, r *http.Request) {
		raw, ctype, err := s.fetchCaptchaImage()
		if err != nil {
			http.Error(w, "captcha fetch failed: "+err.Error(), 502)
			return
		}
		if ctype == "" {
			ctype = "image/jpeg"
		}
		w.Header().Set("content-type", ctype)
		w.Header().Set("cache-control", "no-store")
		w.Write(raw)
	})
	mux.HandleFunc("/submit", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
		var v struct {
			Coordinates [][]int `json:"coordinates"`
			Width       int     `json:"width"`
			Height      int     `json:"height"`
		}
		if err := json.Unmarshal(body, &v); err != nil || len(v.Coordinates) == 0 {
			jsonReply(w, map[string]any{"ok": false, "message": "coordinates 不合法"})
			return
		}
		if v.Width == 0 {
			v.Width = 272
		}
		if v.Height == 0 {
			v.Height = 192
		}
		gc, _ := json.Marshal(map[string]any{"coordinates": v.Coordinates, "width": v.Width, "height": v.Height})
		st.mu.Lock()
		st.state = "pending"
		st.message = "click received, verifying"
		st.lastJSON = string(gc)
		st.mu.Unlock()
		select {
		case s.graph <- string(gc):
		default:
		}
		jsonReply(w, map[string]any{"ok": true, "message": "已提交，正在校验…"})
	})
	mux.HandleFunc("/result", func(w http.ResponseWriter, r *http.Request) {
		st.mu.Lock()
		defer st.mu.Unlock()
		jsonReply(w, map[string]any{"state": st.state, "message": st.message})
	})
	mux.HandleFunc("/peek", func(w http.ResponseWriter, r *http.Request) {
		st.mu.Lock()
		defer st.mu.Unlock()
		jsonReply(w, map[string]any{"message": st.message})
	})
	srv := &http.Server{Addr: s.cfg.Listen, Handler: mux}
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[captcha] server: %v", err)
		}
	}()
	return srv
}

func (s *loginSession) fetchCaptchaImage() ([]byte, string, error) {
	// 与官方 SDK getGraphCodeSrc 完全一致：clientType/platform/lang/rnd 都带上，
	// 否则服务端可能返回一张「未注册到当前登录事务」的图，答案永远对不上。
	q := url.Values{}
	q.Set("clientType", "SDPClient")
	q.Set("platform", "Windows")
	q.Set("lang", s.cfg.Lang)
	q.Set("rnd", strconv.FormatInt(time.Now().UnixMilli(), 10))
	raw, st, err := s.do("GET", "/passport/v1/public/checkCode?"+q.Encode(), nil, nil)
	if err != nil {
		return nil, "", err
	}
	if st != 200 {
		return nil, "", fmt.Errorf("http %d", st)
	}
	if len(raw) < 100 {
		return nil, "", fmt.Errorf("image too short (%d B): %s", len(raw), string(raw))
	}
	ctype := "image/jpeg"
	if len(raw) > 8 && string(raw[1:4]) == "PNG" {
		ctype = "image/png"
	}
	return raw, ctype, nil
}

func jsonReply(w http.ResponseWriter, v any) {
	w.Header().Set("content-type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(v)
}

// ---------- 主流程 ----------

type loginState struct {
	SID     string
	TID     string
	TIDSig  string
	SignKey string
}

// doLogin 走一遍完整登录：authConfig -> psw ->（必要时人工过验证码）-> online。
func (s *loginSession) doLogin(st *captchaState) (*loginState, error) {
	ac, err := s.fetchAuthConfig()
	if err != nil {
		return nil, err
	}
	// 必须先从 authServerInfoList 里选出 ldap 源，拿到 loginDomain（wisedu.com）；
	// 否则 psw 的 username 不带 @域名，服务端按本地密码校验，必然回「用户名或密码错误」。
	s.pickLDAP(ac)
	graph := ""
	for attempt := 1; attempt <= 4; attempt++ {
		pr, raw, err := s.postPSW(ac, graph)
		if err != nil {
			return nil, err
		}
		graph = ""
		// 服务端每次响应都会换 antiReplayRand；下一轮必须用它，否则密码会被判错。
		// （这是唯一被实测验证过的“密码正确”前置条件，别改回“重拉 authConfig”。）
		if pr.Data.AntiReplayRand != "" {
			ac.Data.AntiReplayRand = pr.Data.AntiReplayRand
		}
		if pr.Code == 0 {
			if st != nil {
				st.mu.Lock()
				st.state = "ok"
				st.message = "login ok"
				st.mu.Unlock()
			}
			return s.finish(raw)
		}
		log.Printf("[login] attempt=%d code=%d graphEnable=%d", attempt, pr.Code, pr.Data.GraphCheckCodeEnable)
		if strings.Contains(pr.Msg, "锁定") || strings.Contains(pr.Msg, "locked") {
			return nil, fmt.Errorf("account locked: %s", pr.Msg)
		}
		if pr.Code == 75500000 || pr.Code == 75500308 || pr.Data.GraphCheckCodeEnable == 1 {
			if st != nil {
				st.mu.Lock()
				st.state = "need_more"
				st.message = "click the captcha in the page"
				st.mu.Unlock()
			}
			log.Printf("[login] CAPTCHA required -> http://%s/ (click it yourself)", s.cfg.Listen)
			select {
			case gc := <-s.graph:
				graph = gc
				log.Printf("[login] captcha answer received, submitting")
			case <-time.After(300 * time.Second):
				return nil, fmt.Errorf("captcha timeout")
			}
			continue
		}
		return nil, fmt.Errorf("login failed code=%d msg=%s", pr.Code, pr.Msg)
	}
	return nil, fmt.Errorf("too many attempts")
}

// finish：login ok后取 sid/设备 cookie，把会话推到 online，并拉资源表。
func (s *loginSession) finish(raw string) (*loginState, error) {
	var v struct {
		Data map[string]json.RawMessage `json:"data"`
	}
	_ = json.Unmarshal([]byte(raw), &v)
	ticket := ""
	for _, k := range []string{"sidTicket", "ticket", "sessionId"} {
		if r, ok := v.Data[k]; ok {
			var sv string
			if json.Unmarshal(r, &sv) == nil && sv != "" {
				ticket = sv
			}
		}
	}
	if err := s.promoteOnline(ticket); err != nil {
		log.Printf("[online] failed: %v", err)
	}
	ls := &loginState{SignKey: s.signKey}
	if u, err := url.Parse(s.cfg.Base); err == nil {
		for _, c := range s.hc.Jar.Cookies(u) {
			switch c.Name {
			case "sid":
				ls.SID = c.Value
			case "tid":
				ls.TID = c.Value
			case "tid.sig":
				ls.TIDSig = c.Value
			}
		}
	}
	if ls.SID == "" {
		return nil, fmt.Errorf("login ok但没有拿到 sid cookie")
	}
	if ri, err := s.fetchResources(); err == nil {
		setGlobalRes(ri)
		log.Printf("[res] %d apps", ri.Apps)
	} else {
		log.Printf("[res] fetch failed: %v", err)
	}
	return ls, nil
}

// ---------- 小工具 ----------
