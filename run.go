package main

import (
	"log"
	"sync/atomic"
	"time"
)

// 运行期状态全部在内存：sid / signKey 用原子变量给 Client 读，tid 直接回写配置文件。
var (
	curSID atomic.Value // string
	curKey atomic.Value // string
)

func setSID(s string) { curSID.Store(s) }
func sidNow() string {
	if v, ok := curSID.Load().(string); ok {
		return v
	}
	return ""
}
func setSignKey(k string) { curKey.Store(k) }
func sigKeyNow() string {
	if v, ok := curKey.Load().(string); ok {
		return v
	}
	return ""
}

// run：单进程完成 login -> online -> SOCKS5，并在会话失效时自动重登续期。
func run(cfg Config) error {
	login := func() error {
		lc := loginCfg{
			Base: cfg.Base(), User: cfg.User, Pass: cfg.Password,
			Listen: cfg.LoginListen, Lang: cfg.Lang, Device: cfg.DeviceID,
			TID: cfg.TID, TIDSig: cfg.TIDSig, StraceID: cfg.StraceID, StraceIDSig: cfg.StraceIDSig,
			LimitTag: cfg.LimitTag, LimitTagSig: cfg.LimitTagSig,
		}
		s, err := newLoginSession(lc)
		if err != nil {
			return err
		}
		st := &captchaState{state: "idle", message: "waiting for gateway"}
		srv := s.startCaptchaServer(st)
		defer srv.Close()

		ls, err := s.doLogin(st)
		if err != nil {
			return err
		}
		setSID(ls.SID)
		setSignKey(ls.SignKey)
		if ls.TID != "" && ls.TID != cfg.TID {
			cfg.TID, cfg.TIDSig = ls.TID, ls.TIDSig
			if err := saveState(cfg.path, cfg); err != nil {
				log.Printf("[state] %v", err)
			}
		}
		return nil
	}

	if err := login(); err != nil {
		return err
	}

	// 后台续期：会话 TTL 很短，登录一次就够跑，但要长期在线必须隔一会儿重登。
	go func() {
		for {
			time.Sleep(35 * time.Second)
			if err := login(); err != nil {
				log.Printf("[renew] failed: %v", err)
				continue
			}
			log.Printf("[renew] session renewed")
		}
	}()

	cfg.Res = globalRes
	if srv := startRuleServer(cfg); srv != nil {
		defer srv.Close()
	}
	return serve(cfg)
}
