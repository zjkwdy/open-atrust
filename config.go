package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// deviceState 是"设备身份 + 网关下发的 cookie"，与用户的主动配置分开存放。
// 由程序自动生成/回写，人手不要改；删掉它等于换一台新设备（需要重新过验证码）。
type deviceState struct {
	DeviceID    string `json:"deviceId"`
	TID         string `json:"tid"`
	TIDSig      string `json:"tidSig"`
	StraceID    string `json:"straceid"`
	StraceIDSig string `json:"straceidSig"`
	LimitTag    string `json:"limitTag"`
	LimitTagSig string `json:"limitTagSig"`
}

// statePath 与配置同目录同名，后缀换成 .state.json（config.json → config.state.json）。
func statePath(cfgPath string) string {
	return strings.TrimSuffix(cfgPath, filepath.Ext(cfgPath)) + ".state.json"
}

func loadState(path string) (deviceState, error) {
	var st deviceState
	raw, err := os.ReadFile(path)
	if err != nil {
		return st, err
	}
	err = json.Unmarshal(raw, &st)
	return st, err
}

// saveState 原子写状态文件（0600），内容只有设备身份与 cookie，不含账号密码。
func saveState(cfgPath string, cfg Config) error {
	st := deviceState{
		DeviceID:    cfg.DeviceID,
		TID:         cfg.TID,
		TIDSig:      cfg.TIDSig,
		StraceID:    cfg.StraceID,
		StraceIDSig: cfg.StraceIDSig,
		LimitTag:    cfg.LimitTag,
		LimitTagSig: cfg.LimitTagSig,
	}
	if old, err := loadState(statePath(cfgPath)); err == nil && old == st {
		return nil
	}
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	p := statePath(cfgPath)
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, append(b, 10), 0600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// loadConfig 读用户配置 config*.json，并叠加运行期状态文件。
func loadConfig(path string) (Config, error) {
	cfg := defaultConfig()
	raw, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return cfg, fmt.Errorf("parse %s: %w", path, err)
	}
	if cfg.Listen == "" {
		cfg.Listen = "127.0.0.1:1080"
	}
	if cfg.Lang == "" {
		cfg.Lang = "zh-CN"
	}
	if cfg.LoginListen == "" {
		cfg.LoginListen = "127.0.0.1:18085"
	}
	if cfg.PoolSize == 0 {
		cfg.PoolSize = 2
	}
	cfg.path = path

	st, err := loadState(statePath(path))
	if err != nil && !os.IsNotExist(err) {
		return cfg, fmt.Errorf("parse state: %w", err)
	}
	cfg.DeviceID, cfg.TID, cfg.TIDSig = st.DeviceID, st.TID, st.TIDSig
	cfg.StraceID, cfg.StraceIDSig = st.StraceID, st.StraceIDSig
	cfg.LimitTag, cfg.LimitTagSig = st.LimitTag, st.LimitTagSig

	if cfg.DeviceID == "" {
		cfg.DeviceID = randHex(16)
		if err := saveState(path, cfg); err != nil {
			return cfg, err
		}
	}
	if err := cfg.validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// Base 返回门户基址（登录用），由 SNI 推导。
func (c Config) Base() string { return "https://" + c.SNI }

func (c Config) validate() error {
	var missing []string
	if c.User == "" {
		missing = append(missing, "user")
	}
	if c.Password == "" {
		missing = append(missing, "password")
	}
	if c.SNI == "" {
		missing = append(missing, "sni")
	}
	if c.Gateway == "" {
		missing = append(missing, "gateway")
	}
	if len(missing) > 0 {
		return fmt.Errorf("配置缺少字段: %s", strings.Join(missing, ", "))
	}
	return nil
}
