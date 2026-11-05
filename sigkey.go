package main

// signKey 的纯本地推导（逆向结论，见 _re_docs/04-tunnel-spa.md §7B.14–§7B.20）
//
//	signKey = UPPERHEX( SHA256(S) XOR SHA256( UPPERHEX(SHA256(S)) + challenge_b64 ) )
//	S       = devicePubKeyMod + "10001" + CONST
//
// 其中：
//   - devicePubKeyMod / challenge 均来自同一次 /passport/v1/public/authConfig 响应里的
//     antiMITMAttackData（challenge 就是服务端下发的 128B 随机量，即 aTrustCore 内部的 randomS）；
//   - CONST 是 aTrustCore 内的硬编码 64 字符常量（与 encryptEnv 用的 63 字符常量同源片段）；
//   - 该 key 同时用于 HTTP 头 X-Request-Sig / X-Response-Sig 与 tcpTunnel 的 AuthRequest.xRequestSig。

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

const sigConst = "3uW5IEy8KwDaOMK8uw1TmNr50U3aK1Qdu8b6vopXxGstzan3AJXxVNR6piuKi5Nq"

// calcSignKey 由 devicePubKeyMod（512 hex）与 challenge（base64，172 字符）推导会话 signKey。
func calcSignKey(devicePubKeyMod, challengeB64 string) string {
	s := devicePubKeyMod + "10001" + sigConst
	a := sha256.Sum256([]byte(s))
	aHex := strings.ToUpper(hex.EncodeToString(a[:]))

	b := sha256.Sum256([]byte(aHex + challengeB64))

	out := make([]byte, len(a))
	for i := range a {
		out[i] = a[i] ^ b[i]
	}
	return strings.ToUpper(hex.EncodeToString(out))
}
