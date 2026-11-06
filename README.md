# aTrust 命令行客户端

aTrust部分功能独立开源实现 ，0外部依赖，属于是只要go语言支持你得cpu架构就能跑，占用很低windows上大概占10MB内存，cpu忽略不计

具体功能就是把校园网VPN的 tcpTunnel 协议包装成一个**标准 SOCKS5 代理**，还实现了rule-provider，便于接入现有clash实现校园网分流。

只在辽科大测试了，功能上属于是给辽科大设计的

---

## 1. 能做什么

- **账号密码登录**（LDAP 认证源）
- **本地 SOCKS5**：`127.0.0.1:10080`，支持任意 TCP 目标（HTTP/HTTPS），比如各种校内oj、知网的机构登录
- **自动续期**：每 35 秒重登一次，长期在线
- **Clash 规则集**：内置 rule-provider，配合 Clash Verge 分流

不支持UDP、l3Tunnel/VIP 网段模式，因为ustl只使用tcpTunnel。

---

## 2. 快速开始

```bash
# 前置条件：下载release或者拉源码自行编译
cp config.example.json config.json
#    填 user / password，详见 #3.配置
vi config.json
# 2) run
./atrust-proxy config.json
```

首次登录可能会要求打开浏览器做验证码，看到如下证明跑起来了

```
[online] authCheck http=200 code=0 isOnline=true
[res] apps=240 hostPort=215 host=57 ip=24 domain=193
SOCKS5 listening on 127.0.0.1:10080 -> gateway 221.203.22.52:441
```

测试（访问内网图书馆查书页面）：

```bash
curl -x socks5h://127.0.0.1:10080 -vvL http://opac.ustl.edu.cn:8080/
```

---

## 3. 配置

`config.json`：

```json
{
  "listen": "127.0.0.1:10080",
  "gateway": "221.203.22.52:441",
  "sni": "vpn.ustl.edu.cn",
  "user": "<学号/工号>",
  "password": "<你的密码>",
  "appId": "auto",
  "lang": "zh-CN",
  "loginListen": "127.0.0.1:18085",
  "ruleListen": "127.0.0.1:18090",
  "ruleName": "aTrust",
  "poolSize": 2,
  "verbose": true
}
```

| 字段 | 必填 | 说明 |
|---|---|---|
| `gateway` | + | ustl保持默认就行 |
| `sni` | + | ustl保持默认就行 |
| `user` / `password` | + | 你得ldap账号密码 |
| `listen` | | SOCKS5 监听，默认 `127.0.0.1:1080` |
| `appId` | | 不知道啥意思的默认`auto`即可 |
| `loginListen` | | 验证码网页地址，默认 `127.0.0.1:18085` |
| `ruleListen` | | clash rule-provider HTTP 地址；**留空 = 不启动** |
| `ruleName` | | 规则名 = 文件名，默认 `aTrust` |
| `poolSize` | | 预握手连接池大小，默认 2；0 = 关闭 |
| `directFallback` | | 对非本校但是被路由到这个代理的连接：`false` 直接拒绝，`true` 直连 |
| `verbose` | | 打开详细日志 |
| `procName` / `procPath` | | 伪装进程名/路径（影响 `procHash`），一般不用改 |
| `destIP` | | 留空与官方客户端一致 |

### 状态文件 `config.state.json`

设备指纹等设备身份和网关 cookie（`deviceId`、`tid`、`straceid` 等）删掉它 = 换一台新设备：会重新生成 `deviceId`，并需要再过一次验证码。

---

## 4. 对外接口

| 接口 | 地址 | 说明 |
|---|---|---|
| **SOCKS5 代理** | `127.0.0.1:10080`（`listen`） | 无认证，支持 `socks5h`（域名交给代理解析）。任意 TCP 目标 |
| **规则集** | `http://127.0.0.1:18090/aTrust.yaml` | Clash rule-provider，用于clash引擎匹配内网应用<br />`behavior: classical`，<br />支持：`DOMAIN` / `DOMAIN-SUFFIX` / `IP-CIDR` / `AND(...,DST-PORT)` |
| **验证码网页** | `http://127.0.0.1:18085/` | 仅首次登录/换设备时用 |

---

## 5. 配合 Clash Verge

以下是一段clash verge示例全局脚本，用于注入这个代理到你现有的订阅并与之配合

把下面这段放到 **Clash Verge → 订阅 → 全局扩展脚本**，它会：

1. 注入一个指向本程序的 SOCKS5 节点 `USTL`；
2. 建一个 `USTL-Group` 选择组（`USTL` / `DIRECT`）；
3. 注册 rule-provider `atrust`（每小时拉一次）；延迟测试链接是内网才能访问的图书馆查书目录；
4. 把 `RULE-SET,atrust,USTL-Group` 插到规则最顶端。

```javascript
function main(config, profileName) {
  // 1. 安全检查并初始化数组
  if (!config.proxies) config.proxies = [];
  if (!config['proxy-groups']) config['proxy-groups'] = [];
  if (!config.rules) config.rules = [];
  if (!config['rule-providers']) config['rule-providers'] = {};

  // 2. 注入代理节点（去重后推入节点列表）
  const newProxy = {
    name: "USTL",
    type: "socks5",
    server: "127.0.0.1",
    port: 10080,
    udp: false
  };
  config.proxies = config.proxies.filter(p => p.name !== "USTL");
  config.proxies.unshift(newProxy);

  // 3. 创建策略组（使用 unshift 插在策略组最前面）
  const newGroup = {
    name: "USTL-Group",
    type: "select",
    url: "http://opac.ustl.edu.cn:8080/",
    proxies: ["USTL", "DIRECT"]
  };
  config['proxy-groups'] = config['proxy-groups'].filter(g => g.name !== "USTL-Group");
  config['proxy-groups'].unshift(newGroup);

  // 4. 注入规则提供者
  config['rule-providers']['atrust'] = {
    type: "http",
    behavior: "classical",
    format: "yaml",
    interval: 3600,
    path: "./ruleset/atrust.yaml",
    url: "http://127.0.0.1:18090/aTrust.yaml"
  };

  // 5. 将 aTrust 规则插入到规则列表最顶端（优先匹配）
  const targetRule = "RULE-SET,atrust,USTL-Group";
  if (!config.rules.includes(targetRule)) {
    config.rules.unshift(targetRule);
  }

  return config;
}
```

注意：

- 先启动 `atrust-proxy`，再让 Clash 拉规则集；端口/规则名要和配置里的 `listen`（10080）与 `ruleListen`/`ruleName`（18090 / aTrust）一致。
- 规则集启动时若没起来，Clash 会先 404/超时，等代理跑起来后下一轮（3600s）才会成功；想立刻生效就手动更新一次订阅。

---

## 7. 说明

- 瞎jb做的，不保证可用性，GPL 3.0开源，产生一切后果和作者无关。
