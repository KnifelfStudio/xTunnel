# xTunnel Go 中转服务器

Go 中转端提供轨道、配对、规则核验、控制连接及 TCP/UDP/DNS 数据转发。客户端 `server` 模式使用甲方网络解析与连接目标，中转进程不解析或直接连接业务目标。Android
客户端尚未实现，当前联调使用测试中的双端模拟客户端。

## 运行

使用仓库 `go.mod` 声明的 Go 1.27 工具链：

```sh
go mod download
go run . -listen :8443 \
  -tls-cert /path/to/fullchain.pem \
  -tls-key /path/to/privkey.pem
```

证书和私钥为必填参数；服务只开放 HTTPS/WSS，最低 TLS 1.2。部署证书应受客户端信任且覆盖用户填写的中转主机名；不能跳过证书或主机名校验。首次监听失败会退出；SIGINT/SIGTERM
撤销状态、关闭通道并退出。证书、私钥和任何会话秘密不提交到仓库。

部署为单实例，客户端直接连接该实例的 TLS 监听端口。状态仅驻留内存，重启清空轨道凭据、在线会话和配对码；server
模式需要重新创建轨道、展示新码，agent 重新配对。未提供数据库、多实例同步、反向代理来源 IP 信任或 TLS 卸载支持。HTTP
无状态反向代理不应负载均衡到多个实例。

## 对接与结构

- [接口文档](docs/API.md)：HTTPS JSON、控制消息、数据票据、TCP/UDP/DNS 格式、错误及双方客户端责任。
- [架构设计](docs/superpowers/specs/2026-10-06-relay-design.md)：状态归属、生命周期、业务发送屏障与规则边界。
- [实现计划](docs/superpowers/plans/2026-10-06-relay.md)：实现与验证记录。

`main.go` 只负责监听配置和退出。`internal/relay` 按业务职责分文件：`server/api` 管理轨道和会话；`control/forward`
协调预检与短期票据；`rules/inspect` 核验规则及实际首包；`data/stream/h2/dns` 做有界流式转发与协议检查；`transport` 约束 WSS
消息读取期限。没有数据库层或无调用方的扩展接口。

标准库承担 HTTP/TLS、随机数、正则、并发和计时。Gorilla WebSocket v1.5.3 提供标准库缺少的 RFC 6455 实现；x/net v0.59.0 提供
IDNA、DNS、HTTP/2/HPACK；x/text v0.42.0 是 IDNA 的间接依赖。三者采用 BSD 类许可证，版本和模块校验固定在 go.mod/go.sum。Android
没有新增依赖。

## 验证

```sh
go test ./...
go test -race ./...
go vet ./...
go build .
```

测试包括真实 TLS/WSS 双端模拟：会话更新和重启、旧码获取新配置、码池耗尽、前导零和配对限流、跨角色/失效版本和单次票据、TCP
字节流与半关闭、固定 UDP 目标、甲方 DNS/CNAME/TTL、拒绝不发业务、首包篡改及单通道失败后继续建立新通道。规则/解析测试覆盖可用规则、IDNA、HTTP
URL/消息边界、TLS SNI 分片、明文 HTTP/2、CONNECT 边界与协议升级，另有 WSS 分片/停滞读取期限检查。

CONNECT 代理握手由 agent 在本地处理，隧道只传其后续 TCP/TLS 字节；Go 中转不充当目标 HTTP 代理。当前协议识别会对缺少行终止符、仍可能是
HTTP 方法前缀的 ASCII 首包等待最多 10 秒后报错，例如发送 PING 后立即等待响应的自定义协议；详细行为见接口文档。

这些检查不能替代 Android VPN 生命周期、API 26/目标 Android 版本、真实甲方专用 DNS 和目标设备的端到端验收。服务器源代码可供客户端对接，尚不宣称整个
xTunnel 应用已完成或可发布。
