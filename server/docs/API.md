# xTunnel Go 中转接口 v1

本文供 Android mobile/tv 的 agent 模式和客户端 server 模式对接。客户端 server 模式在甲方网络连接目标；Go
中转服务器只协调会话、核验规则并转发双方数据。本文所称“server 端”均指客户端 server 模式。

实现采用单进程、单实例内存状态，不需要账号或数据库。Go 进程重启后，原轨道、配对码、管理凭据、agent
凭据和数据票据全部失效。部署时提供受客户端信任且主机名匹配的 TLS 证书，最低 TLS 1.2；不能关闭证书或主机名校验。启动示例：

~~~sh
go run . -listen :8443 -tls-cert /path/relay.crt -tls-key /path/relay.key
~~~

## 1. 地址、JSON 与认证

假设用户填写的中转地址为 https://relay.example:8443。管理接口使用 HTTPS，WebSocket 使用同一地址对应的 wss://relay.example:
8443。所有接口拒绝非空 URL 查询串；凭据和票据只能通过头部传递。

JSON 请求必须使用 Content-Type: application/json，可以附带 charset 参数。请求体上限 128 KiB，未知字段、尾随第二个 JSON
值、非法类型或编码均拒绝。二进制字段 first_packet、query、answer 在 JSON 中使用标准 Base64 字符串。数字版本使用 JSON 整数，HTTP
头中的版本使用十进制字符串。

| 头部                   | 使用范围与值                                                                 |
|------------------------|------------------------------------------------------------------------------|
| Authorization          | Bearer 加空格加凭据。server 使用 management_token；agent 使用 agent_token    |
| X-XTunnel-Track        | 当前 track_id；除轨道快照 GET 外的认证请求                                   |
| X-XTunnel-Session      | 当前 service_session；除轨道快照 GET 外的认证请求                            |
| X-XTunnel-Version      | 当前 config_version 的十进制字符串；除轨道快照 GET 外的认证请求              |
| X-XTunnel-Agent        | agent_id；agent 的 HTTPS/控制请求，以及双方的数据通道                        |
| X-XTunnel-Role         | server 或 agent；控制、数据 WSS 必填。HTTPS 管理接口按凭据类型核验角色和归属 |
| X-XTunnel-Ticket       | 本端的单次数据票据；仅数据 WSS                                               |
| X-XTunnel-Forward      | 本次 forward_id；仅数据 WSS                                                  |
| Sec-WebSocket-Protocol | xtunnel.v1；控制、数据 WSS 都必填                                            |

server 的控制连接不需要 X-XTunnel-Agent；server 的数据连接必须携带本次 CONNECT/DNS_OPEN 对应的 agent_id。对 agent 颁发的票据不能被
server 使用，反之亦然。票据绑定角色、轨道、服务会话、配置版本、agent 和转发，默认 30 秒内建立通道；每端只能消费一次。握手失败也不能重复使用已消费票据。

GET /v1/tracks/{track_id} 仅核验路径中的轨道归属与管理凭据，不要求绑定头，允许用旧会话/版本读取最新快照。更新或重启响应丢失时，先查询当前状态，再采用返回的会话/版本；其他管理操作和所有
WSS 仍严格核验当前绑定。

GET /healthz 不需要认证，成功响应 200：

~~~json
{
  "status": "ok"
}
~~~

错误 HTTPS 响应使用以下 JSON。创建/配对/管理失败通过 HTTP 状态表示；已经创建的转发失败通常在 ForwardView
和控制消息中表示，查询接口仍可能返回 200。

~~~json
{
  "error_code": "SESSION_INVALID"
}
~~~

## 2. 规则与公共模型

RuleConfig：

~~~json
{
  "ipv4_cidrs": [
    "10.20.0.0/16"
  ],
  "domains": [
    "internal.example"
  ],
  "http_url_regex": [
    "^http://api\\.internal\\.example/api/"
  ]
}
~~~

三个字段均为字符串数组。客户端应明确发送空数组；没有规则时默认允许隧道。创建、更新和重启请求必须明确携带非 null 的 rules
对象，rules:{} 表示无规则，缺失 rules 不会被解释成清空配置。CIDR 只允许 IPv4；域名按首尾空白、小写、尾部点和 IDNA ASCII
形式规范化，匹配本域及标签边界下的所有子域，不接受端口、路径或通配符；正则采用 Go regexp/RE2
的查找匹配语义，整串匹配需自行添加 ^ 和 $。三类规则合计最多 256 条，单条正则最多 4 KiB。任一规则无效都拒绝整次保存，不跳过错误项。响应
rules 保留提交值，不保证改写成规范化字符串。

明文 HTTP 使用完整 URL，保留路径/查询串的原始编码与顺序，默认 80
端口省略、非默认端口保留。例如 http://api.internal.example:8080/api/status?q=1。普通 TCP、UDP、TLS/HTTPS 只使用实际 IPv4 CIDR
和可识别域名，跳过接口正则；有可用规则时任一命中才允许，没有可用规则时允许。Go 中转自行核验实际首包/HTTP 头和甲方解析候选，不信任
agent 声明“已经匹配”。

Target：

~~~json
{
  "host": "api.internal.example",
  "port": 80
}
~~~

业务 host 为 IPv4 字符串或规范化域名；port 为 1～65535。域名目标由 server 端使用甲方当前网络解析。HTTP Host 或 TLS SNI
识别出域名后，实际通道目标必须对应该域名，不能继续使用无关 IP。

TrackView：

~~~json
{
  "track_id": "<track-id>",
  "management_token": "<仅创建时返回的管理凭据>",
  "service_session": "<service-session>",
  "config_version": 1,
  "pairing_code": "0042",
  "rules": {
    "ipv4_cidrs": [],
    "domains": [],
    "http_url_regex": []
  },
  "online": false
}
~~~

| 字段             | 含义                                                                            |
|------------------|---------------------------------------------------------------------------------|
| track_id         | 轨道身份。server 本机保存；agent 配对后保存，重连时防止号码被回收后误配另一轨道 |
| management_token | 创建时自动返回的至少 256 位安全随机凭据；后续 TrackView 不包含此字段            |
| service_session  | 本次 server 服务会话；服务重启会改变                                            |
| config_version   | 当前配置版本；创建/重启为 1，规则更新加 1                                       |
| pairing_code     | 四位数字字符串，允许前导零；轨道已停止时为空字符串                              |
| rules            | 当前已提交规则                                                                  |
| online           | 当前服务会话有效且 server 控制连接在线；创建成功仍为 false                      |

PairView：

~~~json
{
  "track_id": "<track-id>",
  "service_session": "<service-session>",
  "config_version": 1,
  "agent_id": "<agent-id>",
  "agent_token": "<agent-token>",
  "rules": {
    "ipv4_cidrs": [],
    "domains": [],
    "http_url_regex": []
  }
}
~~~

agent_token 是本次 agent 会话的至少 256 位安全随机凭据，只在当前运行会话保留。配对成功不代表控制在线或 VPN 已建立。

## 3. 轨道管理与配对

| 方法和路径                           | 认证                                   | 请求                  | 成功响应                           |
|--------------------------------------|----------------------------------------|-----------------------|------------------------------------|
| POST /v1/tracks                      | 无                                     | {"rules": RuleConfig} | 201 TrackView，含 management_token |
| GET /v1/tracks/{track_id}            | 所属轨道的 server 管理凭据；无需绑定头 | 无                    | 200 TrackView                      |
| PUT /v1/tracks/{track_id}/rules      | server 管理凭据及当前绑定头            | {"rules": RuleConfig} | 200 新 TrackView                   |
| POST /v1/tracks/{track_id}/restart   | server 管理凭据及当前绑定头            | {"rules": RuleConfig} | 200 新 TrackView，online=false     |
| DELETE /v1/tracks/{track_id}/session | server 管理凭据及当前绑定头            | 无                    | 200 已停止 TrackView               |
| POST /v1/pair                        | 无                                     | 见下文                | 201 PairView                       |

首次 server 服务启动：

1. POST /v1/tracks，保存轨道身份和管理凭据。此时配对码已分配，但轨道离线，不能配对。
2. 用返回的会话/版本及管理凭据连接 GET /v1/control，角色为 server。
3. 收到 HELLO 后展示当前配对码，轨道才允许 agent 配对。
4. agent POST /v1/pair，再用 PairView 连接 agent 控制 WSS，收到 HELLO 后才可建立 VPN。

配对请求：

~~~json
{
  "pairing_code": "0042",
  "expected_track_id": "<此前保存的轨道身份>"
}
~~~

首次配对可省略 expected_track_id；已经保存轨道身份的重连必须发送此字段，服务器会核验一致性。同一有效码支持多个
agent，不会因一次成功配对而被消费。无效、失效、离线或轨道不匹配统一返回 404 PAIR_UNAVAILABLE。

同一来源 IP 每分钟累计 10 次失败尝试后返回 429 PAIR_RATE_LIMITED，并包含 Retry-After: 60；客户端至少等待 60
秒。服务器使用连接来源地址，不把客户端传入的转发来源头当作限流身份。

规则更新与服务重启的语义不同：

| 操作     | 成功                                                                                                   | 失败                                                                                                   |
|----------|--------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------|
| 更新规则 | 同一服务会话，版本加 1；分配新码并保留本会话全部旧码；旧 agent/转发撤销；server 控制收到 TRACK_UPDATED | 配置无效、码池耗尽等均保留原配置、版本、配对码和连接                                                   |
| 服务重启 | 撤销旧会话、全部旧码、agent 和转发；新会话、版本 1、新码；server 重新建立控制连接                      | 输入校验或新会话凭据生成在撤销前失败时不改原会话；完成撤销后若不能分配新码，保持轨道停止，不恢复旧会话 |
| 停止服务 | 立即撤销会话、配对码、agent 和转发；online=false                                                       | 认证/绑定错误不改变状态                                                                                |

重启新码不会与该轨道刚撤销会话的任一旧有效码相同，包括停止后再启动、码池耗尽后的重试。管理凭据保留，用于撤销旧会话和创建新服务会话；修改状态的
HTTP 绑定头必须使用当前服务会话/版本，快照 GET 用于恢复这些字段。配对码全局唯一，码池为 0000～9999，耗尽返回 503
PAIRING_CODE_EXHAUSTED。

创建示例，RELAY 是用户确认的 HTTPS 地址：

~~~sh
curl -sS "$RELAY/v1/tracks" \
  -H 'Content-Type: application/json' \
  --data '{"rules":{"ipv4_cidrs":["10.20.0.0/16"],"domains":["internal.example"],"http_url_regex":[]}}'
~~~

二维码使用以下 JSON，仅包含协议版本、中转地址和配对码，不包含管理/agent 凭据或票据。扫码地址与已填写地址不同，必须展示并由用户确认本次配对目标；二维码不是管理接口请求。

~~~json
{
  "protocol_version": 1,
  "relay_url": "https://relay.example:8443",
  "pairing_code": "0042"
}
~~~

## 4. 控制 WSS

GET /v1/control 使用认证头和 xtunnel.v1 子协议升级。一个服务会话同时只有一个 server 控制连接，每个 agent 同时只有一个控制连接；重复连接返回
409 CONTROL_ALREADY_CONNECTED，不替换原连接。

控制消息为 UTF-8 JSON 文本消息，最长 64 KiB，每条消息从首字节开始须在 30 秒内读完，分片间的心跳不能延长此期限。字段只使用本版本定义的字段；未知类型、非法
JSON、角色错误或跨轨道操作会关闭控制连接。属于本轨道某条转发的非法目标结果仅使该转发以 PROTOCOL_ERROR
结束。控制通道只传状态/协调信息，不传业务载荷。

| 消息             | 方向          | 使用字段与行为                                                                                                                    |
|------------------|---------------|-----------------------------------------------------------------------------------------------------------------------------------|
| HELLO            | 中转 → 双方   | track_id、service_session、config_version、rules；server 另有 pairing_code，agent 另有 agent_id                                   |
| PING / PONG      | 双向          | {"type":"PING"} / {"type":"PONG"}；收到 PING 回复 PONG                                                                            |
| TRACK_UPDATED    | 中转 → server | track_id、service_session、config_version、rules、pairing_code；原控制保持在线，立即采用新版本绑定头                              |
| RESOLVE          | 中转 → server | forward_id、request_id、service_session、config_version、target；只解析，不能连接目标或发送业务                                   |
| RESOLVED         | server → 中转 | forward_id、service_session、config_version、candidates；失败改用 error_code=RESOLUTION_FAILED 或 TIMEOUT                         |
| CONFIRM_REQUIRED | 中转 → agent  | forward_id、request_id、service_session、config_version、target、actual_ip、transport；复核本地规则后调用 confirm                 |
| CONNECT          | 中转 → server | forward_id、request_id、service_session、config_version、agent_id、transport、target、actual_ip、ticket；UDP 另有 source_endpoint |
| DNS_OPEN         | 中转 → server | forward_id、request_id、service_session、config_version、agent_id、transport=dns、ticket                                          |
| TARGET_READY     | server → 中转 | forward_id、service_session、config_version、actual_ip；表示目标 socket 就绪，不表示可以发送业务                                  |
| TARGET_FAILED    | server → 中转 | forward_id、service_session、config_version、error_code；允许 CONNECT_FAILED、TIMEOUT、RESOLUTION_FAILED                          |
| READY            | 中转 → 双方   | forward_id、request_id、service_session、config_version、transport、target，业务转发另有 actual_ip                                |
| FORWARD_RESULT   | 中转 → agent  | forward_id、request_id、service_session、config_version、transport、target、error_code，可含 actual_ip；没有 status 字段          |
| CLOSE_FORWARD    | 中转 → server | forward_id、service_session、config_version、error_code；关闭对应目标和数据通道                                                   |
| CANCEL           | agent → 中转  | forward_id、service_session、config_version；取消自己的转发                                                                       |
| STOP             | 中转 → 对端   | error_code 表示停止原因，随后关闭控制连接                                                                                         |

服务端每 20 秒发送 PING，连续 60 秒没有对端消息按离线处理；原生 WebSocket Pong 也可刷新读取期限，客户端仍应处理协议 JSON
PING/PONG。明确断线立即处理。

控制消息必须关联当前 service_session、config_version、forward_id，并核验迟到消息对应的操作仍有效；不能用旧结果恢复已经取消、重启或更新的转发。server
收到 CONNECT 时只能连接 actual_ip:target.port，不得重新解析后切换到其他地址；目标连接默认超时 10 秒，中转也从确认开始计时等待
TARGET_READY。

RESOLVED 示例：

~~~json
{
  "type": "RESOLVED",
  "forward_id": "<forward-id>",
  "service_session": "<service-session>",
  "config_version": 1,
  "candidates": [
    "10.20.0.8",
    "10.20.0.9"
  ]
}
~~~

## 5. TCP/UDP 预检与数据就绪

ForwardView：

~~~json
{
  "forward_id": "<forward-id>",
  "request_id": "request-001",
  "status": "CONNECTING",
  "actual_ip": "10.20.0.8",
  "target": {
    "host": "api.internal.example",
    "port": 80
  },
  "transport": "tcp",
  "agent_ticket": "<本次 agent 票据>"
}
~~~

| 字段         | 含义                                                             |
|--------------|------------------------------------------------------------------|
| forward_id   | 中转分配的转发标识，用于查询、取消、控制消息和数据通道绑定       |
| request_id   | agent 提交的请求标识，用于匹配异步结果                           |
| status       | RESOLVING、CONFIRM_REQUIRED、CONNECTING、READY、FAILED 或 CLOSED |
| actual_ip    | 中转选中的实际 IPv4；选定前和 DNS 辅助通道中不出现               |
| target       | 此通道授权的规范化主机及固定端口；DNS 辅助通道的端口为 0         |
| transport    | tcp、udp 或 dns；dns 只通过 /v1/dns 创建                         |
| agent_ticket | 票据签发后出现，终态不再返回；已消费后不可再次使用               |
| error_code   | 失败或关闭时出现；正常关闭为 CLOSED                              |

查询 HTTP 200 或创建 HTTP 202 均不代表 READY。

| 方法和路径                             | 请求/结果                                                                               |
|----------------------------------------|-----------------------------------------------------------------------------------------|
| POST /v1/forwards                      | agent 认证；提交下面的预检对象，返回 202 ForwardView                                    |
| GET /v1/forwards/{forward_id}          | agent 认证；返回 200 当前 ForwardView                                                   |
| POST /v1/forwards/{forward_id}/confirm | agent 认证；{"actual_ip":"10.20.0.8"}，成功 200 CONNECTING ForwardView，含 agent_ticket |
| DELETE /v1/forwards/{forward_id}       | agent 认证；取消该转发，返回 200 终态 ForwardView                                       |

TCP 请求：

~~~json
{
  "request_id": "request-001",
  "transport": "tcp",
  "target": {
    "host": "api.internal.example",
    "port": 80
  },
  "first_packet": "R0VUIC9hcGkvc3RhdHVzP3E9MSBIVFRQLzEuMQ0KSG9zdDogYXBpLmludGVybmFsLmV4YW1wbGUNCg0K"
}
~~~

此 Base64 表示 GET /api/status?q=1 HTTP/1.1 以及 Host: api.internal.example 的完整请求头。first_packet
是之后实际数据流的精确起始字节；预检不会替客户端把这些字节发送到业务目标。HTTP/H2 预检只提交完整首个请求头所需字节，不包含请求体或后续请求。TLS
应提供足够识别完整 ClientHello 的有限首包。中转会再次核对实际数据的起始字节和后续实际协议，不能通过空首包或谎报 TCP 绕过
HTTP/HTTP2 规则。CONNECT 的处理见第 6 节，不能在此提交原始代理握手。

UDP 请求：

~~~json
{
  "request_id": "udp-001",
  "transport": "udp",
  "target": {
    "host": "dns-independent-service.internal.example",
    "port": 9000
  },
  "source_endpoint": "10.0.0.2:45678"
}
~~~

UDP 禁止 first_packet，source_endpoint 必须为非零端口的 IPv4:port。DNS 辅助查询使用单独 /v1/dns，不通过此接口指定专用 DNS
服务器地址/端口。

一次业务连接的顺序：

~~~mermaid
sequenceDiagram
    participant A as agent
    participant R as Go中转
    participant S as server端
    participant T as 甲方目标
    A ->> R: POST /v1/forwards（有限首包）
    R ->> S: RESOLVE（域名目标）
    S -->> R: RESOLVED（甲方IPv4候选）
    R -->> A: CONFIRM_REQUIRED（选定actual_ip）
    A ->> A: 按实际IPv4复核本地规则
    A ->> R: POST confirm（actual_ip）
    R -->> A: ForwardView（agent_ticket）
    R -->> S: CONNECT（server ticket、actual_ip）
    A ->> R: GET /v1/data（agent票据）
    S ->> T: 仅建立到已选IPv4的目标socket
    S ->> R: GET /v1/data（server票据）
    S ->> R: TARGET_READY（actual_ip）
    R -->> A: READY
    R -->> S: READY
    A ->> R: 原始业务字节（含精确首包）
    R ->> S: 核验通过的业务字节
    S ->> T: 业务字节
~~~

纯 IPv4 目标不需要 RESOLVE，直接核验该地址。域名解析最多返回 32 个 IPv4 候选，中转选择通过轨道规则的地址；全部未命中时终态为
RULE_REJECTED，未向甲方业务目标发送业务数据。agent 实际地址复核未通过时，取消尚未发送的操作并按其本地规则处理；不能改变
actual_ip 后继续确认。

POST confirm 只接受仍为 CONFIRM_REQUIRED 且 actual_ip 完全一致的转发；重复确认或状态改变返回 409
FORWARD_STATE_INVALID。双方数据 WSS 建立和 TARGET_READY 全部完成，中转才发送 READY；双方必须等待 READY，不能在目标连接完成或
WebSocket 握手成功后自行发送业务。

request_id 为 1～64 个可打印 ASCII 非空白字符，由 agent 生成。相同 agent 的活动 request_id 重复提交返回 409
DUPLICATE_REQUEST，不自动复用结果。重复取消保持已经终止的结果；转发不存在或不属于该 agent 返回 404 FORWARD_NOT_FOUND。终态保留约
30 秒供查询，随后删除。客户端需要保留自己的请求关联记录，不能把查询不到解释为规则拒绝。

预检 curl 示例：

~~~sh
curl -sS "$RELAY/v1/forwards" \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $AGENT_TOKEN" \
  -H "X-XTunnel-Track: $TRACK_ID" \
  -H "X-XTunnel-Session: $SERVICE_SESSION" \
  -H "X-XTunnel-Version: $CONFIG_VERSION" \
  -H "X-XTunnel-Agent: $AGENT_ID" \
  --data '{"request_id":"request-001","transport":"tcp","target":{"host":"api.internal.example","port":80},"first_packet":"R0VUIC9hcGkvc3RhdHVzP3E9MSBIVFRQLzEuMQ0KSG9zdDogYXBpLmludGVybmFsLmV4YW1wbGUNCg0K"}'
~~~

## 6. 数据 WSS：TCP、HTTP、UDP

双方分别 GET /v1/data，携带本端凭据、所有绑定头、本端票据及 xtunnel.v1。数据 WSS 与控制 WSS 分开，每个 TCP 上游连接使用独立通道。每个二进制
WebSocket 消息最长 64 KiB；TCP 消息边界没有业务语义，中转按连续字节流处理并施加背压。

每条 WSS 消息从首字节开始须在 30 秒内完成，分片和穿插的控制帧不会重置期限。中转每 20 秒发送原生 WebSocket
Ping，客户端必须持续读取并回应 Pong；连续 60 秒未读到数据或控制帧时关闭该数据通道。此期限同样约束尚未形成明文消息的 TLS
传输停滞。完成首包识别后，正常响应心跳的空闲普通 TCP/TLS 连接可以保留；首包识别及 HTTP 后续请求头仍有 10 秒期限。数据通道故障只影响对应业务。

TCP 某一方向写完时，可发送唯一允许的数据文本消息：

~~~json
{
  "type": "FIN"
}
~~~

FIN 文本消息最长 128 字节，拒绝未知字段及尾随 JSON。FIN 表示该方向半关闭；对端将其映射为对应目标 socket
的写方向关闭，另一方向仍可继续返回数据。发送 FIN 后不能再发送该方向的业务字节；不要使用关闭整个 WebSocket 来替代需要接收剩余响应的
TCP 半关闭。UDP、DNS 不使用 FIN。

明文 HTTP/1.1 同一连接上的每个请求都会重新核验完整 URL/Host、长度及消息边界。Content-Length 与 chunked 正确流式转发；冲突长度、非法
Host、不完整头等是 PROTOCOL_ERROR。升级请求先核验，实际成功升级后才透传。OPTIONS * 没有资源 URL，跳过正则，已配置规则且
IP/域名都未命中时拒绝。明文 HTTP/2 按每个 HEADERS 请求的 :scheme、:authority、:path 判定，不能当作未知 TCP；加密 HTTP/2 按
TLS 处理。

HTTP/1.1 和 HTTP/2 CONNECT 由 agent 的本地代理处理：以 CONNECT authority 创建普通 TCP 预检，不提交代理请求头、不虚构 HTTPS
URL；收到 READY 后，agent 才向应用返回本地代理成功响应，并将后续 TLS/原始字节送入通道。甲方目标是 authority 对应的实际
socket，不是 HTTP 代理。中转收到字面 CONNECT 请求头或 H2 CONNECT HEADERS 会返回 PROTOCOL_ERROR。后续业务首包识别出与已授权目标不同的
Host/SNI 时，agent 必须在发送业务前取消空通道，按识别出的域名重新预检，不能改变原通道的目标。

当前识别有一项兼容限制：缺少行终止符、仍可能是 HTTP 方法前缀的 ASCII 首包（例如发送 PING 后立即等待响应），会继续等待识别并在
10 秒后超时报错。不会按等待时间降级透传，以免绕过 URL 规则；二进制 TCP、可识别的行协议及服务端先发数据不受这一歧义影响。

agent 应将同一应用 HTTP 下游长连接中的每个请求分别预检，并按请求选择本地或独立隧道上游，同时保持响应顺序。需要将下一请求转为本地路由时，优先在该请求创建上游之前获得
RULE_REJECTED。把多个未经单独预检的请求放进同一已 READY 上游，之后被拒绝会关闭该上游，客户端不能重发此前已处理的请求。

UDP 数据消息采用下列 v1 二进制格式，整数为网络字节序：

| 字节偏移 | 长度     | 内容                                 |
|----------|----------|--------------------------------------|
| 0        | 1        | 固定版本 0x01                        |
| 1        | 4        | 本次会话原始 source_endpoint 的 IPv4 |
| 5        | 2        | 本次会话原始源端口                   |
| 7        | 4        | 中转选定 actual_ip 的 IPv4           |
| 11       | 2        | target.port                          |
| 13       | 0～65507 | 一个完整 UDP 数据报载荷              |

两个方向都必须携带完全相同的固定 13 字节会话头。server 返回响应时不交换头部源/目的字段；它们表示已批准的逻辑会话，不是本次响应的网络包方向。agent
根据该绑定恢复交给应用的响应端点。每个 WebSocket 二进制消息保留一个数据报边界；改变任何目标或源端点都必须建立新预检/会话，不能在现有通道替换地址。UDP
会话在双向均无有效数据报的连续 60 秒后清理，任一方向的有效数据报均刷新活动时间，心跳不计入业务活动；已通过隧道发送的数据报失败时不在本地重发。

TLS 业务始终端到端透传，不解密、不替换目标证书、不检查加密 URL；首版不提供甲方自签名 HTTPS 证书适配。

## 7. DNS 辅助通道

POST /v1/dns 使用 agent 认证和绑定头：

~~~json
{
  "request_id": "dns-001",
  "query": "<单个DNS查询报文的标准Base64>"
}
~~~

query 是原始 DNS 报文，不含 TCP DNS 的两字节长度前缀，不含目标 DNS 地址/端口。此能力只允许解析操作，不受“专用 DNS 地址必须在业务
CIDR 内”的限制；server 必须使用甲方当前网络的 DNS 能力，不能使用 Go 中转网络或写死公共 DNS，不能把该通道当作任意端口代理。

AAAA 查询直接返回 200，无须数据票据：

~~~json
{
  "status": "ANSWER",
  "answer": "<匹配原查询ID/问题的NOERROR空答案Base64>"
}
~~~

其他允许的查询返回 202 ForwardView，transport=dns，target.host 为原查询名、target.port 为 0，status=CONNECTING，含
agent_ticket。流程如下：

1. 中转向 server 控制发送 DNS_OPEN 及 server 票据，agent 从 HTTPS 响应取得 agent 票据。
2. 双方建立各自的数据 WSS；DNS 无 actual_ip 确认，也不发送 TARGET_READY。
3. 双通道就绪后，中转通过控制通道向双方发送 READY。
4. 中转在 server 数据通道发送一次原始 DNS 查询二进制消息。
5. server 使用甲方 DNS 得到一条响应，在自己的数据通道返回一次原始 DNS 响应二进制消息。
6. 中转核验响应后，在 agent 数据通道发送一条响应并结束转发。agent 数据通道为接收专用，不再发送查询或其他业务消息。

DNS 从创建到完成共用 5 秒预算，包含通道建立、查询发送和响应读取，不在通道就绪后重新计时。DNS 响应必须匹配原始 ID、单一问题名、类型和
IN 类，允许规范的 ASCII 大小写差异；CNAME、IPv4 和 TTL 原样保留，任何分区出现 AAAA 地址记录均拒绝。NXDOMAIN/SERVFAIL 等合法
DNS 错误响应保持为 DNS 响应，不能因此尝试本地 DNS 重发。解析失败或超时同样不触发跨网络重试。

解析报文上限 4096 字节、最多 128 个资源记录，只允许标准 QUERY opcode、一个 IN 问题。查询类型为
A、AAAA、CNAME、NS、SOA、PTR、MX、TXT、SRV、SVCB、HTTPS；不允许 ANY、AXFR、IXFR、更新或未知查询类型。查询不能携带答案/授权记录，仅可附带一个根名称
EDNS0 OPT：UDP 大小 512～4096、仅 DO 标志、最多 16 个选项且每项不超过 512 字节；查询选项只接受合法 COOKIE 或全零
PADDING。拒绝尾随字节、非法压缩指针、错误 RDATA 长度以及 SRV/SVCB/HTTPS 目标中的禁止压缩。

agent 的 DNS 选择及缓存职责：

- 解析前能够确定至少一端规则不可能允许域名时，使用 agent 当前网络 DNS；存在待解析 CIDR/HTTP URL 条件，或两端无规则/域名已获两端允许时，先使用甲方
  DNS。
- 记录原查询域名、CNAME 链、IPv4、TTL、解析网络、轨道会话及配置版本；业务域名规则仍匹配原域名，不能让 CNAME 改变允许范围。
- 域名识别优先使用合法 HTTP Host/TLS SNI，再使用未过期且无歧义的 DNS 映射。同一 IP 对应多个域名且无 Host/SNI 时按域名未知处理。
- 遵守 TTL；网络、服务会话或配置版本改变时清理对应缓存；本地和甲方解析结果不能混用。
- 业务预检明确拒绝后，已识别域名的本地直连必须通过 agent 当前网络重新解析；纯 IP 目标保持原 IP。
- 处理应用经代理的明文 UDP/TCP DNS，AAAA 返回正常空答案；不解密 DoH/DoT，不从加密 DNS 猜测域名。

## 8. 错误、回退与停止边界

| error_code                                                                                | 来源/含义                                               | 客户端动作                                                    |
|-------------------------------------------------------------------------------------------|---------------------------------------------------------|---------------------------------------------------------------|
| RULE_REJECTED                                                                             | 预检规则未允许，当前业务请求尚未到甲方目标              | 仅当前尚未转发的请求可本地路由；域名重新使用本地 DNS          |
| RULE_REJECTED_AFTER_READY                                                                 | 已 READY 数据通道的实际请求/后续请求规则未允许          | 关闭对应上游并报错，不自动本地重发                            |
| RESOLUTION_FAILED / CONNECT_FAILED                                                        | 甲方解析或目标连接失败                                  | 报错，不本地重发                                              |
| TIMEOUT / CHANNEL_FAILED                                                                  | 等待超时或单条数据通道失败                              | 关闭本次业务，不本地重发；控制仍在线时其他请求可新建通道      |
| PROTOCOL_ERROR                                                                            | JSON/首包/实际头/帧/绑定报文不合法                      | 报错，不降级成普通 TCP，不本地重发                            |
| CANCELLED / CLOSED                                                                        | 主动取消/正常业务结束                                   | 清理该业务连接                                                |
| UNAUTHORIZED                                                                              | 凭据不存在或角色/归属不符；通常 HTTP 401                | 不重放业务；核对会话，必要时重新配对/注册                     |
| SESSION_INVALID                                                                           | 服务会话/配置版本已失效；通常 HTTP 409                  | 停止当前 agent 会话与 VPN，保留本地配置等待用户重新连接       |
| CONTROL_OFFLINE / CONTROL_DISCONNECTED                                                    | 控制不可用或已断开                                      | 停止 agent VPN，不自动恢复或重发失败业务                      |
| CONFIG_UPDATED / TRACK_OFFLINE / TRACK_STOPPED / SESSION_RESTARTED / SERVER_STOPPED       | STOP/转发终态中的停止原因                               | 清理 agent 会话、TUN、tun2socks、控制/数据连接和相关 DNS 缓存 |
| TICKET_INVALID / TICKET_BINDING_INVALID                                                   | 票据过期/已消费，或角色/会话/归属错误；HTTP 401/403     | 放弃该通道，不复用票据或切本地重发                            |
| PAIR_UNAVAILABLE / PAIR_RATE_LIMITED                                                      | 不能配对 / 达到失败次数限制                             | 显示原因或等待至少 60 秒                                      |
| INVALID_RULES / PAIRING_CODE_EXHAUSTED / RESOURCE_LIMIT                                   | 输入规则无效 / 四位码池耗尽 / 资源上限                  | 按更新/重启不同失败语义处理，不假定操作部分成功               |
| CONTROL_ALREADY_CONNECTED / DUPLICATE_REQUEST / FORWARD_STATE_INVALID / FORWARD_NOT_FOUND | 重复控制、重复活动请求、状态/归属不符、转发记录已不存在 | 核验当前请求和状态，不把结果未知解释为规则拒绝                |
| TLS_REQUIRED / INTERNAL_ERROR                                                             | 非 TLS 请求 / 内部操作失败                              | 报错，不发送未保护 socket 或重放业务                          |

只有预检明确的 RULE_REJECTED 能授权当前请求的自动本地回退；目标失败、断线、超时、无响应或结果未知都不能作为回退信号。RULE_REJECTED_AFTER_READY
不授权本地回退。控制事件以 forward_id/request_id 关联整个转发，不提供 HTTP 请求序号或 H2 stream_id；agent 应在每个新 HTTP
请求选择上游前单独预检，而不是依赖已 READY 通道的错误进行分流。

单条目标/数据通道失败不停止整个 VPN；server 或 agent 控制断开、轨道离线、配置撤销才使当前 agent 会话失效。agent 此时主动关闭
VPN，后续新请求恢复系统本地网络；已经失败的请求不自动重发。

## 9. 客户端服务生命周期

server 端 Activity 重建、返回桌面、息屏和控制重连不算服务重启。每次真正服务启动，已保存轨道身份/管理凭据时先读取当前轨道快照，再携带其会话/版本调用
restart，撤销旧会话后用新 TrackView 连接控制；没有现存可认证轨道（包括 Go 中转已重启）则重新创建并展示新码。

server 网络切换或控制断开时，同一仍运行的服务会话按 1、2、4、8 秒递增、上限 30 秒重连；停止服务后取消重试。重连保留当前配对码和配置，旧
agent 与业务连接不会恢复。规则更新的 TRACK_UPDATED 使 server 更新其版本/码，但不替换服务会话。

agent 因断线、配置更新、对端离线停止 VPN 后，保存用户填写的中转地址、配对码/轨道身份、本地规则和应用选择，并显示停止原因；等待用户点击重新连接。重新连接通过有效配对码重新获取
PairView、建立新的 agent 控制会话后再建立 VPN，不能复用失效 agent_token 或自动恢复 VPN。

agent 的平台责任：

- 只有配对有效、控制在线并得到当前配置后才建立 IPv4 TUN；server 模式只使用普通 socket，不建立 VPN。两种运行模式使用前台服务，页面退出不停止服务。
- 管理/WSS、本地直连和本地 DNS socket 在连接前通过 VpnService.protect 排除自身 VPN，并绑定当前底层网络；保护/绑定失败直接报错。
- 进入 VPN 的 IPv6 流量阻断，不启用 allowFamily (AF_INET6) 或 allowBypass。未选中应用继续走系统网络。
- 全部应用不设置允许列表；仅指定应用至少保留一个仍安装的应用，空选择禁止启动，卸载后有效选择为空则停止 VPN。
- 本地规则保存后原子替换快照并关闭既有代理连接；应用范围改变则清理旧 TUN 并重建，重建失败保持停止。
- 用户停止、系统撤销 VPN 权限、服务销毁或隧道不可用时执行可重复清理，不自动抢回权限或重发业务。
- 首版不支持开机自动连接/始终开启 VPN；系统“阻止未经过 VPN 的连接”须关闭，否则断线后的系统本地恢复会被系统阻止。

轨道身份和管理凭据置于应用私有存储，排除备份、迁移、导出；agent 凭据和票据仅保留在运行会话。日志不记录配对码、认证头、票据、完整
URL 查询串、DNS 明细或业务载荷。

## 10. 当前资源与时间上限

| 项目                           | 当前实现                                                                   |
|--------------------------------|----------------------------------------------------------------------------|
| 四位码池                       | 全局 10000 个，所属会话撤销后回收                                          |
| 轨道总数                       | 4096；当前进程内保留轨道身份                                               |
| agent 数量                     | 每轨道 128，全局 8192；配对后 60 秒未建立控制连接会被清理                  |
| 转发记录                       | 每 agent 128，全局 8192；包括保留约 30 秒的终态记录                        |
| 规则                           | 三类合计 256 条，单条正则 4 KiB                                            |
| JSON 请求                      | 128 KiB                                                                    |
| HTTP 管理请求头                | 32 KiB；读头 10 秒，读/写 15 秒                                            |
| 控制 WSS 消息                  | 64 KiB；发送队列 32 条，超限会关闭该控制连接                               |
| WSS 消息读取                   | 首字节起 30 秒，分片及穿插控制帧不延长；传输无读取进展上限 60 秒           |
| 心跳                           | 控制 JSON PING、数据原生 Ping 均为 20 秒；控制连续 60 秒没有对端消息按离线 |
| 数据 WSS 二进制消息 / FIN 文本 | 64 KiB / 128 字节                                                          |
| TCP 有限首包 / TLS ClientHello | 64 KiB；实际首包/后续可识别头读取有 10 秒期限                              |
| HTTP/HTTP2 头                  | 32 KiB；H2 同时活动请求流最多 128，HPACK 动态表上限 4096 字节              |
| IPv4 候选                      | 1～32 个                                                                   |
| 域名预检解析                   | 5 秒；最终实际 IPv4 确认等待 30 秒                                         |
| 数据票据 / 双通道建立          | 30 秒，单次使用；server 目标就绪从确认开始限时 10 秒                       |
| DNS                            | 4096 字节、128 条记录；创建到完成共用 5 秒预算                             |
| UDP 载荷                       | 最长 65507 字节，加固定 13 字节头                                          |
| UDP 空闲                       | 双向均无有效数据报 60 秒                                                   |
| 终态转发保留                   | 约 30 秒，维护线程每秒清理                                                 |

这些接口检查不能代替客户端的有限缓冲、超时、取消及平台网络保护。协议约定以项目 [AGENTS.md](../../AGENTS.md) 为最终依据；真实
Android VPN、甲方专用 DNS 与设备上的完整隧道联调需由客户端交付阶段验证。
