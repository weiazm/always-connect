# 出口保护：产品接线计划（DESIGN §六十六）

给接手实现的人。先读 AGENTS.md、DESIGN §六十六（方案、实验记录、验证级别）、UI-DESIGN「出口保护」一节、实测清单 §K，再按本计划分批做。设计以 DESIGN 为准；本文件只排工作顺序、接口与验证，做完一步就在 DESIGN §66.14 与本文件里更新进度。

## 0. 起点

- 分支：`docs/egress-guard`（PR #7，未合入）。新工作区从 main 建的，先 `git fetch origin docs/egress-guard` 再把自己的分支对齐到它；推送只做快进推送到 `docs/egress-guard`，不改写历史。开工前与提交前都先合入最新 main（小节号取当时最大值加一）。
- 已完成（CI 四个 job 全绿或本机全部单测通过）：
  - `core/src/egress_gate`：逐包判定（25 个单测）。
  - `core/src/bin/alwaysconnect-gate.rs`：openconnect `--script-tun` 的闸门程序；第一个参数是 vpnc-script 路径；`AC_GATE_CONTROL`（控制 socket）、`AC_GATE_TUN=utun`；启动后发 `{"up":{"ifname":...}}`，运行中接收新配置行。
  - `core/scripts/gate-harness.{sh,py}`：rust-linux job 里真实 openconnect + ocserv 的整环 harness（12 项）。
  - `core/src/egress_control`：控制方（配置模型、检测方式、组判定、拦截记录、socket 协议；12 个单测）。HTTPS 由平台钩子 `ProbeHook` 执行。
  - `core/src/oc_engine.rs`：`Config.egress`、`egress_active()`（断线保护开着 + 有启用的组）、以 `-S` 启动、`start_egress`（闸门不在或不可信即以"组件缺失"终止）、换网/隧道连上时失效、`Engine::{set_egress_probe, update_egress, egress_status, egress_probe_host}`；`oc_engine/egress_tests.rs` 3 个启动契约测试。
- 配置 JSON（camelCase，App 与 Rust 共用）：`{"enabled":bool,"groups":[{"id":1,"name":"…","enabled":bool,"members":[{"pattern":"a.example","method":"trace"|"cdn-node"|自定义 id|null,"probeHost":null}],"cidrs":["…"],"expect":["ZZ"]}],"methods":[{"id":"…","name":"…","url":"https://{host}/…","head":false,"extract":{"kind":"kv"|"json"|"header","key":"…","regex":null}}]}`。`method:null` 即"跟随本组"。

## 1. 打包与进程清扫（已接线）

1. `scripts/build-local.sh`：`cargo build --release --bin alwaysconnect-gate`，复制到 `$APP/Contents/Resources/openconnect/bin/alwaysconnect-gate`，用与 openconnect 同一身份签名（参照 `scripts/bundle-openconnect.sh` 的签名方式）。现有安装（`scripts/dev-helper.sh install`、App 内 PrivilegedBundle）整目录复制到 `/Library/PrivilegedHelperTools/AlwaysConnect-openconnect`，引擎的 `bundled_is_trusted` 已覆盖该路径。
2. `scripts/verify-release.sh` / `scripts/package-release.sh`：发布包必须含闸门程序且签名有效；打包检查的构建机路径规则同样适用。
3. `Sources/Helper/HelperDaemon.swift` 的 `leftoverMarkers`：加 `("openconnect", "--script=" + quoted(gate) + " " + quoted(script))`。
4. `scripts/reset-network.sh`：结束 openconnect 后再结束 `AlwaysConnect-openconnect/bin/alwaysconnect-gate`；`scripts/uninstall-test.sh` 夹具加上该文件（`uninstall.sh` 已整目录删除）。
5. local-checks：断言 App 包里有闸门程序且可执行。

## 2. 后台服务：探测钩子与 XPC（已接线）

1. 探测钩子（Swift，Network.framework 薄壳）：`NWConnection` + TLS（`sec_protocol_options_add_tls_application_protocol` 依次加入 `ProbeRequest.alpn`）、`requiredInterface` 取名为 `ProbeRequest.interface` 的接口（`NWPathMonitor` 取快照）、证书按系统校验；发送 `request` 原文，读到关闭或 64 KB 或超时（`timeoutMs`），返回原始字节；失败返回空。不在引擎队列上执行，不带任何 cookie 或凭据。
2. FFI（`core/src/ffi.rs`）：`ac_oc_set_egress_probe(engine, ctx, fn(ctx, req_json, out_len) -> malloc 字节)`、`ac_oc_update_egress(engine, json)`、`ac_oc_egress_status(engine) -> malloc JSON`、`ac_oc_egress_probe_host(engine, host) -> malloc JSON`。Swift 侧 `@_silgen_name` 声明放在 `CLIOrchestrator.swift` 现有声明旁。
3. `CLIOrchestrator` 的引擎配置 JSON 加 `egress`；`HelperDaemon` 保存 App 下发的配置，连接时带上，运行中 `update_egress`。
4. XPC（`Sources/Shared/HelperXPC.swift`，Phase 1 三个方法不动）：`setEgressProtection(_ json: String, withReply: (Bool))`、`getEgressStatus(withReply: (String))`、`probeEgress(_ host: String, withReply: (String))`。App 侧一律 3 秒超时回落，并先判断 `installedHelperOutdated`（调用已装服务没有的方法会断开连接）。

## 3. App：配置、界面、通知（已接线）

1. 模型（`Sources/Shared/Models.swift` 或现有设置存储处）：与上面 JSON 同形的 Codable，新增字段一律 `decodeIfPresent`；随分流名单同一时机下发后台服务。
2. 分流页第三张卡（UI-DESIGN「出口保护」一节逐条实现）：总开关（经 Cisco 或断线保护关着时置灰并写明原因；切换时"需要重新连接一次"内联确认）、组列表与编辑、成员的检测方式选择、加网站时调 `probeEgress` 显示每种方式的结果并按规则默认选中（全部失败默认"跟随本组"）、预期国家（打开组时以探测结果锁定）、自定义检测方式（折叠）。没有能查的成员时组开关不可点。
3. 连接页：走 VPN 的行加「加入出口保护」（与「加直连」同一位置与撤销条）。
4. 面板一行状态与通知：`getEgressStatus` 只在面板可见或出口保护开着且已连接时以带容差的计时器读取；异常与恢复各推一次通知（UserNotifications），动作「信任新出口」把观测国家加进该组 `expect` 后 `setEgressProtection`；拦截记录进诊断包。
5. 关断线保护时若出口保护开着：同时关掉出口保护并提示需要重新连接（DESIGN §66.8）。

## 4. DNS 转发器去掉 ECH（已接线）

`core/src/dns_forwarder.rs` 在 §42 去掉地址提示的同一处，出口保护开着时再去掉 HTTPS/SVCB 记录的 `ech` 参数（SvcParamKey 5）；单测覆盖开与关两种情况、其余参数原样保留。

## 5. 文档、验证与交付

接线的行为、边界和验证级别已记在 DESIGN §66.14。真实网关、闸门恢复、浏览器、匿名检测及开销的机测数据见 DESIGN §66.15，逐项完成情况见 mac-proof §K。

- 每批：代码与 DESIGN（§66.14 进度、验证级别）、UI-DESIGN、HANDOVER、实测清单同批改；`cd core && cargo test`；`scripts/build-local.sh --tests`；推送前对 `git log -p origin/main..HEAD` 做关键词审查（清单只在本地，见项目记忆）；四个 CI job 全绿再汇报；更新 PR #7 描述。
- 开销：按 §32 量出口保护关着（必须零新增）与开着时的 footprint / CPU / 每秒唤醒与 VPN 吞吐，写进 DESIGN。
- 不做：不替换 /Applications 里的 App 或已装后台服务（等维护者说"装"）、不在本机动网络、不合并、不发版。
- 真机实测（实测清单 K1–K10）需维护者在场：先问协调方确认没有别的 Thread 在测；用带自动恢复的验收工具安装；会新登录一次 VPN（手机确认一次）；把某组预期国家故意设错即可模拟"出口不对"。

## 6. 公开仓库

代码、文档、测试夹具、提交信息里不出现维护者要保护的服务、国家、具体查询点或公司信息；示例一律 `*.example`、`*.test`、文档地址段与 ZZ/YY。
