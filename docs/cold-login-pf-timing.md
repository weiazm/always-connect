# 首连截止的真机计时

用于 [DESIGN §68.4](../DESIGN.md#684-面板区分准备服务器地址和连接-vpn) 的独立验收工具。
它把网关准备的截止设在连接意图后 2.5 秒，调用候选版正式的 Rust `Guard` 接口，
省略 App 的准备回执。测试只覆盖后台截止后的拦截，正常首次登录、缓存和真实网关另测。
两个可执行文件只放入验收工具包，产品安装包无需包含它们。

## 构建并交给回退包

在准备实测的候选提交上以普通用户构建。使用当前候选的 Rust 库，以及 macOS 自带的框架。

```bash
cargo build --locked --release --manifest-path core/Cargo.toml --example cold-login-pf-timing
swiftc -O -warnings-as-errors core/scripts/ColdLoginPFTimingProbe.swift -o <验收包待签目录>/pf-timing-https
```

把 `core/target/release/examples/cold-login-pf-timing` 复制为 `tools.app/Contents/Resources/pf-timing`，
把 `pf-timing-https` 放在同目录，然后由现有验收流程签名。由 `ops.sh` 复制至 root 私有
stage 并按既有证书与 identifier `codesign --verify --strict --deep -R` 验签后再执行。
调用只传入绝对 stage 路径，使用干净的进程环境。

```text
<stage>/tools.app/Contents/Resources/pf-timing <stage>
```

原 App 正常退出，卸载其 launchd 服务并独占本机网络测试窗口。由启动方确认所有 VPN
均未连接，包括没有改变 IPv4 默认路由的 VPN。测量程序另外检查产品进程、服务和
网络账本均不存在，确认目标与默认 IPv4 路由均使用同一个物理网卡，并读取产品锚点、
子锚点和表为空。遇到在用或无法核对的状态即退出。

### root 私有 stage 契约

- 路径 `/private/tmp/alwaysconnect-acceptance.<suffix>`，属主 `root:wheel`、模式 `0700`，无符号链接。
  `guard-label` 为 `com.alwaysconnect.acceptance.<suffix>`，`guard-pid` 与对应系统 launchd 作业的运行 PID 一致。
  `deadline` 为十进制 Unix 秒，启动时至少剩 60 秒。
- `guard-ready` 和 `exercise-done` 分别为单行 `ready` 和 `exercised`。`connection-good`
  是回退进程持续刷新、最近 20 秒内触及的普通空文件。存在 `disarm`、`guard-stopped` 或
  `rollback-reason` 时退出。工具在武装前和采样期间继续检查回退状态。
- 由验收方写入 root 所有、模式 `0400` 的普通文件 `pf-timing.json`。只允许 `host`（TLS 域名）、
  `address`（经确认与域名对应的公网 IPv4 字符串）、`path`（固定的绝对路径，无查询或片段）、
  `uid` 和 `gid`（普通登录用户的数值身份）。使用获准的受控端点。端点须用有效证书、
  允许同一条 HTTP/1.1 连接反复 HEAD，并返回无正文的 HTTP 2xx。工具固定连接该地址的 443 端口，
  按域名校验证书。域名、地址和路径只通过匿名管道传给探测程序，不进入命令参数、输出或仓库。
  探测程序先放弃 root 凭据与额外组权限，再打开套接字。它不发凭据、不跟随跳转、不重连。

### 回退与 PID 登记

同一 stage 仅执行一次。计时进程先建立独立进程组，写入 root 私有的 `pf-timing-pgid`，
内容为单行十进制 `PID=PGID` 的共同数值。开始武装前写 `pf-timing-armed`，内容为单行
正式 Guard 持有者（正常为 `own:1`）。复核恢复成功后才写 `pf-timing-clean`，内容为
`restored` 加换行。测量失败但恢复成功时一样写该标记。正常收尾先回收 HTTPS 子进程，
再取消截止票据、释放本次持有者，读回空锚点和原 PF 启用状态、原启用引用集合，
并核对产品账本消失。最后核对原物理路由和新 HTTPS 连接。

独立回退必须能在计时进程挂起或被杀时自行完成。回退前核对登记的 PID、进程组及 root
私有包中的确切可执行路径，先收割该组，再恢复 App 和服务，避免旧截止重新加载。
当 `pf-timing-armed` 存在且没有恢复标记时，按产品路径
`/Library/Application Support/AlwaysConnect/guard.json` 核对本次开机的 `bootSession`、
登记的 `holder`、`connected: false`、空 `inputs.gatewayIps`，只归还确认属于本次测量的
十进制字符串 `token`。本工具不运行全局 PF flush 或 disable。若进程恰在 PF 返回引用后、
Guard 原子落盘前死亡，或归还引用失败但产品账本已删除，账本可能没有可归还的 token。
回退方保留测前引用基线，只有能够证明归属的引用才可归还。无法归属或未恢复时应记录为未确认。
`pf-timing-armed` 缺失表示计时进程未到达任何 PF 写入口。恢复流程最终读回项目锚点与连通性。

## 度量与判定

启动先在同一条已建立的 TLS 连接取得至少三次成功应答，完成最后一轮只读检查后再取一次成功应答。
从调用 `Guard` 前开始按单调时钟计时。每隔约 50 毫秒只读检查产品锚点。HTTPS 在同一连接上
约每 100 毫秒发送一次 HEAD，单次等待最多 350 毫秒，遇到超时、关闭或其他错误停止。
判断依据包括后台核验状态、规则出现的读回区间、最后成功应答、首次无应答的请求启动时刻及结果时刻。
规则最晚须在 3 秒内读回，首次无应答的请求须在 3 秒内启动。收到关闭或超时的时刻可能更晚，
观测窗口为 3.65 秒。若规则读回后发出的请求仍成功、有提前失败、响应协议异常或后台未能核验，
工具退出非零并保留已知读数。正常结束仍需核对恢复，退出码 0 才表示全部通过。

采样只能定位规则出现和该条 HTTPS 流的行为区间，不能推算最后一个物理包或推断其他流量均已被拦截。
只有真机验收通过后才记录实测数字。离线预检运行
`cargo test --locked --manifest-path core/Cargo.toml --example cold-login-pf-timing`，
它使用正式 Guard、假 pfctl 和替身应答时间线。Swift 端可单独编译核对。
