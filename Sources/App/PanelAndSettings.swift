import SwiftUI

/// Menu-bar popover: a big coloured status header, four switches as
/// tiles (VPN, 代理, 出口保护, 断线保护; layout B, user 2026-11-25), the
/// speed, server and split, last error. The red recovery button stays
/// whenever the network is held. The old small switch read the same
/// on and off inside a popover (user, 2026-11-03), so the state is now
/// spelled out and the button says what it will do (UI-DESIGN.md §四).
/// Disconnecting a working connection goes through an inline confirm
/// row; from a red state (dropped, held) the button restores the
/// direct network at once, so the user is never trapped.
/// The panel is lazily created and released on close to keep the App's
/// footprint minimal.
struct PanelView: View {
    @ObservedObject var manager: HelperClient
    var profile: Profile
    var onStart: () -> Void
    var onStop: () -> Void
    /// Close the popover, then open Settings (optionally on a tab).
    var onOpenSettings: (String?) -> Void = { SettingsWindow.shared.show(tab: $0) }
    /// Close the panel (a link opened in the browser).
    var onClose: () -> Void = {}
    @State private var showConfirmDisconnect = false
    @State private var servers = ProfileStore.loadServers()
    @State private var selectedServer = ProfileStore.loadProfile().server
    @State private var protectionOn = ProfileStore.loadAppSettings().isDropProtectionOn
    @State private var egressDisabledWithDrop = false
    @State private var egressActionError: String?
    @State private var egressStopConfirmation: UInt32?
    @State private var egressRechecking = false
    @State private var showConfirmQuit = false
    /// The split switch flipped while connected: reconnect first (§26.12).
    @State private var confirmSplit: Bool?
    @State private var siteCount = DirectSites.sites(ProfileStore.loadAppSettings()).count
    /// Other VPNs / proxies seen at panel open (§27.2).
    @State private var neighbors: [NeighborNotice] = []
    private let activityTimer = Timer.publish(every: 3, on: .main, in: .common).autoconnect()
    @State private var showConfirmReset = false
    @State private var resettingNetwork = false
    @State private var resetMessage: String?
    /// Read once per panel open (it compares two binaries).
    @State private var helperOutdated = HelperInstaller.installedHelperOutdated
    @State private var installMessage: String?
    /// The 网速 card's reader, only while the panel is open (§45.4).
    @StateObject private var speed = PanelSpeed()
    /// Whether the network answers through the VPN, while open (§69.8).
    @StateObject private var link = LinkCheck()
    @ObservedObject private var proxyHealth = ProxyHealth.shared
    @State private var settings = ProfileStore.loadAppSettings()
    /// The 出口保护 switch asked for a reconnect: the change waits here.
    @State private var egressSwitch: (change: EgressRuleChange, paused: [UInt32])?

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            PanelStatusHeader(client: manager, subtitle: subtitle)
            if !manager.gatewayTrustFailed, manager.state != .disconnected, let notice = manager.loginProtectionNotice {
                Label(notice, systemImage: "lock.shield").font(.callout)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if manager.showsConnected, let notice = manager.dnsNotice {
                Label(notice, systemImage: "exclamationmark.triangle.fill")
                    .font(.callout)
                    .foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if primaryButtonNeeded { primaryButton }
            tiles
            if showConfirmDisconnect {
                HStack {
                    Text("断开后网络恢复直连")
                        .font(.callout)
                    Spacer()
                    Button("确认断开") {
                        showConfirmDisconnect = false
                        onStop()
                    }
                    Button("取消") {
                        showConfirmDisconnect = false
                    }
                }
            }
            egressFollowUps
            if manager.showsConnected {
                speedCard
            }
            quickSettings
            if let on = confirmSplit {
                VStack(alignment: .leading, spacing: 6) {
                    Text(on ? "开启分流要用证书重新连接一次，手机需要再批准。"
                            : "关闭分流会改回经 Cisco 重新连接一次，可能需要再批准。")
                        .font(.callout)
                        .fixedSize(horizontal: false, vertical: true)
                    HStack {
                        Spacer()
                        Button("取消") { confirmSplit = nil }
                        Button("重新连接") {
                            confirmSplit = nil
                            manager.setSplit(on: on)
                        }
                        .buttonStyle(.borderedProminent)
                    }
                }
            }
            ForEach(neighbors.filter { $0.level == .warning || manager.state == .disconnected }, id: \.text) { notice in
                Label(notice.text, systemImage: notice.level == .warning ? "exclamationmark.triangle.fill" : "info.circle")
                    .font(.caption)
                    .foregroundStyle(notice.level == .warning ? Color.orange : Color.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if let drop = manager.lastDrop {
                Label("上次掉线 \(dropTime(drop.latestDropAt)) · \(drop.panelSummary)",
                      systemImage: "clock.arrow.circlepath")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if let error = manager.lastError {
                Text(error)
                    .font(.caption)
                    .foregroundStyle(.red)
            }
            if let notice = manager.autoStopNotice, manager.state == .disconnected {
                Text(notice)
                    .font(.caption)
                    .foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if manager.helperUnresponsive {
                // The restore got no answer (DESIGN.md §25.5): the way
                // out that needs no background service at all.
                VStack(alignment: .leading, spacing: 6) {
                    Text(manager.networkHeld
                         ? "后台服务没有响应，网络仍被暂停"
                         : "后台服务状态未确认，可尝试恢复网络")
                        .font(.caption)
                        .foregroundStyle(.red)
                    Button("强制恢复网络（需电脑密码）") {
                        manager.prepareForForcedRestore()
                        HelperInstaller.forceRecover { result in
                            switch result {
                            case .success:
                                installMessage = "网络已恢复直连"
                                manager.forcedRestoreDone()
                            case .failure(HelperInstaller.InstallError.cancelled):
                                installMessage = "已取消：需要输入电脑密码才能强制恢复"
                                manager.forcedRestoreAbandoned()
                            case .failure(let error):
                                installMessage = "强制恢复失败：\(error.localizedDescription)"
                                manager.forcedRestoreAbandoned()
                            }
                        }
                    }
                    if let installMessage {
                        Text(installMessage)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
            }
            if let warning = manager.pfWarning, manager.state != .disconnected {
                Text(warning)
                    .font(.caption)
                    .foregroundStyle(.red)
            }
            if let warning = manager.splitWarning, manager.showsConnected {
                Text(warning)
                    .font(.caption)
                    .foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if !manager.helperAvailable {
                // "Helper" is our word, not the user's: say what it is
                // for (UI-DESIGN.md §四).
                HStack {
                    Text("后台服务未运行：断线时无法封网")
                        .font(.caption)
                        .foregroundStyle(.red)
                    Spacer()
                    Button("安装后台服务") {
                        HelperInstaller.install { result in
                            switch result {
                            case .success:
                                installMessage = "后台服务已安装"
                                manager.refreshStatus()
                            case .failure(let error):
                                installMessage = HelperInstaller.failureText(error)
                            }
                        }
                    }
                }
                if let installMessage {
                    Text(installMessage)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            if manager.helperAvailable, helperOutdated {
                // A rebuilt local App carries a newer service than the
                // one installed (DESIGN.md §21.8).
                HStack {
                    Text(manager.helperUpdateWaiting ? "等这次登录完成后再更新…"
                         : manager.helperUpdatePending ? "正在更新后台服务…"
                         : manager.switchIsOn && !manager.usesCisco ? "后台服务有新版本（更新时连接会断几秒，自动接上）" : "后台服务有新版本")
                        .font(.caption)
                        .foregroundStyle(.orange)
                        .fixedSize(horizontal: false, vertical: true)
                    Spacer()
                    Button("更新") {
                        manager.installHelper { result in
                            switch result {
                            case .success:
                                helperOutdated = false
                                installMessage = "后台服务已更新"
                            case .failure(let error):
                                installMessage = HelperInstaller.failureText(error)
                            }
                        }
                    }
                    .disabled(manager.helperUpdatePending)
                }
                if let installMessage {
                    Text(installMessage)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            UpdateBanner(onOpen: onClose)
            networkResetConfirm
            Divider()
            // One quiet toolbar row: Settings (server, account, network),
            // diagnostics, the way back to the direct network (always
            // there, §24.6), quit.
            HStack(spacing: 0) {
                PanelToolButton(title: "设置", symbol: "gearshape") {
                    onOpenSettings(nil)
                }
                .help("服务器地址、账号、断线保护等")
                PanelToolButton(title: "诊断包", symbol: "square.and.arrow.down") {
                    DiagnosticsExporter.export(manager: manager, profile: profile)
                }
                .help("导出诊断信息（不含密码与账号）")
                PanelToolButton(title: resettingNetwork ? "恢复中…" : "恢复网络",
                                symbol: "arrow.uturn.backward.circle") {
                    showConfirmReset = true
                }
                .disabled(resettingNetwork)
                .help("上不了网、被 AlwaysConnect 卡住时：断开 VPN，清掉 AlwaysConnect 改过的路由、DNS 和防火墙设置，回到直连")
                Spacer(minLength: 0)
                // Quit = VPN off, direct network, nothing of ours left
                // running (DESIGN.md §21.5); confirm only when that
                // actually ends a connection.
                PanelToolButton(title: "退出", symbol: "power") {
                    if manager.switchIsOn {
                        showConfirmQuit = true
                    } else {
                        AppQuit.request()
                    }
                }
                .help("断开 VPN、恢复直连网络，并退出 AlwaysConnect")
            }
            if showConfirmQuit {
                HStack {
                    Text("退出会断开 VPN，网络恢复直连")
                        .font(.callout)
                    Spacer()
                    Button("断开并退出") {
                        showConfirmQuit = false
                        AppQuit.request()
                    }
                    Button("取消") { showConfirmQuit = false }
                }
            }
        }
        .padding(16)
        .frame(width: 340)
        .toggleStyle(.always)
        .onAppear {
            manager.prepareGatewayWhileDirect()
            speed.start()
            manager.refreshSplitActivity()
            manager.refreshEgress()
            checkHealth()
            let active = manager.state != .disconnected
            let cisco = manager.usesCisco
            let split = manager.ownConnection
            DispatchQueue.global(qos: .userInitiated).async {
                let found = NetworkNeighbors.notices(NetworkNeighbors.observe(
                    oursActive: active && !cisco, ciscoTunnel: active && cisco, splitOn: split))
                DispatchQueue.main.async { neighbors = found }
            }
        }
        .onReceive(activityTimer) { _ in
            manager.refreshSplitActivity()
            manager.expireGatewayPreparation()
            checkHealth()
        }
        .onChange(of: manager.showsConnected) { _ in link.reset(); checkHealth() }
        .onDisappear { speed.stop() }
    }

    /// 网速 (DESIGN.md §45.4): the VPN and the direct part side by side,
    /// only while connected; "连接详情" opens the per-connection page.
    private var speedCard: some View {
        Button { onOpenSettings("connections") } label: {
            HStack(spacing: 10) {
                speedColumn("走 VPN", color: .green, speed.totals?.vpn)
                Divider().frame(height: 30)
                speedColumn("直连", color: .orange, speed.totals?.direct)
                Image(systemName: "chevron.right")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.tertiary)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .help("网速；点开看每条连接")
        .padding(.horizontal, 12).padding(.vertical, 9)
        .background(RoundedRectangle(cornerRadius: 10).fill(Color.primary.opacity(0.06)))
    }

    private func speedColumn(_ title: String, color: Color, _ rate: [Int]?) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack(spacing: 5) {
                Circle().fill(color).frame(width: 6, height: 6)
                Text(title).font(.caption).foregroundStyle(.secondary)
            }
            HStack(alignment: .firstTextBaseline, spacing: 6) {
                Text("↓ " + (rate.map { PanelSpeed.text($0[0]) } ?? "…"))
                    .font(.system(size: 13, weight: .semibold).monospacedDigit())
                Text("↑ " + (rate.map { PanelSpeed.text($0[1]) } ?? "…"))
                    .font(.caption2.monospacedDigit())
                    .foregroundStyle(.secondary)
            }
            .lineLimit(1)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    /// One row of the settings card: icon, name, a line under it, and
    /// whatever sits on the right.
    private func rowLabel(_ symbol: String, _ title: String, _ caption: String?, captionLines: Int = 1,
                          captionColor: Color = .secondary) -> some View {
        HStack(spacing: 10) {
            Image(systemName: symbol)
                .foregroundStyle(.secondary)
                .frame(width: 18)
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                if let caption {
                    Text(caption)
                        .font(.caption)
                        .foregroundStyle(captionColor)
                        .lineLimit(captionLines)
                }
            }
        }
    }

    /// 按网站分流 in the panel (§26.12): the switch, and in one line what
    /// it is doing right now.
    private var splitRow: some View {
        Toggle(isOn: Binding(
            get: { manager.ownConnection },
            set: { on in
                if manager.switchIsOn { confirmSplit = on } else { manager.setSplit(on: on) }
            })) {
            HStack(spacing: 6) {
                rowLabel("arrow.triangle.branch", "按网站分流", splitCaption)
                    .help(splitHelp)
                Spacer(minLength: 4)
                Button("名单") { onOpenSettings("split") }
                    .buttonStyle(.link)
                    .font(.caption)
            }
        }
        .disabled(manager.splitSwitchPending)
        .padding(.vertical, 8)
    }

    /// The sites the split is sending direct right now, on hover.
    private var splitHelp: String {
        guard let activity = manager.splitActivity, !activity.entries.isEmpty else { return "" }
        return "正在直连：" + activity.entries.joined(separator: "、")
    }

    private var splitCaption: String {
        if manager.splitSwitchPending { return "正在切换，稍候会重新连接…" }
        guard manager.ownConnection else { return "关：全部走 VPN（经 Cisco）" }
        if siteCount == 0 { return "名单还是空的，点「名单」添加" }
        guard manager.showsConnected, let activity = manager.splitActivity else {
            return "名单里 \(siteCount) 条不走 VPN"
        }
        if activity.entries.isEmpty { return "还没打开名单里的网站" }
        return "\(activity.entries.count) 个网站直连 · \(activity.addresses) 个地址"
    }

    /// The way back when the Mac has no network because of us (DESIGN.md
    /// §24.6): always there, works offline, asks once for the Mac password.
    /// The button itself is in the bottom toolbar (§45.4); its confirm
    /// and its outcome show here.
    @ViewBuilder private var networkResetConfirm: some View {
        if showConfirmReset {
            VStack(alignment: .leading, spacing: 6) {
                Text("会断开 VPN，并清掉 AlwaysConnect 改过的路由、DNS 和防火墙设置，回到直连。需要输入一次开机密码。")
                    .font(.callout)
                    .fixedSize(horizontal: false, vertical: true)
                HStack {
                    Spacer()
                    Button("取消") { showConfirmReset = false }
                    Button("恢复网络") {
                        showConfirmReset = false
                        resettingNetwork = true
                        resetMessage = nil
                        manager.prepareForNetworkReset()
                        NetworkReset.run { outcome in
                            resettingNetwork = false
                            manager.networkResetFinished()
                            switch outcome {
                            case .restored(let text): resetMessage = text
                            case .failed(let text): resetMessage = "没有完全恢复：\(text)"
                            case .cancelled: resetMessage = nil
                            }
                        }
                    }
                    .buttonStyle(.borderedProminent)
                }
            }
        }
        if let resetMessage {
            Text(resetMessage)
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    /// The everyday switches, right in the panel (owner's request,
    /// DESIGN.md §21.13): which server, and drop protection.
    private var quickSettings: some View {
        VStack(spacing: 0) {
            HStack {
                rowLabel("server.rack", "服务器", nil)
                Spacer()
                Menu {
                    ForEach(servers) { entry in
                        Button {
                            selectedServer = entry.target
                            manager.switchServer(to: entry.target)
                        } label: {
                            if entry.target == selectedServer {
                                Label(entry.name, systemImage: "checkmark")
                            } else {
                                Text(entry.name)
                            }
                        }
                    }
                    Divider()
                    Button("管理服务器…") { onOpenSettings("credentials") }
                } label: {
                    Text(servers.first { $0.target == selectedServer }?.name ?? selectedServer)
                }
                .menuStyle(.borderlessButton)
                .fixedSize()
            }
            .padding(.vertical, 9)
            Divider()
            splitRow
        }
        .font(.callout)
        .padding(.horizontal, 12)
        .background(RoundedRectangle(cornerRadius: 10).fill(Color.primary.opacity(0.06)))
    }

    // MARK: - The four switches (layout B, UI-DESIGN.md 面板)

    /// The everyday button is the VPN tile; the big button stays only where
    /// it says more than a switch can: the red way back to the direct
    /// network (never trapped, §24.6), missing credentials, and cancelling
    /// a protected login.
    private var primaryButtonNeeded: Bool {
        manager.gatewayTrustFailed || manager.state == .reconnecting || manager.networkHeld
            || !manager.hasCredentials
            || (manager.state == .disconnected && manager.loginProtectionNotice != nil)
    }

    private var tiles: some View {
        // Two equal columns; a long state line is cut, never widens one.
        VStack(spacing: 8) {
            HStack(spacing: 8) {
                vpnTile
                proxyTile
            }
            HStack(spacing: 8) {
                egressTile
                dropTile
            }
        }
    }

    private var vpnTile: some View {
        let red = manager.gatewayTrustFailed || manager.state == .reconnecting || manager.networkHeld
        let (caption, tint): (String, Color) = {
            if !manager.hasCredentials { return ("先填账号和密码", .secondary) }
            if manager.gatewayTrustFailed { return ("网关证书不对", .red) }
            if manager.networkHeld && manager.state != .connected { return ("网络已暂停", .red) }
            switch manager.state {
            case .connected:
                switch link.state {
                case .ok(let ms): return ("已连接 · \(ms) ms", .green)
                case .slow(let ms): return ("已连接 · 慢 \(ms) ms", .orange)
                case .down: return ("已连接 · 网络不通", .red)
                case .unknown: return ("已连接 · 检测中…", .green)
                }
            case .reconnecting: return ("掉线重连中", .orange)
            case .disconnected:
                return (manager.onDemandPaused ? "按网络规则暂停" : "未连接", .secondary)
            default: return ("正在连接…", .orange)
            }
        }()
        return PanelTile(symbol: "lock.shield.fill", title: "VPN", caption: caption, tint: tint,
                         isOn: manager.switchIsOn,
                         help: "上网检测：每 10 秒试着打开几个常用网址，取最快的应答（面板开着时才测）") { on in
            if on {
                showConfirmDisconnect = false
                if manager.hasCredentials { onStart() } else { onOpenSettings("credentials") }
            } else if red {
                onStop()
            } else {
                showConfirmDisconnect = true
            }
        } open: { onOpenSettings("credentials") }
    }

    private var proxyTile: some View {
        let all = (settings.proxyRoutes ?? []).filter { $0.enabled && !$0.sites.isEmpty }
        let on = settings.proxiesOn && !all.isEmpty
        let (caption, tint): (String, Color) = {
            if all.isEmpty { return ((settings.proxyRoutes ?? []).isEmpty ? "未添加" : "都已停用", .secondary) }
            if !settings.proxiesOn { return ("关 · 网站照常分流", .secondary) }
            if !manager.ownConnection { return ("要开按网站分流", .orange) }
            let summary = proxyHealth.summary(all)
            let color: Color = summary.level == .ok ? .green : summary.level == .warn ? .orange : summary.level == .fail ? .red : .secondary
            if !manager.showsConnected { return ("\(all.count) 个 · 连上 VPN 生效", .secondary) }
            return (summary.text, color)
        }()
        return PanelTile(symbol: "arrow.triangle.swap", title: "代理", caption: caption, tint: tint, isOn: on,
                         help: proxyHelp(all)) { turnOn in
            if all.isEmpty { onOpenSettings("proxy"); return }
            var stored = ProfileStore.loadAppSettings()
            stored.proxiesPaused = turnOn ? nil : true
            ProfileStore.saveAppSettings(stored)
            settings = stored
            if !manager.usesCisco { manager.pushDirectDomains() }
            if turnOn { proxyHealth.check(all, force: true) }
        } open: { onOpenSettings("proxy") }
    }

    /// Each proxy and its state, on hover.
    private func proxyHelp(_ routes: [ProxyRoute]) -> String {
        routes.map { route in
            "\(route.name)：" + (proxyHealth.checks[route.id]?.short ?? "未检测")
        }.joined(separator: "\n")
    }

    private var egressTile: some View {
        let config = settings.egressProtection ?? EgressProtection()
        let available = !manager.usesCisco && protectionOn
        let (caption, tint): (String, Color) = {
            if config.groups.isEmpty { return ("未设置", .secondary) }
            if manager.usesCisco { return ("经 Cisco 时不可用", .secondary) }
            if !protectionOn { return ("要先开断线保护", .secondary) }
            guard config.isActive else { return ("关", .secondary) }
            guard let line = manager.egressLine, !manager.gatewayTrustFailed else { return ("开", .secondary) }
            switch manager.egressLevel {
            case .ok: return (line, .green)
            case .partial: return (line, .orange)
            case .unknown: return (line, .secondary)
            }
        }()
        return PanelTile(symbol: "checkmark.shield.fill", title: "出口保护", caption: caption, tint: tint,
                         isOn: config.isActive && available, enabled: available || config.groups.isEmpty,
                         help: manager.egressLine ?? "") { on in
            if config.groups.isEmpty { onOpenSettings("egress"); return }
            setEgress(on: on)
        } open: { onOpenSettings("egress") }
    }

    private var dropTile: some View {
        PanelTile(symbol: protectionOn ? "lock.fill" : "lock.open.fill", title: "断线保护",
                  caption: protectionOn ? "掉线时暂停上网" : "关 · 掉线走本地网络",
                  tint: .secondary, isOn: protectionOn,
                  help: protectionOn ? "掉线时暂停上网，不漏走直连" : "掉线时改走本地网络") { on in
            protectionOn = on
            var stored = ProfileStore.loadAppSettings()
            stored.dropProtection = on
            egressDisabledWithDrop = !on && stored.egressProtection?.enabled == true
            if !on { stored.egressProtection?.enabled = false }
            ProfileStore.saveAppSettings(stored, updatingEgress: !on)
            settings = ProfileStore.loadAppSettings()
            manager.dropProtectionChanged()
        } open: { onOpenSettings("general") }
    }

    /// While the panel is open: the VPN's answer time, and each proxy at
    /// most every 30 s (§69.8). Nothing runs once it closes.
    private func checkHealth() {
        if manager.showsConnected { link.checkIfDue() }
        if manager.showsConnected, manager.ownConnection, settings.proxiesOn {
            proxyHealth.check(settings.activeProxyRoutes)
        }
    }

    /// The 出口保护 switch: off pauses every protection that is on and
    /// remembers which; on brings those back (or, if none were noted,
    /// every protection that has sites and countries).
    private func setEgress(on: Bool) {
        let stored = ProfileStore.loadAppSettings()
        let config = stored.egressProtection ?? EgressProtection()
        let paused = config.enabled ? config.groups.filter(\.enabled).map(\.id) : []
        let wanted = Set(stored.egressPausedRules ?? [])
        let change = EgressRuleChange(config: config) { result in
            for index in result.groups.indices {
                let group = result.groups[index]
                let ready = !group.sites.isEmpty && !group.expect.isEmpty
                result.groups[index].enabled = on && ready && (wanted.isEmpty || wanted.contains(group.id))
            }
        }
        guard !on || change.after.isActive else {
            egressActionError = "没有能打开的保护（要有网站和允许的国家）。"
            onOpenSettings("egress")
            return
        }
        guard change.after.permitsActivation(comparedTo: config) else { egressActionError = "这组保护还不能打开。"; return }
        if change.needsReconnect(connected: manager.showsConnected) {
            egressSwitch = (change, paused)
        } else {
            applyEgressSwitch(change, paused: paused)
        }
    }

    private func applyEgressSwitch(_ change: EgressRuleChange, paused: [UInt32]) {
        manager.saveEgress(change.after, replacing: change.before) { ok in
            if ok {
                var latest = ProfileStore.loadAppSettings()
                latest.egressPausedRules = change.after.isActive ? nil : paused
                ProfileStore.saveAppSettings(latest)
            }
            egressActionError = ok ? nil : "没有改成。请在出口保护页重试。"
            settings = ProfileStore.loadAppSettings()
            manager.refreshEgress()
        }
    }

    /// Under the tiles: what 出口保护 needs from the user right now.
    @ViewBuilder private var egressFollowUps: some View {
        if let pending = egressSwitch {
            VStack(alignment: .leading, spacing: 6) {
                Text(EgressRuleChange.reconnectCaption).font(.caption).fixedSize(horizontal: false, vertical: true)
                HStack {
                    Spacer()
                    Button("取消") { egressSwitch = nil }
                    Button(pending.change.confirmationTitle) {
                        egressSwitch = nil
                        applyEgressSwitch(pending.change, paused: pending.paused)
                    }
                    .buttonStyle(.borderedProminent)
                }
            }
        }
        if !manager.gatewayTrustFailed, manager.egressLine != nil,
           !manager.egressNotices.isEmpty || manager.egressRecheckRule != nil {
            HStack(spacing: 12) {
                Image(systemName: "exclamationmark.shield.fill").foregroundStyle(.orange)
                if let id = manager.egressRecheckRule {
                    Button(egressRechecking ? "正在重新检查…" : "重新检查出口") {
                        egressRechecking = true
                        manager.recheckEgressRule(id) { ok in
                            egressRechecking = false
                            egressActionError = ok ? "重新检查已完成，请查看当前状态。" : "这次未完成重新检查。"
                        }
                    }.disabled(egressRechecking)
                }
                if let notice = manager.egressNotices.first, manager.egressNotices.count == 1 {
                    Button("暂停这个保护", role: .destructive) { askToDisableEgressGroup(notice.id) }
                } else if !manager.egressNotices.isEmpty {
                    Menu("暂停保护") {
                        ForEach(manager.egressNotices) { notice in
                            Button(notice.name, role: .destructive) { askToDisableEgressGroup(notice.id) }
                        }
                    }
                    .fixedSize()
                }
                Spacer()
            }
            .buttonStyle(.borderless)
            .font(.caption)
        }
        if let id = egressStopConfirmation {
            VStack(alignment: .leading, spacing: 6) {
                Text(EgressRuleChange.reconnectCaption).font(.caption).fixedSize(horizontal: false, vertical: true)
                HStack {
                    Spacer()
                    Button("取消") { egressStopConfirmation = nil }
                    Button("关闭并重连") { egressStopConfirmation = nil; disableEgressGroup(id) }
                }
            }
        }
        if let egressActionError {
            Text(egressActionError).font(.caption).foregroundStyle(.secondary)
        }
        if egressDisabledWithDrop {
            Text("出口保护已关闭。自建连接需要重新连接一次才能生效。")
                .font(.caption).foregroundStyle(.secondary)
        }
    }

    private func disableEgressGroup(_ id: UInt32) {
        manager.disableEgressGroup(id) { ok in
            egressActionError = ok ? nil : "这组未停用。请在分流设置重试。"
        }
    }

    private func askToDisableEgressGroup(_ id: UInt32) {
        let config = ProfileStore.loadAppSettings().egressProtection ?? EgressProtection()
        let change = EgressRuleChange(config: config) { $0.disableGroup(id) }
        if change.needsReconnect(connected: manager.showsConnected) { egressStopConfirmation = id }
        else { disableEgressGroup(id) }
    }

    /// The engine's own words under the headline (retry count, last
    /// notice); for a plain disconnect, what "未连接" means.
    private var subtitle: String {
        if manager.state == .disconnected, let notice = manager.loginProtectionNotice { return notice }
        if !manager.hasCredentials {
            // Servers usually come from the Mac's Cisco (§三十八).
            return ProfileStore.loadProfile().servers.isEmpty ? "先填服务器、账号和密码" : "先填账号和密码"
        }
        if manager.state == .disconnected, !manager.networkHeld, manager.protectsDrops,
           let preparation = manager.loginGatewayReadiness.caption { return preparation }
        if manager.onDemandPaused, manager.state == .disconnected, !manager.networkHeld { return manager.stateLine }
        if manager.state == .disconnected, !manager.networkHeld { return "VPN 已关，正在用本地网络上网" }
        if manager.state == .reconnecting { return manager.stateLine }
        if manager.showsConnected {
            // Which server and for how long (§45.4), not the engine's words.
            let server = servers.first { $0.target == selectedServer }?.name ?? selectedServer
            guard let since = manager.connectedSince else { return server }
            return "\(server) · 已连接 \(Self.duration(Date().timeIntervalSince(since)))"
        }
        return manager.detail.isEmpty ? manager.stateLine : manager.detail
    }

    /// "不到 1 分钟", "12 分钟", "2 小时 13 分", "3 天 4 小时".
    static func duration(_ seconds: TimeInterval) -> String {
        let minutes = Int(seconds) / 60
        if minutes < 1 { return "不到 1 分钟" }
        if minutes < 60 { return "\(minutes) 分钟" }
        let hours = minutes / 60
        if hours < 24 { return "\(hours) 小时 \(minutes % 60) 分" }
        return "\(hours / 24) 天 \(hours % 24) 小时"
    }

    /// One button, labelled with what it does next.
    @ViewBuilder private var primaryButton: some View {
        let red = manager.gatewayTrustFailed || manager.state == .reconnecting || manager.networkHeld
        if red {
            // Never trapped behind drop protection: one click, no
            // confirm, back to the direct network.
            Button { showConfirmDisconnect = false; onStop() } label: {
                Text("断开 VPN，恢复直连网络").frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .tint(.red)
            .controlSize(.large)
        } else if !manager.hasCredentials {
            Button(ProfileStore.loadProfile().servers.isEmpty ? "填写服务器与账号" : "填写账号与密码") {
                onOpenSettings("credentials")
            }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
                .frame(maxWidth: .infinity)
        } else if manager.state == .disconnected, let notice = manager.loginProtectionNotice {
            let preparing = notice == ProtectedLoginNotice.preparingGateway
            Button(preparing ? "取消连接" : "取消连接并恢复直连") {
                showConfirmDisconnect = false
                onStop()
            }
                .buttonStyle(.borderedProminent).controlSize(.large)
        } else if manager.state == .disconnected, !manager.networkHeld {
            Button { showConfirmDisconnect = false; onStart() } label: {
                Text(manager.onDemandPaused ? "仍然连接" : "连接 VPN").frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
        } else {
            Button { showConfirmDisconnect = true } label: {
                Text(manager.showsConnected ? "断开 VPN" : "取消连接").frame(maxWidth: .infinity)
            }
            .buttonStyle(.bordered)
            .controlSize(.large)
        }
    }

    private func dropTime(_ date: Date) -> String {
        let formatter = DateFormatter()
        if Calendar.current.isDateInToday(date) {
            formatter.dateFormat = "今天 HH:mm"
        } else {
            formatter.dateFormat = "MM-dd HH:mm"
        }
        return formatter.string(from: date)
    }
}

/// The menu-bar panel's window (DESIGN.md §32.16): a borderless panel
/// with the popover material under the icon, not an NSPopover. Measured
/// with the same SwiftUI content: an NSPopover costs ~130 MB of graphics
/// memory for as long as it shows (animated or not), this ~7 MB.
final class MenuPanel: NSPanel {
    init() {
        super.init(contentRect: NSRect(x: 0, y: 0, width: 340, height: 200),
                   styleMask: [.borderless], backing: .buffered, defer: true)
        isFloatingPanel = true
        level = .statusBar
        collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary, .transient, .ignoresCycle]
        backgroundColor = .clear
        isOpaque = false
        hasShadow = true
        isReleasedWhenClosed = false
        hidesOnDeactivate = false
        animationBehavior = .utilityWindow
    }

    // Key, so native controls draw active (an inactive window draws them
    // grey, which read as "off", §21.14).
    override var canBecomeKey: Bool { true }
    override var canBecomeMain: Bool { false }

    override func cancelOperation(_ sender: Any?) { close() }
}

/// Tells the panel when its SwiftUI content wants another size (a
/// confirm row appeared), so the window follows with its top fixed.
final class PanelHostingView<Content: View>: NSHostingView<Content> {
    var onResize: (() -> Void)?
    private var pending = false

    override func invalidateIntrinsicContentSize() {
        super.invalidateIntrinsicContentSize()
        guard !pending else { return }
        pending = true
        DispatchQueue.main.async { [weak self] in
            self?.pending = false
            self?.onResize?()
        }
    }
}

final class PanelController: NSObject, NSWindowDelegate {
    private var panel: MenuPanel?
    private weak var anchor: NSStatusBarButton?
    private var outsideClicks: Any?
    private let manager: HelperClient

    init(manager: HelperClient) {
        self.manager = manager
    }

    var isShown: Bool { panel?.isVisible ?? false }

    func toggle(relativeTo button: NSStatusBarButton) {
        if isShown {
            panel?.close()
            return
        }
        // Fresh profile on every open: Settings may have changed it
        // since launch, and the panel must not show stale values.
        // Re-attach too: re-registers for pushes after a Helper
        // restart and corrects availability.
        manager.refreshStatus()
        UpdateChecker.shared.checkIfDue()
        GeoUpdater.shared.checkIfDue()
        let view = PanelView(
            manager: manager,
            profile: ProfileStore.loadProfile(),
            onStart: { [weak self] in self?.startTapped() },
            onStop: { [weak self] in self?.manager.disconnectByUser() },
            onOpenSettings: { [weak self] tab in
                self?.panel?.close()
                SettingsWindow.shared.show(tab: tab)
            },
            onClose: { [weak self] in self?.panel?.close() }
        )
        let panel = MenuPanel()
        let effect = NSVisualEffectView()
        effect.material = .popover
        effect.state = .active
        effect.blendingMode = .behindWindow
        effect.wantsLayer = true
        effect.layer?.cornerRadius = 12
        effect.layer?.masksToBounds = true
        let host = PanelHostingView(rootView: view)
        host.onResize = { [weak self, weak host] in
            guard let self, let host, let panel = self.panel else { return }
            let size = host.fittingSize
            if abs(size.height - panel.frame.height) > 0.5 || abs(size.width - panel.frame.width) > 0.5 {
                self.place(panel, size: size)
            }
        }
        host.translatesAutoresizingMaskIntoConstraints = false
        effect.addSubview(host)
        NSLayoutConstraint.activate([
            host.leadingAnchor.constraint(equalTo: effect.leadingAnchor),
            host.trailingAnchor.constraint(equalTo: effect.trailingAnchor),
            host.topAnchor.constraint(equalTo: effect.topAnchor),
            host.bottomAnchor.constraint(equalTo: effect.bottomAnchor),
        ])
        panel.contentView = effect
        panel.delegate = self
        self.panel = panel
        anchor = button
        place(panel, size: host.fittingSize)
        NSApp.activate(ignoringOtherApps: true)
        panel.makeKeyAndOrderFront(nil)
        // A click anywhere else closes it, as a popover's would.
        outsideClicks = NSEvent.addGlobalMonitorForEvents(matching: [.leftMouseDown, .rightMouseDown]) { [weak self] _ in
            self?.panel?.close()
        }
    }

    /// Under the menu-bar icon, top edge fixed (the panel grows and
    /// shrinks downwards as rows appear), kept on screen.
    private func place(_ panel: NSPanel, size: NSSize) {
        guard let button = anchor, let window = button.window else { return }
        let icon = window.convertToScreen(button.convert(button.bounds, to: nil))
        let screen = window.screen ?? NSScreen.main
        let bounds = screen?.visibleFrame ?? icon
        var x = icon.midX - size.width / 2
        x = min(max(x, bounds.minX + 6), bounds.maxX - size.width - 6)
        let top = icon.minY - 4
        panel.setFrame(NSRect(x: x.rounded(), y: (top - size.height).rounded(),
                              width: size.width, height: size.height), display: true)
    }

    func windowDidResignKey(_ notification: Notification) {
        // A menu or sheet of the panel itself takes key briefly; anything
        // else (another app, the desktop) closes it.
        DispatchQueue.main.async { [weak self] in
            guard let self, let panel = self.panel, panel.isVisible, !panel.isKeyWindow else { return }
            if NSApp.keyWindow == nil || NSApp.keyWindow?.parent === panel { return }
            panel.close()
        }
    }

    /// Closed = gone (DESIGN.md §32.1): its SwiftUI tree, timers and
    /// polls go with it; the next open builds a fresh one.
    func windowWillClose(_ notification: Notification) {
        guard let closing = notification.object as? MenuPanel, closing === panel else { return }
        if let outsideClicks { NSEvent.removeMonitor(outsideClicks) }
        outsideClicks = nil
        closing.delegate = nil
        DispatchQueue.main.async { [weak self] in
            closing.contentView = nil
            if self?.panel === closing { self?.panel = nil }
            MemoryRelief.soon()  // what the panel used goes back (§45.5)
        }
    }

    private func startTapped() {
        // Credentials come from the Keychain; without them the panel
        // switch is disabled, so this guard is a second line only.
        _ = manager.connectWithStoredCredentials(manual: true)
    }
}

/// One of the panel's switches (layout B, user 2026-11-25: low tiles,
/// no empty right half): icon and name with the switch on the first line,
/// the state across the whole tile under them. Clicking the words opens
/// that page of Settings.
struct PanelTile: View {
    var symbol: String
    var title: String
    var caption: String
    var tint: Color = .secondary
    var isOn: Bool
    var enabled = true
    var help = ""
    var toggle: (Bool) -> Void
    var open: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 5) {
            HStack(spacing: 6) {
                Button(action: open) {
                    HStack(spacing: 7) {
                        ZStack {
                            Circle().fill(isOn ? Color.accentColor : Color.primary.opacity(0.12))
                            Image(systemName: symbol)
                                .font(.system(size: 10.5, weight: .semibold))
                                .foregroundStyle(isOn ? Color.white : Color.secondary)
                        }
                        .frame(width: 22, height: 22)
                        Text(title).font(.system(size: 13, weight: .semibold)).lineLimit(1)
                            .fixedSize()
                        Spacer(minLength: 0)
                    }
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                // The App's own switch (§21.14): the system one turns grey
                // whenever the panel is not the active window.
                AlwaysSwitchTrack(isOn: Binding(get: { isOn }, set: toggle), width: 32, height: 19)
                    .disabled(!enabled)
                    .accessibilityLabel(title)
            }
            Button(action: open) {
                HStack(spacing: 4) {
                    if tint != .secondary { Circle().fill(tint).frame(width: 5, height: 5) }
                    Text(caption)
                        .font(.system(size: 11))
                        .frame(minWidth: 0, alignment: .leading)
                        .foregroundStyle(tint == .secondary ? Color.secondary : tint)
                        .lineLimit(1)
                        .truncationMode(.tail)
                    Spacer(minLength: 0)
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 8)
        .frame(minWidth: 0, maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 10, style: .continuous)
            .fill(Color.primary.opacity(isOn ? 0.08 : 0.045)))
        .help(help)
    }
}

/// Small icon + label button for the panel's bottom row.
private struct PanelToolButton: View {
    var title: String
    var symbol: String
    var action: () -> Void

    var body: some View {
        Button(action: action) {
            Label(title, systemImage: symbol)
                .font(.callout)
                .padding(.horizontal, 6)
                .padding(.vertical, 4)
                .contentShape(Rectangle())
        }
        .buttonStyle(.borderless)
        .foregroundStyle(.secondary)
    }
}
