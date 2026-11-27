import SwiftUI

/// Menu-bar popover: one control card with Cisco and the split's proxies,
/// each with its own switch (design C, user 2026-11-26), Cisco's three
/// options as a list, the speed, last error. The red recovery button stays
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
    /// Sample data only (the README picture): nothing of this Mac is read,
    /// no network, keychain or connection state.
    var preview: PanelPreview?
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
    @State private var siteCount = DirectSites.sites(ProfileStore.loadAppSettings()).count
    /// Other VPNs / proxies seen at panel open (§27.2).
    @State private var neighbors: [NeighborNotice] = []
    private let activityTimer = Timer.publish(every: 2, on: .main, in: .common).autoconnect()
    /// Latencies only while the panel shows them: at once, then every 2 s.
    private let healthTimer = Timer.publish(every: 1, tolerance: 0.2, on: .main, in: .common).autoconnect()
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
            controlCard
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
            options
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
            if manager.showsConnected || manager.proxyOnlyRunning {
                speedCard
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
            if !manager.helperAvailable, preview == nil {
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
                .help("上不了网、被 AlwaysConnect 卡住时：断开 Cisco，清掉 AlwaysConnect 改过的路由、DNS 和防火墙设置，回到直连")
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
                .help("断开 Cisco、恢复直连网络，并退出 AlwaysConnect")
            }
            if showConfirmQuit {
                HStack {
                    Text("退出会断开 Cisco，网络恢复直连")
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
            if let preview {
                speed.showPreview(preview.speed)
                link.showPreview(preview.link)
                return
            }
            settings = ProfileStore.loadAppSettings()
            proxyHealth.configure(settings.activeProxyRoutes)
            manager.prepareGatewayWhileDirect()
            // Also refreshes the split status (正在直连, proxied totals).
            speed.start()
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
        .onReceive(proxyHealth.$keys.dropFirst()) { _ in
            if preview == nil { settings = ProfileStore.loadAppSettings() }
        }
        .onReceive(activityTimer) { _ in manager.expireGatewayPreparation() }
        .onReceive(healthTimer) { _ in if preview == nil { checkHealth() } }
        .onChange(of: manager.showsConnected) { _ in link.reset(); checkHealth() }
        .onDisappear { speed.stop() }
    }

    /// 网速 (DESIGN.md §45.4): the VPN and the direct part side by side,
    /// only while connected; "连接详情" opens the per-connection page.
    private var speedCard: some View {
        let totals = speed.totals
        return Button { onOpenSettings("traffic") } label: {
            HStack(spacing: 10) {
                if manager.showsConnected {
                    speedColumn("Cisco", color: .green, totals?.vpn)
                    Divider().frame(height: 36)
                }
                // §69.17, §69.18: the columns are known when the panel
                // opens, from the settings, not from the first numbers
                // (user, 2026-11-26: "两个跳变成3个，这是什么鬼交互啊").
                if proxyColumnShown {
                    speedColumn("代理", color: .purple, totals.map { $0.proxy ?? [0, 0] })
                    Divider().frame(height: 36)
                }
                speedColumn("直连", color: .orange, totals?.direct)
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

    /// The 代理 column: proxies are on for this connection, or (a change
    /// the service has not applied yet) proxied bytes are still moving.
    private var proxyColumnShown: Bool {
        (!settings.activeProxyRoutes.isEmpty && (manager.ownConnection || manager.proxyOnlyRunning))
            || (speed.totals?.proxy.map { $0 != [0, 0] } ?? false)
    }

    private func speedColumn(_ title: String, color: Color, _ rate: [Int]?) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack(spacing: 5) {
                Circle().fill(color).frame(width: 6, height: 6)
                Text(title).font(.caption).foregroundStyle(.secondary)
            }
            // Down above up: three columns fit without cutting a number.
            Text("↓ " + (rate.map { PanelSpeed.text($0[0]) } ?? "…"))
                .font(.system(size: 13, weight: .semibold).monospacedDigit())
                .lineLimit(1)
                .minimumScaleFactor(0.8)
            Text("↑ " + (rate.map { PanelSpeed.text($0[1]) } ?? "…"))
                .font(.caption2.monospacedDigit())
                .foregroundStyle(.secondary)
                .lineLimit(1)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    /// The sites the split is sending direct right now, on hover.
    private var splitHelp: String {
        guard let activity = manager.splitActivity, !activity.entries.isEmpty else { return "" }
        return "正在直连：" + activity.entries.joined(separator: "、")
    }

    /// The way back when the Mac has no network because of us (DESIGN.md
    /// §24.6): always there, works offline, asks once for the Mac password.
    /// The button itself is in the bottom toolbar (§45.4); its confirm
    /// and its outcome show here.
    @ViewBuilder private var networkResetConfirm: some View {
        if showConfirmReset {
            VStack(alignment: .leading, spacing: 6) {
                Text("会断开 Cisco，并清掉 AlwaysConnect 改过的路由、DNS 和防火墙设置，回到直连。需要输入一次开机密码。")
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

    /// Options list under the control card (panel A chosen 2026-11-27, DESIGN §71):
    /// 出口保护 sits on top and stays active even when Cisco is off; 分流直连 and
    /// 断线保护 rest while Cisco is off.
    private var options: some View {
        let ciscoOn = manager.switchIsOn
        let egressResting = manager.usesCisco && manager.state != .disconnected
        return VStack(alignment: .leading, spacing: 5) {
            VStack(spacing: 0) {
                egressRow(resting: egressResting)
                Divider().padding(.leading, 41)
                directRow(resting: !ciscoOn)
                Divider().padding(.leading, 41)
                dropRow(resting: !ciscoOn)
            }
            .background(RoundedRectangle(cornerRadius: 10, style: .continuous).fill(Color.primary.opacity(0.045)))
            if !ciscoOn {
                Text("分流直连和断线保护跟着 Cisco，连上后生效")
                    .font(.system(size: 11)).foregroundStyle(.secondary)
                    .padding(.leading, 4)
            }
        }
    }

    /// Cisco and the split's proxies, one card, two rows, two switches
    /// (design C, user 2026-11-26: "c"; line version: "线条版"). Neutral
    /// card; the state lines carry the colour.
    private var controlCard: some View {
        VStack(spacing: 0) {
            ciscoRow
            Divider().padding(.leading, 57)
            proxyRow
        }
        .background(RoundedRectangle(cornerRadius: 14, style: .continuous).fill(Color.primary.opacity(0.06)))
        .overlay(RoundedRectangle(cornerRadius: 14, style: .continuous)
            .stroke(cardAlarm ? Color.red.opacity(0.45) : Color.primary.opacity(0.10), lineWidth: 1))
    }

    /// Held, dropped or refused: the card's edge says it too.
    private var cardAlarm: Bool {
        manager.gatewayTrustFailed || manager.state == .reconnecting || manager.networkHeld
    }

    /// Cisco: the globe and the server menu on the left, the state under
    /// the server's name, the switch on the right (§69.9).
    private var ciscoRow: some View {
        let header = PanelStatusHeader(client: manager, subtitle: subtitle)
        let red = cardAlarm
        let (caption, tint): (String, Color) = {
            if manager.showsConnected {
                switch link.state {
                case .ok(let ms): return ("Cisco 已连接 · \(ms) ms", .green)
                case .slow(let ms): return ("Cisco 已连接 · 网络慢 \(ms) ms", .orange)
                case .down: return ("Cisco 已连接 · 网络不通", .red)
                case .unknown: return ("Cisco 已连接", .green)
                }
            }
            if manager.loginStopped { return (header.subtitle, .orange) }
            let tint: Color = red ? .red : (manager.state == .disconnected ? .secondary : .orange)
            if manager.state == .disconnected && !red {
                return (manager.hasCredentials ? "Cisco 未连接" : header.subtitle, tint)
            }
            return (header.look.headline + (header.subtitle.isEmpty ? "" : " · " + header.subtitle), tint)
        }()
        let since = manager.connectedSince.map { "已连接 " + Self.duration(Date().timeIntervalSince($0)) }
        return HStack(spacing: 11) {
            Image(nsImage: GlobeIcon.image(header.badge, size: 30))
                .frame(width: 32, height: 32)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
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
                    // One Text: a menu label puts a separate image first.
                    (Text(servers.first { $0.target == selectedServer }?.name ?? (selectedServer.isEmpty ? "服务器" : selectedServer))
                        .font(.system(size: 16, weight: .semibold))
                     + Text("  ") + Text(Image(systemName: "chevron.down"))
                        .font(.system(size: 10, weight: .bold))
                        .foregroundColor(.secondary))
                        .lineLimit(1)
                }
                .menuStyle(.borderlessButton)
                .menuIndicator(.hidden)
                .fixedSize()
                .help("切换服务器")
                stateLine(caption, tint, lines: manager.gatewayTrustFailed ? 4 : 2)
                    .help(manager.showsConnected ? (since ?? "") + "\n上网检测：面板开着时每 2 秒试着打开几个常用网址，取最快的应答" : "")
            }
            Spacer(minLength: 8)
            AlwaysSwitchTrack(isOn: Binding(get: { manager.switchIsOn && !manager.loginStopped }, set: { on in
                if on {
                    showConfirmDisconnect = false
                    if manager.hasCredentials { onStart() } else { onOpenSettings("credentials") }
                } else if red {
                    onStop()  // never trapped: no confirm (§24.6)
                } else {
                    showConfirmDisconnect = true
                }
            }), width: 42, height: 25)
            .accessibilityLabel("Cisco")
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 11)
    }

    /// The split's proxies, on whether Cisco is connected or not (§69.20).
    private var proxyRow: some View {
        let all = (settings.proxyRoutes ?? []).filter { $0.enabled && !$0.sites.isEmpty }
        let on = settings.proxiesOn && !all.isEmpty
        let (caption, tint): (String, Color) = {
            if all.isEmpty { return ((settings.proxyRoutes ?? []).isEmpty ? "未添加，点这里添加" : "未启用", .secondary) }
            if !settings.proxiesOn { return ("关", .secondary) }
            if manager.usesCisco && manager.state != .disconnected { return ("Cisco 连着时由 Cisco 管，断开后恢复", .secondary) }
            if let error = manager.proxyOnlyError { return (error, .orange) }
            let ownSplit = !manager.usesCisco && manager.showsConnected
            guard manager.proxyOnlyRunning || ownSplit else {
                return (manager.state == .disconnected ? "正在启用…" : "Cisco 连上后接着用", .secondary)
            }
            let summary = proxyHealth.summary(all)
            let color: Color = summary.level == .ok ? .green : summary.level == .warn ? .orange : summary.level == .fail ? .red : .secondary
            return ((all.count > 1 ? "\(all.count) 个代理 · " : "") + summary.text, color)
        }()
        return HStack(spacing: 11) {
            ProxyMark(on: on)
                .frame(width: 32, height: 32)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                Menu {
                    ForEach(all) { route in
                        Button("\(route.name)：" + (proxyHealth.checks[route.id].map { $0.level == .ok ? $0.short : $0.text } ?? "未检测")) {
                            onOpenSettings("proxy")
                        }
                    }
                    if !all.isEmpty { Divider() }
                    Button("管理代理…") { onOpenSettings("proxy") }
                } label: {
                    (Text("分流代理").font(.system(size: 16, weight: .semibold))
                     + Text("  ") + Text(Image(systemName: "chevron.down"))
                        .font(.system(size: 10, weight: .bold))
                        .foregroundColor(.secondary))
                        .lineLimit(1)
                }
                .menuStyle(.borderlessButton)
                .menuIndicator(.hidden)
                .fixedSize()
                .help("哪些网站经代理、每个代理现在怎样")
                stateLine(caption, tint, lines: 2)
                    .help(proxyHelp(all))
            }
            Spacer(minLength: 8)
            AlwaysSwitchTrack(isOn: Binding(get: { on }, set: { turnOn in
                if all.isEmpty { onOpenSettings("proxy"); return }
                var stored = ProfileStore.loadAppSettings()
                stored.proxiesPaused = turnOn ? nil : true
                ProfileStore.saveAppSettings(stored)
                settings = stored
                manager.syncProxyOnly()
                if turnOn { proxyHealth.check(all, force: true) }
            }), width: 42, height: 25)
            .accessibilityLabel("分流代理")
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 11)
    }

    private func stateLine(_ caption: String, _ tint: Color, lines: Int) -> some View {
        let neutral = tint == .secondary
        return HStack(alignment: .firstTextBaseline, spacing: 5) {
            Circle().fill(neutral ? Color.secondary.opacity(0.6) : tint).frame(width: 6, height: 6)
            Text(caption)
                .font(.system(size: 11.5))
                .foregroundStyle(neutral ? Color.secondary : tint)
                .lineLimit(lines)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    /// 分流直连: the 不走 Cisco list on or resting, live (§69.9).
    private func directRow(resting: Bool) -> some View {
        let own = manager.ownConnection
        let on = own && settings.directOn
        let (caption, tint): (String, Color) = {
            if !own { return ("要开按网站分流", .secondary) }
            if !settings.directOn { return ("关 · 都走 Cisco", .secondary) }
            if siteCount == 0 { return ("名单是空的", .secondary) }
            if manager.showsConnected, let activity = manager.splitActivity, !activity.entries.isEmpty {
                return ("\(activity.entries.count) 个网站正在直连", .green)
            }
            return ("\(siteCount) 条不走 Cisco", .secondary)
        }()
        return PanelOptionRow(symbol: "arrow.turn.up.right", title: "分流直连", caption: caption, tint: tint, isOn: on,
                              enabled: own, resting: resting, help: splitHelp) { turnOn in
            var stored = ProfileStore.loadAppSettings()
            stored.directPaused = turnOn ? nil : true
            ProfileStore.saveAppSettings(stored)
            settings = stored
            DirectList.pushNetworks()
            if !manager.usesCisco { manager.pushDirectDomains() }
        } open: { onOpenSettings("split") }
    }

    /// Each proxy and its state, on hover.
    private func proxyHelp(_ routes: [ProxyRoute]) -> String {
        routes.map { route in
            let check = proxyHealth.checks[route.id]
            return "\(route.name)：" + (check.map { $0.level == .ok ? $0.short : $0.text } ?? "未检测")
        }.joined(separator: "\n")
    }

    private func egressRow(resting: Bool) -> some View {
        let config = settings.egressProtection ?? EgressProtection()
        let available = protectionOn && (!manager.usesCisco || manager.state == .disconnected)
        let activeCount = config.groups.filter(\.enabled).count
        let (caption, tint): (String, Color) = {
            if config.groups.isEmpty { return ("未设置", .secondary) }
            if manager.usesCisco && manager.state != .disconnected { return ("经 Cisco 客户端时暂不可用", .secondary) }
            if !protectionOn { return ("要先开断线保护", .secondary) }
            guard config.isActive else { return ("关", .secondary) }
            guard let line = manager.egressLine, !manager.gatewayTrustFailed else {
                return (activeCount > 0 ? "\(activeCount) 组保护中" : "开", .secondary)
            }
            switch manager.egressLevel {
            case .ok: return (line, .green)
            case .partial: return (line, .orange)
            case .unknown: return (line, .secondary)
            }
        }()
        return PanelOptionRow(symbol: "checkmark.shield.fill", title: "出口保护", caption: caption, tint: tint,
                              activeColor: SettingsTone.shield,
                              isOn: config.isActive && available, enabled: available || config.groups.isEmpty,
                              resting: resting, help: (manager.egressLine ?? "Cisco 关闭时也保护")) { on in
            if config.groups.isEmpty { onOpenSettings("egress"); return }
            setEgress(on: on)
        } open: { onOpenSettings("egress") }
    }

    private func dropRow(resting: Bool) -> some View {
        PanelOptionRow(symbol: protectionOn ? "lock.fill" : "lock.open.fill", title: "断线保护",
                       caption: protectionOn ? "掉线时暂停上网" : "关 · 掉线走本地网络",
                       tint: .secondary, isOn: protectionOn, resting: resting,
                       help: protectionOn ? "掉线时暂停上网，不漏走直连" : "掉线时改走本地网络") { on in
            protectionOn = on
            var stored = ProfileStore.loadAppSettings()
            stored.dropProtection = on
            egressDisabledWithDrop = !on && stored.egressProtection?.enabled == true
            if !on { stored.egressProtection?.enabled = false }
            ProfileStore.saveAppSettings(stored, updatingEgress: !on)
            settings = ProfileStore.loadAppSettings()
            manager.dropProtectionChanged()
        } open: { onOpenSettings("connect") }
    }

    /// While the panel is open: the VPN's answer time and each proxy's, at
    /// once and then every 2 s (§69.8, §69.16). Nothing runs once it closes.
    private func checkHealth() {
        if manager.showsConnected { link.checkIfDue() }
        let proxiesActive = manager.proxyOnlyRunning || (manager.showsConnected && manager.ownConnection)
        if proxiesActive, settings.proxiesOn {
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
        if manager.state == .disconnected, !manager.networkHeld { return "Cisco 已关，正在用本地网络上网" }
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
                Text("断开 Cisco，恢复直连网络").frame(maxWidth: .infinity)
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
                Text(manager.onDemandPaused ? "仍然连接" : "连接 Cisco").frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
        } else {
            Button { showConfirmDisconnect = true } label: {
                Text(manager.showsConnected ? "断开 Cisco" : "取消连接").frame(maxWidth: .infinity)
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
        UpdateChecker.shared.checkOnPanelOpen()
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

/// What the README picture shows (offscreen render, sample data only).
struct PanelPreview {
    var speed: PanelSpeed.Totals
    var link: LinkCheck.State
}

/// One of Cisco's options in the panel's list (design C): icon, name, the
/// state, the switch. Resting (Cisco off): the name only, greyed; the list
/// says once that these come with Cisco. Clicking the words opens that
/// page of Settings.
struct PanelOptionRow: View {
    var symbol: String
    var title: String
    var caption: String
    var tint: Color = .secondary
    var activeColor: Color = .accentColor
    var isOn: Bool
    var enabled = true
    var resting = false
    var help = ""
    var toggle: (Bool) -> Void
    var open: () -> Void

    var body: some View {
        let lit = isOn && !resting
        HStack(spacing: 9) {
            Button(action: open) {
                HStack(spacing: 9) {
                    ZStack {
                        Circle().fill(lit ? activeColor : Color.primary.opacity(0.10))
                        Image(systemName: symbol)
                            .font(.system(size: 10.5, weight: .semibold))
                            .foregroundStyle(lit ? Color.white : Color.secondary)
                    }
                    .frame(width: 22, height: 22)
                    Text(title).font(.system(size: 13, weight: .semibold))
                        .foregroundStyle(resting ? Color.secondary : Color.primary)
                        .lineLimit(1).fixedSize()
                    Spacer(minLength: 6)
                    if !resting {
                        HStack(spacing: 4) {
                            if tint != .secondary { Circle().fill(tint).frame(width: 5, height: 5) }
                            Text(caption)
                                .font(.system(size: 11))
                                .foregroundStyle(tint == .secondary ? Color.secondary : tint)
                                .lineLimit(1)
                                .truncationMode(.tail)
                        }
                    }
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            if !resting {
                // The App's own switch (§21.14): the system one turns grey
                // whenever the panel is not the active window.
                AlwaysSwitchTrack(isOn: Binding(get: { isOn }, set: toggle), width: 32, height: 19)
                    .disabled(!enabled)
                    .accessibilityLabel(title)
            }
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 7)
        .frame(minHeight: 35)
        .help(help)
    }
}

/// The proxies' mark, drawn like the globe (user, 2026-11-26: "线条版"):
/// label-coloured line art, half strength while off.
struct ProxyMark: View {
    var on: Bool
    var body: some View {
        ZStack {
            Circle().stroke(Color.primary.opacity(on ? 0.85 : 0.45), lineWidth: 1.6)
            Image(systemName: "arrow.triangle.swap")
                .font(.system(size: 12.8, weight: .regular))
                .foregroundStyle(Color.primary.opacity(on ? 0.9 : 0.45))
        }
        .frame(width: 28, height: 28)
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
