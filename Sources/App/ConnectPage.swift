import SwiftUI

/// Settings → 连接 (DESIGN.md §69.14, user 2026-11-26: "可以优化成7页"):
/// when the VPN connects and what happens when it drops, in one place.
/// They were split between 通用 and the old 连接 tab, which also held the
/// live connection list (now 流量).
struct ConnectPage: View {
    @ObservedObject private var manager = HelperClient.shared
    @State private var autoConnect = ProfileStore.loadProfile().autoConnectOnLaunch
    @State private var settings = ProfileStore.loadAppSettings()
    @State private var egressDisabledWithDrop = false

    var body: some View {
        Form {
            Section {
                Toggle(isOn: Binding(
                    get: { autoConnect },
                    set: { on in
                        // The latest profile: 账号 may have changed it meanwhile.
                        var profile = ProfileStore.loadProfile()
                        profile.autoConnectOnLaunch = on
                        ProfileStore.saveProfile(profile)
                        autoConnect = on
                    })) {
                    IconLabel(title: "打开 App 时自动连接", symbol: "bolt.fill", color: SettingsTone.vpn)
                }
            } header: {
                TimelineView(.periodic(from: .now, by: 30)) { _ in
                    let look = self.look
                    PageHero(symbol: "power", color: look.color, title: "连接", status: look.line, dot: look.dot) {
                        if manager.state == .disconnected, !manager.networkHeld, manager.hasCredentials {
                            Button("连接") { _ = manager.connectWithStoredCredentials(manual: true) }
                                .buttonStyle(.borderedProminent)
                        }
                    }
                }
            }

            OnDemandSettings()

            Section {
                // Both connection ways (DESIGN.md §26.19): the Cisco
                // engine's kill switch (§21.6) and the own connection's
                // pf set and held routes.
                Toggle(isOn: Binding(
                    get: { settings.isDropProtectionOn },
                    set: { on in
                        var latest = ProfileStore.loadAppSettings()
                        latest.dropProtection = on
                        egressDisabledWithDrop = !on && latest.egressProtection?.enabled == true
                        if !on { latest.egressProtection?.enabled = false }
                        settings = latest
                        ProfileStore.saveAppSettings(settings, updatingEgress: !on)
                        HelperClient.shared.dropProtectionChanged()
                    })) {
                    IconLabel(title: "断线保护", subtitle: dropLine, symbol: "lock.fill", color: SettingsTone.vpn)
                }
                lastDrop
            } header: {
                Text("断线了怎么办")
            } footer: {
                if egressDisabledWithDrop {
                    Footnote("出口保护已关闭。自建连接需要重新连接一次才能生效。")
                }
            }
        }
        .formStyle(.grouped)
        .onAppear {
            autoConnect = ProfileStore.loadProfile().autoConnectOnLaunch
            settings = ProfileStore.loadAppSettings()
        }
    }

    /// The card's colour and line follow the panel's VPN card: green
    /// connected, red held or refused, orange on the way, neutral off.
    private var look: (line: String, color: Color, dot: Color?) {
        if manager.showsConnected {
            let since = manager.connectedSince.map { " · " + PanelView.duration(Date().timeIntervalSince($0)) } ?? ""
            return ("已连接 \(serverName)\(since)", SettingsTone.vpn, .green)
        }
        if manager.gatewayTrustFailed || manager.state == .reconnecting || manager.networkHeld {
            return (manager.stateLine, .red, .red)
        }
        if manager.loginStopped { return (manager.stateLine, .orange, .orange) }
        if manager.state == .disconnected {
            return (manager.hasCredentials ? "没有连接 · 正在用本地网络上网" : "先在「账号」页填服务器、账号和密码",
                    SettingsTone.neutral, nil)
        }
        return (manager.stateLine, .orange, .orange)
    }

    private var serverName: String {
        let profile = ProfileStore.loadProfile()
        return profile.servers.first { $0.target == profile.server }?.name ?? profile.server
    }

    private var dropLine: String {
        guard settings.isDropProtectionOn else { return "关：VPN 断开后直接用本地网络上网，后台照常重连" }
        return manager.usesCisco
            ? "VPN 断开时暂停上网，直到重新连上或你手动断开"
            : "VPN 断开时暂停上网（分流直连的网站照常），直到重新连上或你手动断开"
    }

    /// The newest drop, with the way to all of them (诊断).
    @ViewBuilder private var lastDrop: some View {
        if let drop = manager.dropHistory.last {
            LabeledContent {
                Button("全部记录") { UserDefaults.standard.set("diagnostics", forKey: "settingsTab") }
                    .buttonStyle(.borderless)
            } label: {
                IconLabel(title: "上次掉线 " + Self.when(drop.droppedAt), subtitle: drop.summary,
                          symbol: "clock.arrow.circlepath", color: SettingsTone.neutral)
            }
        } else {
            IconLabel(title: "还没有掉线记录", symbol: "clock.arrow.circlepath", color: SettingsTone.neutral)
        }
    }

    /// "今天 10:03", "昨天 23:40", "11月20日 08:15".
    static func when(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "HH:mm"
        let time = formatter.string(from: date)
        if Calendar.current.isDateInToday(date) { return "今天 " + time }
        if Calendar.current.isDateInYesterday(date) { return "昨天 " + time }
        formatter.dateFormat = "M月d日 HH:mm"
        return formatter.string(from: date)
    }
}
