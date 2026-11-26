import SwiftUI

/// 分流代理 on its own (offscreen screenshots); in the App it is a part
/// of the 分流 page (§69.9).
struct ProxyPage: View {
    var previewRoutes: [ProxyRoute]? = nil
    var previewSplitOn = true

    var body: some View {
        Form { ProxySections(splitOn: previewSplitOn, previewRoutes: previewRoutes) }
            .formStyle(.grouped)
    }
}

/// 分流代理 (DESIGN.md §六十九, UI-DESIGN.md): sites that go through the
/// user's own SOCKS5 or HTTP proxy. Each proxy is an address and a rule
/// box in the split list's syntax; the first proxy whose rules match a
/// site takes it, before 分流直连. Sections of the 分流 page.
struct ProxySections: View {
    @ObservedObject private var health = ProxyHealth.shared
    @State private var routes: [ProxyRoute]
    @State private var paused: Bool
    @State private var editing: ProxyRoute?
    @State private var note: String?
    private let preview: Bool
    private let splitOn: Bool
    private let onSave: (AppSettings) -> Void
    /// Read once (it hashes two binaries): an older service ignores proxies.
    @State private var serviceTooOld: Bool

    init(splitOn: Bool, previewRoutes: [ProxyRoute]? = nil, onSave: @escaping (AppSettings) -> Void = { _ in }) {
        let settings = previewRoutes == nil ? ProfileStore.loadAppSettings() : AppSettings()
        _routes = State(initialValue: previewRoutes ?? settings.proxyRoutes ?? [])
        preview = previewRoutes != nil
        _paused = State(initialValue: previewRoutes == nil && !settings.proxiesOn)
        self.splitOn = splitOn
        self.onSave = onSave
        _serviceTooOld = State(initialValue: previewRoutes == nil && HelperInstaller.installedHelperOutdated)
    }


    var body: some View {
        Group {
            Section {
                if !splitOn {
                    EgressCallout(icon: "info.circle.fill", tint: .blue,
                                  text: "经 Cisco 客户端连接时，连着的期间由 Cisco 决定流量去向，代理暂停。",
                                  caption: "Cisco 断开后代理照常生效：命中规则的网站走代理，其余走本地网络。") { EmptyView() }
                }
                if paused {
                    EgressCallout(icon: "pause.circle.fill", tint: .orange,
                                  text: "分流代理已在菜单栏面板上关闭。",
                                  caption: "关闭期间这些网站照常按分流名单走 VPN 或直连。") {
                        Button("打开") {
                            var stored = ProfileStore.loadAppSettings()
                            stored.proxiesPaused = nil
                            ProfileStore.saveAppSettings(stored)
                            paused = false
                            save()
                        }
                    }
                }
                if serviceTooOld && routes.contains(where: \.enabled) {
                    EgressCallout(icon: "exclamationmark.triangle.fill", tint: .orange,
                                  text: "后台服务需要更新，代理才会生效。",
                                  caption: "更新之前，这些网站照常走 VPN，不会走直连。") { EmptyView() }
                }
                if let note {
                    EgressCallout(icon: "exclamationmark.triangle.fill", tint: .orange, text: note) {
                        Button("知道了") { self.note = nil }
                    }
                }
                if routes.isEmpty {
                    EmptyGuide(symbol: "server.rack", color: SettingsTone.proxy, title: "还没有代理",
                               text: "粘贴一行代理地址，再写上哪些网站经它访问。") {
                        Button("添加第一个代理") { addProxy() }
                            .buttonStyle(.borderedProminent)
                    }
                } else {
                    ForEach(Array(routes.enumerated()), id: \.element.id) { index, route in row(route, index: index) }
                }
            } header: {
                HStack(spacing: 6) {
                    Text("经代理访问的网站")
                    HoverHelp(action: {}) { explanation }
                    Spacer()
                    Button(action: addProxy) { Label("添加代理", systemImage: "plus") }
                        .buttonStyle(.borderless)
                }
            } footer: {
                Footnote("命中规则的网站经你的 SOCKS5 / HTTP 代理访问；代理不通时直接打不开，不会改走别的路。"
                         + (routes.count > 1 ? "几个代理都命中同一个网站时，用排在前面的。" : ""))
            }
        }
        .onAppear { if !preview { health.check(routes) } }
        .sheet(item: $editing) { route in
            ProxyEditor(route: route, isNew: !routes.contains(where: { $0.id == route.id }),
                        cancel: { editing = nil }) { saved in
                editing = nil
                if let index = routes.firstIndex(where: { $0.id == saved.id }) { routes[index] = saved } else { routes.append(saved) }
                save()
            }
        }
    }

    private func addProxy() {
        editing = ProxyRoute(name: "", kind: .socks5, host: "", port: 0, sites: [])
    }

    private var explanation: some View {
        VStack(alignment: .leading, spacing: 6) {
            ForEach([
                "域名、网站清单规则：查 DNS 之前就交给代理，域名由代理解析，排在「不走 Cisco 的网站」之前。",
                "geoip、网段规则：按 DNS 答复的地址判断（连着 Cisco 时问 Cisco 的 DNS，否则问本地网络的）；直接写的网段，连 IP 也走代理。",
                "TCP 两种代理都转发；UDP（如 QUIC）只经 SOCKS5，HTTP 代理的网站浏览器会自动改用 TCP。",
                "连代理本身按分流名单走：在局域网或「不走 Cisco 的网站」里就走本地网络，否则经 Cisco；Cisco 没连时一律走本地网络。",
                "Cisco 没连时代理照样生效（只开代理）：命中规则的网站走代理，其余走本地网络。",
                "代理连不上、拒绝或密码不对：这些网站直接打不开，不会改走直连或 Cisco。",
            ], id: \.self) { line in
                Text("• " + line).fixedSize(horizontal: false, vertical: true)
            }
        }
        .font(.callout)
        .frame(width: 380, alignment: .leading)
        .padding(12)
    }

    private func row(_ route: ProxyRoute, index: Int) -> some View {
        HStack(spacing: 12) {
            IconTile(symbol: route.kind == .socks5 ? "point.3.connected.trianglepath.dotted" : "globe",
                     color: route.enabled ? SettingsTone.proxy : SettingsTone.neutral)
            VStack(alignment: .leading, spacing: 2) {
                Text(route.name).font(.body.weight(.medium)).lineLimit(1)
                Text(ProxyLink.display(route).replacingOccurrences(of: "://", with: " · "))
                    .font(.system(.caption, design: .monospaced)).foregroundStyle(.secondary).lineLimit(1)
                ProxyStatusLine(route: route, check: health.checks[route.id], checking: health.checking.contains(route.id))
            }
            Spacer(minLength: 8)
            Text("\(route.sites.count) 条规则")
                .font(.caption).foregroundStyle(.secondary)
                .padding(.horizontal, 8).padding(.vertical, 3)
                .background(Capsule().fill(Color.secondary.opacity(0.12)))
            Toggle("", isOn: Binding(
                get: { route.enabled },
                set: { on in
                    guard let i = routes.firstIndex(where: { $0.id == route.id }) else { return }
                    routes[i].enabled = on
                    save()
                    if on && !preview { health.check([routes[i]], force: true) }
                }))
                .labelsHidden()
                .fixedSize()
                .accessibilityLabel("启用 \(route.name)")
            Menu {
                Button("编辑…") { editing = route }
                if route.enabled { Button("重新检测") { health.check([route], force: true) } }
                if index > 0 { Button("排到前面") { move(route, by: -1) } }
                if index < routes.count - 1 { Button("排到后面") { move(route, by: 1) } }
                Divider()
                Button("删除", role: .destructive) {
                    routes.removeAll { $0.id == route.id }
                    health.forget(route.id)
                    if !preview { ProxyPasswords.delete(for: route) }
                    save()
                }
            } label: { Image(systemName: "ellipsis.circle") }
            .menuStyle(.borderlessButton)
            .menuIndicator(.hidden)
            .fixedSize()
        }
        .padding(.vertical, 4)
        .contentShape(Rectangle())
        .onTapGesture(count: 2) { editing = route }
    }

    private func move(_ route: ProxyRoute, by offset: Int) {
        guard let index = routes.firstIndex(where: { $0.id == route.id }) else { return }
        let target = index + offset
        guard routes.indices.contains(target) else { return }
        routes.swapAt(index, target)
        save()
    }

    private func save() {
        guard !preview else { return }
        var stored = ProfileStore.loadAppSettings()
        stored.proxyRoutes = routes
        ProfileStore.saveAppSettings(stored)
        onSave(stored)
        if !HelperClient.shared.usesCisco {
            HelperClient.shared.pushDirectDomains { taken in
                note = taken == nil ? "已保存；后台服务没有回应，更新后台服务后生效。" : nil
            }
        }
    }
}

/// One proxy: its address as one line (parsed here, ProxyLink), an
/// optional name and its rule box, saved on 完成.
struct ProxyEditor: View {
    let isNew: Bool
    let cancel: () -> Void
    let done: (ProxyRoute) -> Void
    private let original: ProxyRoute
    @State private var link: String
    @State private var name: String
    @State private var rules: String
    /// The check made on 完成, for the address and rules it was made with.
    @State private var result: (key: String, check: ProxyCheck)?
    @State private var checkingNow = false

    /// `previewCheck`: a check result shown as if just made (screenshots).
    init(route: ProxyRoute, isNew: Bool, previewCheck: ProxyCheck? = nil,
         cancel: @escaping () -> Void, done: @escaping (ProxyRoute) -> Void) {
        self.isNew = isNew
        self.cancel = cancel
        self.done = done
        original = route
        let link = isNew ? "" : ProxyLink.display(route)
        let rules = route.sites.joined(separator: "\n")
        _link = State(initialValue: link)
        _name = State(initialValue: isNew ? "" : route.name)
        _rules = State(initialValue: rules)
        _result = State(initialValue: previewCheck.map { (link + "\u{0}" + rules, $0) })
    }

    private var parsed: ProxyLink.Parsed { ProxyLink.parse(link) }
    private var rulesParsed: ProxyRuleInput { ProxyRuleInput(rules) }
    /// A saved password is kept when the line names the same user without one.
    private var keepsPassword: Bool {
        guard let l = parsed.link, l.password == nil, let user = l.username else { return false }
        return original.passwordStamp != nil && original.username == user
    }
    private var checkKey: String { link + "\u{0}" + rules }
    /// A failed check shown for what is typed now: 完成 saves anyway.
    private var overriding: Bool { result.map { $0.key == checkKey && $0.check.level != .ok } ?? false }
    private var canSave: Bool {
        guard let l = parsed.link, rulesParsed.issues.isEmpty, !rulesParsed.sites.isEmpty else { return false }
        return l.username == nil || l.password != nil || keepsPassword
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            Text(isNew ? "添加代理" : "编辑代理").font(.title3.weight(.semibold))

            VStack(alignment: .leading, spacing: 6) {
                Text("代理地址").font(.callout.weight(.medium))
                TextField("", text: $link, prompt: Text("socks5://用户名:密码@1.2.3.4:1080"))
                    .textFieldStyle(.roundedBorder)
                    .font(.system(.body, design: .monospaced))
                status
            }

            VStack(alignment: .leading, spacing: 6) {
                Text("名称").font(.callout.weight(.medium))
                TextField("", text: $name, prompt: Text(parsed.link.map { $0.name ?? "\($0.host):\($0.port)" } ?? "可不填"))
                    .textFieldStyle(.roundedBorder)
            }

            VStack(alignment: .leading, spacing: 6) {
                Text("经这个代理访问的网站").font(.callout.weight(.medium))
                EgressRuleText(input: $rules, height: 140)
                EgressRuleIssues(issues: rulesParsed.issues)
            }

            checkView

            HStack {
                Spacer()
                Button("取消", action: cancel).keyboardShortcut(.cancelAction)
                Button(overriding ? "仍然保存" : "完成", action: save)
                    .keyboardShortcut(.defaultAction)
                    .buttonStyle(.borderedProminent)
                    .tint(overriding ? .orange : nil)
                    .disabled(!canSave || checkingNow)
            }
        }
        .padding(24)
        .frame(width: 520)
    }

    @ViewBuilder private var status: some View {
        switch parsed {
        case .link(let l):
            let missingPassword = l.username != nil && l.password == nil && !keepsPassword
            Label(missingPassword ? "\(l.summary)，还缺密码：写成 用户名:密码@地址" : l.summary + (keepsPassword ? "，沿用已存的密码" : ""),
                  systemImage: missingPassword ? "exclamationmark.triangle.fill" : "checkmark.circle.fill")
                .font(.caption)
                .foregroundStyle(missingPassword ? Color.orange : Color.green)
        case .problem(let problem):
            if link.trimmingCharacters(in: .whitespaces).isEmpty {
                Text("支持 socks5://、http://、主机:端口，也可粘贴 socks5, 1.2.3.4, 1080, 用户名, 密码 这种逗号写法")
                    .font(.caption).foregroundStyle(.secondary)
            } else {
                Label(problem, systemImage: "exclamationmark.triangle.fill").font(.caption).foregroundStyle(.orange)
            }
        }
    }

    /// Under the rules: the check 完成 runs before saving (§69.8).
    @ViewBuilder private var checkView: some View {
        if checkingNow {
            HStack(spacing: 8) {
                ProgressView().controlSize(.small)
                Text("正在检测：连代理、核对密码、试着经它打开规则里的网站…").font(.caption).foregroundStyle(.secondary)
            }
        } else if let result, result.key == checkKey {
            let check = result.check
            let tint: Color = check.level == .ok ? .green : (check.level == .warn ? .orange : .red)
            VStack(alignment: .leading, spacing: 3) {
                Label(check.short, systemImage: check.level == .ok ? "checkmark.circle.fill" : "exclamationmark.triangle.fill")
                    .font(.callout.weight(.medium)).foregroundStyle(tint)
                Text(check.text).font(.caption).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                if check.level != .ok {
                    Text(check.level == .fail
                         ? "这样保存的话，规则里的网站会打不开（不会改走别的路）。改好地址再点「完成」会重新检测。"
                         : "代理本身能用。如果这个网站本来就打不开，可以照样保存。")
                        .font(.caption).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
    }

    private func candidate(_ l: ProxyLink) -> ProxyRoute {
        var saved = original
        saved.kind = l.kind
        saved.host = l.host
        saved.port = l.port
        saved.sites = rulesParsed.sites
        let typedName = name.trimmingCharacters(in: .whitespaces)
        saved.name = !typedName.isEmpty ? typedName : (l.name ?? "\(l.host):\(l.port)")
        saved.username = l.username
        return saved
    }

    /// 完成 checks first; saves at once when the proxy works, otherwise
    /// shows why and turns into 仍然保存.
    private func save() {
        guard let l = parsed.link, canSave, !checkingNow else { return }
        if overriding { commit(l, check: result?.check); return }
        let route = candidate(l)
        let password = l.password ?? (keepsPassword ? ProxyPasswords.password(for: original) : nil)
        let key = checkKey
        checkingNow = true
        DispatchQueue.global(qos: .userInitiated).async {
            let check = ProxyCheck.run(route, password: password)
            DispatchQueue.main.async {
                checkingNow = false
                result = (key, check)
                if check.level == .ok, key == checkKey { commit(l, check: check) }
            }
        }
    }

    private func commit(_ l: ProxyLink, check: ProxyCheck?) {
        var saved = candidate(l)
        if l.username == nil {
            ProxyPasswords.delete(for: saved)
            saved.passwordStamp = nil
        } else if let password = l.password {
            // Only a stamp goes into the settings; the password into the keychain.
            saved.passwordStamp = ProxyPasswords.save(password, for: saved) ? UUID().uuidString : nil
        }
        if let check { ProxyHealth.shared.record(check, for: saved.id) }
        done(saved)
    }
}

/// A proxy's rule box, read like the exit protection's (one rule per
/// line, comments allowed, pasted Clash lines normalized).
struct ProxyRuleInput {
    static let siteLimit = 512

    var sites: [String] = []
    var issues: [EgressRuleInput.Issue] = []

    init(_ input: String) {
        var seen = Set<String>()
        for (index, raw) in input.split(omittingEmptySubsequences: false, whereSeparator: \.isNewline).enumerated() {
            let text = raw.trimmingCharacters(in: .whitespaces)
            guard !text.isEmpty, !text.hasPrefix("#"), !text.hasPrefix("//") else { continue }
            guard let rule = ListRule.parse(text) else {
                issues.append(.init(id: index + 1, message: ListRule.problem(text) ?? "写法无效"))
                continue
            }
            if seen.insert(rule.text).inserted { sites.append(rule.text) }
        }
        if sites.count > Self.siteLimit { issues.append(.init(id: 0, message: "最多 \(Self.siteLimit) 条")) }
    }
}

/// A proxy's state under its address: a dot and a short line.
struct ProxyStatusLine: View {
    let route: ProxyRoute
    let check: ProxyCheck?
    let checking: Bool

    var body: some View {
        let (text, tint): (String, Color) = {
            if !route.enabled { return ("已停用", .secondary) }
            if checking && check == nil { return ("检测中…", .secondary) }
            guard let check else { return ("未检测", .secondary) }
            switch check.level {
            case .ok: return (check.short, .green)
            case .warn: return (check.short, .orange)
            case .fail: return (check.short, .red)
            }
        }()
        HStack(spacing: 5) {
            Circle().fill(tint).frame(width: 6, height: 6)
            Text(text).font(.caption).foregroundStyle(tint == .secondary ? Color.secondary : tint)
                .lineLimit(1).truncationMode(.tail)
            if checking && check != nil { ProgressView().controlSize(.mini) }
        }
        .help(check.map { $0.text + ($0.fromTraffic ? "（来自实际连接）" : "") } ?? "")
    }
}
