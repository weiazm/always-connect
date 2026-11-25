import SwiftUI

/// 代理 (DESIGN.md §六十九, UI-DESIGN.md): sites that go through the
/// user's own SOCKS5 or HTTP proxy. Each proxy is an address and a rule
/// box in the split list's syntax; the first proxy whose rules match a
/// site takes it, before the 不走 VPN list.
struct ProxyPage: View {
    @ObservedObject private var manager = HelperClient.shared
    @State private var routes: [ProxyRoute]
    @State private var editing: ProxyRoute?
    @State private var note: String?
    private let preview: Bool
    private var splitOn: Bool
    /// Read once (it hashes two binaries): an older service ignores proxies.
    @State private var serviceTooOld: Bool

    init(previewRoutes: [ProxyRoute]? = nil, previewSplitOn: Bool = true) {
        let settings = ProfileStore.loadAppSettings()
        _routes = State(initialValue: previewRoutes ?? settings.proxyRoutes ?? [])
        preview = previewRoutes != nil
        splitOn = previewRoutes != nil ? previewSplitOn : settings.splitOn
        _serviceTooOld = State(initialValue: previewRoutes == nil && HelperInstaller.installedHelperOutdated)
    }


    var body: some View {
        Form {
            Section {
                HStack(alignment: .center, spacing: 12) {
                    VStack(alignment: .leading, spacing: 3) {
                        HStack(spacing: 6) {
                            Text("经代理访问的网站").font(.headline)
                            HoverHelp(action: {}) { explanation }
                        }
                        Text("命中规则的网站经你的 SOCKS5 / HTTP 代理访问；代理不通时直接打不开，不会改走别的路。")
                            .font(.caption).foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    Spacer(minLength: 12)
                    Button {
                        editing = ProxyRoute(name: "", kind: .socks5, host: "", port: 0, sites: [])
                    } label: { Label("添加代理", systemImage: "plus") }
                    .controlSize(.large)
                }
                if !splitOn {
                    EgressCallout(icon: "info.circle.fill", tint: .blue,
                                  text: "代理只在「按网站分流」开启时生效。",
                                  caption: "经 Cisco 连接时由 Cisco 决定流量去向，这里的规则不起作用。") {
                        Button("去「分流」打开") { UserDefaults.standard.set("split", forKey: "settingsTab") }
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
            }
            Section {
                if routes.isEmpty {
                    VStack(spacing: 8) {
                        Image(systemName: "arrow.triangle.swap").font(.system(size: 28)).foregroundStyle(.secondary)
                        Text("还没有代理").font(.body.weight(.medium))
                        Text("点「添加代理」，粘贴一行代理地址，再写上哪些网站经它访问。")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 28)
                } else {
                    ForEach(Array(routes.enumerated()), id: \.element.id) { index, route in row(route, index: index) }
                }
            } footer: {
                if routes.count > 1 {
                    Text("几个代理都命中同一个网站时，用排在前面的。").font(.caption).foregroundStyle(.secondary)
                }
            }
        }
        .formStyle(.grouped)
        .sheet(item: $editing) { route in
            ProxyEditor(route: route, isNew: !routes.contains(where: { $0.id == route.id }),
                        cancel: { editing = nil }) { saved in
                editing = nil
                if let index = routes.firstIndex(where: { $0.id == saved.id }) { routes[index] = saved } else { routes.append(saved) }
                save()
            }
        }
    }

    private var explanation: some View {
        VStack(alignment: .leading, spacing: 6) {
            ForEach([
                "域名、网站清单规则：查 DNS 之前就交给代理，域名由代理解析，排在「不走 VPN 的网站」之前。",
                "geoip、网段规则：按 VPN 的 DNS 答复地址判断；直接写的网段，连 IP 也走代理。",
                "TCP 两种代理都转发；UDP（如 QUIC）只经 SOCKS5，HTTP 代理的网站浏览器会自动改用 TCP。",
                "连代理本身按分流名单走：在局域网或「不走 VPN 的网站」里就走本地网络，否则经 VPN。",
                "代理连不上、拒绝或密码不对：这些网站直接打不开，不会改走直连或 VPN。",
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
            Image(systemName: route.kind == .socks5 ? "point.3.connected.trianglepath.dotted" : "globe")
                .font(.system(size: 16))
                .foregroundStyle(route.enabled ? Color.accentColor : Color.secondary)
                .frame(width: 22)
            VStack(alignment: .leading, spacing: 2) {
                Text(route.name).font(.body.weight(.medium)).lineLimit(1)
                Text(ProxyLink.display(route).replacingOccurrences(of: "://", with: " · "))
                    .font(.system(.caption, design: .monospaced)).foregroundStyle(.secondary).lineLimit(1)
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
                }))
                .labelsHidden()
                .toggleStyle(.switch)
                .controlSize(.small)
                .accessibilityLabel("启用 \(route.name)")
            Menu {
                Button("编辑…") { editing = route }
                if index > 0 { Button("排到前面") { move(route, by: -1) } }
                if index < routes.count - 1 { Button("排到后面") { move(route, by: 1) } }
                Divider()
                Button("删除", role: .destructive) {
                    routes.removeAll { $0.id == route.id }
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

    init(route: ProxyRoute, isNew: Bool, cancel: @escaping () -> Void, done: @escaping (ProxyRoute) -> Void) {
        self.isNew = isNew
        self.cancel = cancel
        self.done = done
        original = route
        _link = State(initialValue: isNew ? "" : ProxyLink.display(route))
        _name = State(initialValue: isNew ? "" : route.name)
        _rules = State(initialValue: route.sites.joined(separator: "\n"))
    }

    private var parsed: ProxyLink.Parsed { ProxyLink.parse(link) }
    private var rulesParsed: ProxyRuleInput { ProxyRuleInput(rules) }
    /// A saved password is kept when the line names the same user without one.
    private var keepsPassword: Bool {
        guard let l = parsed.link, l.password == nil, let user = l.username else { return false }
        return original.passwordStamp != nil && original.username == user
    }
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

            HStack {
                Spacer()
                Button("取消", action: cancel).keyboardShortcut(.cancelAction)
                Button("完成", action: save)
                    .keyboardShortcut(.defaultAction)
                    .buttonStyle(.borderedProminent)
                    .disabled(!canSave)
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

    private func save() {
        guard let l = parsed.link else { return }
        var saved = original
        saved.kind = l.kind
        saved.host = l.host
        saved.port = l.port
        saved.sites = rulesParsed.sites
        let typedName = name.trimmingCharacters(in: .whitespaces)
        saved.name = !typedName.isEmpty ? typedName : (l.name ?? "\(l.host):\(l.port)")
        saved.username = l.username
        if l.username == nil {
            ProxyPasswords.delete(for: saved)
            saved.passwordStamp = nil
        } else if let password = l.password {
            // Only a stamp goes into the settings; the password into the keychain.
            saved.passwordStamp = ProxyPasswords.save(password, for: saved) ? UUID().uuidString : nil
        }
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
