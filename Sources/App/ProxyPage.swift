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
                if routes.isEmpty {
                    VStack(alignment: .leading, spacing: 6) {
                        Text("还没有代理").font(.body.weight(.medium))
                        Text("添加一个 SOCKS5 或 HTTP 代理，再写上哪些网站经它访问。")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    .padding(.vertical, 4)
                } else {
                    ForEach(routes) { route in row(route) }
                }
                HStack {
                    Button {
                        editing = ProxyRoute(name: "代理 \(routes.count + 1)", kind: .socks5, host: "127.0.0.1", port: 1080, sites: [])
                    } label: { Label("添加代理", systemImage: "plus") }
                    Spacer()
                }
            } header: {
                Text("经代理访问的网站")
            } footer: {
                Text("命中规则的网站经所选代理访问，排在「不走 VPN 的网站」之前；几个代理都命中时，用排在前面的。"
                     + "这些网站的域名交给代理解析，本机不向任何 DNS 查询。只转发 TCP（网页、HTTPS 等）；"
                     + "UDP（如 QUIC）会被拒绝，浏览器会自动改用 TCP。代理连不上或拒绝时，这些网站打不开，不会改走直连或 VPN。"
                     + "连接代理本身按分流名单走：在局域网或直连名单里就走本地网络，否则经 VPN。暂不支持需要用户名密码的代理。")
                    .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
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

    private func row(_ route: ProxyRoute) -> some View {
        HStack(spacing: 10) {
            Toggle("", isOn: Binding(
                get: { route.enabled },
                set: { on in
                    guard let index = routes.firstIndex(where: { $0.id == route.id }) else { return }
                    routes[index].enabled = on
                    save()
                }))
                .labelsHidden()
                .accessibilityLabel("启用 \(route.name)")
            VStack(alignment: .leading, spacing: 2) {
                Text(route.name).font(.body.weight(.medium))
                Text(route.summary).font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            if routes.first?.id != route.id {
                Button { move(route, by: -1) } label: { Image(systemName: "arrow.up") }
                    .buttonStyle(.borderless).help("排到前面（几个代理都命中时用前面的）")
            }
            Button("编辑") { editing = route }
            Button(role: .destructive) {
                routes.removeAll { $0.id == route.id }
                save()
            } label: { Image(systemName: "trash") }
                .buttonStyle(.borderless)
                .help("删除这个代理；它的网站回到原来的分流")
        }
        .padding(.vertical, 2)
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

/// One proxy: name, kind, address and its rule box, saved on 完成.
struct ProxyEditor: View {
    let isNew: Bool
    let cancel: () -> Void
    let done: (ProxyRoute) -> Void
    @State private var route: ProxyRoute
    @State private var portText: String
    @State private var rules: String

    init(route: ProxyRoute, isNew: Bool, cancel: @escaping () -> Void, done: @escaping (ProxyRoute) -> Void) {
        self.isNew = isNew
        self.cancel = cancel
        self.done = done
        _route = State(initialValue: route)
        _portText = State(initialValue: route.port > 0 ? String(route.port) : "")
        _rules = State(initialValue: route.sites.joined(separator: "\n"))
    }

    private var parsed: ProxyRuleInput { ProxyRuleInput(rules) }
    private var port: Int? { Int(portText.trimmingCharacters(in: .whitespaces)).flatMap { ProxyRoute.validPort($0) ? $0 : nil } }
    private var host: String { route.host.trimmingCharacters(in: .whitespaces) }
    private var addressProblem: String? {
        if !ProxyRoute.validHost(host) { return "地址只能是 IP 或域名，例如 127.0.0.1 或 proxy.example.com" }
        if port == nil { return "端口是 1–65535 之间的数字" }
        return nil
    }
    private var canSave: Bool {
        addressProblem == nil && parsed.issues.isEmpty && !route.name.trimmingCharacters(in: .whitespaces).isEmpty
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text(isNew ? "添加代理" : "编辑代理").font(.title3.weight(.semibold))
            Form {
                TextField("名称", text: $route.name)
                Picker("类型", selection: $route.kind) {
                    ForEach(ProxyRoute.Kind.allCases) { Text($0.label).tag($0) }
                }
                .pickerStyle(.segmented)
                HStack {
                    TextField("地址", text: $route.host, prompt: Text("127.0.0.1"))
                    TextField("端口", text: $portText, prompt: Text(route.kind == .socks5 ? "1080" : "8080"))
                        .frame(width: 90)
                }
                if let addressProblem, !route.host.isEmpty || !portText.isEmpty {
                    Text(addressProblem).font(.caption).foregroundStyle(.orange)
                }
            }
            .formStyle(.columns)
            VStack(alignment: .leading, spacing: 6) {
                Text("经这个代理访问的网站").font(.body.weight(.medium))
                EgressRuleText(input: $rules, height: 150)
                Text("网段和 geoip 不能用：代理按域名选，本机不先查这些网站的地址。")
                    .font(.caption).foregroundStyle(.secondary)
                EgressRuleIssues(issues: parsed.issues)
            }
            HStack {
                Spacer()
                Button("取消", action: cancel).keyboardShortcut(.cancelAction)
                Button("完成") {
                    var saved = route
                    saved.name = saved.name.trimmingCharacters(in: .whitespaces)
                    saved.host = host
                    saved.port = port ?? 0
                    saved.sites = parsed.sites
                    done(saved)
                }
                .keyboardShortcut(.defaultAction)
                .disabled(!canSave)
            }
        }
        .padding(20)
        .frame(width: 520)
    }
}

/// A proxy's rule box, read like the exit protection's (one rule per
/// line, comments allowed, pasted Clash lines normalized), with networks
/// and geoip refused.
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
            switch rule {
            case .network, .geoip:
                issues.append(.init(id: index + 1, message: "代理只按域名分流，网段和 geoip 不能用"))
            default:
                if seen.insert(rule.text).inserted { sites.append(rule.text) }
            }
        }
        if sites.count > Self.siteLimit { issues.append(.init(id: 0, message: "最多 \(Self.siteLimit) 条")) }
    }
}
