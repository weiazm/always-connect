import SwiftUI

struct EgressWebsiteForm: View {
    @Environment(\.dismiss) private var dismiss
    @ObservedObject private var manager = HelperClient.shared
    @ObservedObject private var recent = EgressRecentVisits.shared
    @State private var input: String
    @State private var rule: UInt32?
    @State private var newRuleID = UInt32.random(in: 1...UInt32.max)
    @State private var wholeSite = true
    @State private var method: String?
    @State private var selectedSites: Set<String>
    @State private var countries: [String] = []
    @State private var probes: [String: EgressProtection.SetupProbe] = [:]
    @State private var probing = false
    @State private var request = UUID()
    @State private var retry = 0
    @State private var saving = false
    @State private var confirm: EgressRuleChange?
    @State private var error: String?
    let saved: (EgressRuleChange, String) -> Void

    init(input: String = "", sites: [String] = [], rule: UInt32? = nil,
         saved: @escaping (EgressRuleChange, String) -> Void) {
        _input = State(initialValue: input)
        _selectedSites = State(initialValue: Set(sites))
        _rule = State(initialValue: rule)
        self.saved = saved
    }

    private var scopes: [EgressWebsiteScope] {
        EgressWebsiteScope.unique(([input] + selectedSites.sorted()).compactMap {
            EgressWebsiteScope($0, includesSubdomains: wholeSite)
        })
    }
    private var online: Bool { manager.showsConnected && !manager.usesCisco && manager.protectsDrops }
    private var config: EgressProtection { ProfileStore.loadAppSettings().egressProtection ?? EgressProtection() }
    private var setupQuery: SetupQuery {
        .init(hosts: scopes.map(\.host), method: method, online: online, connectedSince: manager.connectedSince, retry: retry)
    }
    private var hasVerifiedSite: Bool { probes.values.contains { $0.verifiedMethod != nil } }
    private var conflictingScope: Bool {
        let direct = DirectSites.sites(ProfileStore.loadAppSettings())
        return scopes.contains { $0.conflicts(in: config, rule: rule, direct: direct) }
    }
    private var proposal: EgressRuleChange? {
        let choices = scopes
        guard online, !choices.isEmpty, !probing, !conflictingScope,
              choices.allSatisfy({ probes[$0.host]?.isComplete == true }),
              rule != nil || (hasVerifiedSite && !countries.isEmpty) else { return nil }
        return EgressWebsiteScope.adding(choices, to: config, rule: rule, newRuleID: newRuleID,
                                        methods: verifiedMethods(probes, config: config), countries: countries,
                                        activateExisting: false)
    }

    var body: some View {
        Form {
            Section("网站") {
                let latest = recent.recentSites(config: config, direct: DirectSites.sites(ProfileStore.loadAppSettings()))
                let available = Array(Set(latest).union(selectedSites)).sorted { left, right in
                    (latest.firstIndex(of: left) ?? Int.max, left) < (latest.firstIndex(of: right) ?? Int.max, right)
                }
                if !available.isEmpty {
                    DisclosureGroup("从最近访问中选") {
                        ForEach(available, id: \.self) { site in
                            Toggle(site, isOn: Binding(get: { selectedSites.contains(site) }, set: { on in
                                if on { selectedSites.insert(site) } else { selectedSites.remove(site) }
                            }))
                        }
                    }
                }
                TextField("网站或网址", text: $input, prompt: Text("https://chat.example"))
                if !scopes.isEmpty {
                    let domain = scopes.count == 1 ? DirectSites.site(of: scopes[0].host) : "选中的网站"
                    Toggle("同时保护 \(domain) 和子域名", isOn: $wholeSite)
                    Text(scopes.map(\.website).joined(separator: "、")).font(.caption).foregroundStyle(.secondary)
                }
            }
            Section("出口") {
                if !online {
                    Text(manager.usesCisco ? "先打开「按网站分流」，再连接 VPN 查看出口。"
                         : !manager.protectsDrops ? "请先打开断线保护。"
                         : "先连上 VPN（按网站分流），才能看到网站现在从哪里出去。")
                        .foregroundStyle(.secondary)
                    if !manager.usesCisco, manager.protectsDrops, !manager.switchIsOn {
                        Button("连接 VPN") { manager.connectForEgressSetup() }
                    }
                } else if probing {
                    ProgressView("正在确认它现在从哪里出去…").controlSize(.small)
                } else if scopes.count > 8 {
                    Text("一次最多检查 8 个网站，请减少选择。").foregroundStyle(.orange)
                } else if !probes.isEmpty {
                    ForEach(scopes, id: \.host) { scope in
                        if let probe = probes[scope.host] {
                            Text(scopes.count == 1 ? probe.caption : "\(scope.host)：\(probe.caption)")
                        }
                    }
                    if probes.values.contains(where: { !$0.isComplete || $0.verifiedMethod == nil }) {
                        Button("重新检查") { retry += 1 }
                    }
                    if rule == nil && hasVerifiedSite {
                        EgressCountrySelection(countries: $countries)
                    }
                }
            }
            Section {
                Picker("放进", selection: $rule) {
                    Text("新规则").tag(UInt32?.none)
                    ForEach(config.rulesForEditing.groups) { group in
                        Text(group.name + " · " + group.expect.map(egressCountryName).joined(separator: "、"))
                            .tag(Optional(group.id))
                    }
                }
                if let group = config.rulesForEditing.groups.first(where: { $0.id == rule }) {
                    Text(group.enabled ? "这条规则只允许 " + group.expect.map(egressCountryName).joined(separator: "、")
                         : "网站会加入这条停用的规则，原设置保留。")
                        .font(.caption).foregroundStyle(.secondary)
                }
                if !probes.isEmpty && !hasVerifiedSite && proposal == nil {
                    Text("请选择一条已有直接检查网站的规则，或先添加一个能直接检查的网站。")
                        .font(.caption).foregroundStyle(.orange)
                }
                DisclosureGroup("更换检查方式") {
                    Picker("检查方式", selection: $method) {
                        Text("自动选择").tag(String?.none)
                        ForEach(config.availableMethods.filter(\.isDirect)) { option in
                            Text(option.name).tag(Optional(option.id))
                        }
                    }
                    ForEach(config.availableMethods.filter { !$0.isDirect }) { option in
                        Text(option.name + " · " + EgressProtection.Method.thirdPartyCaption)
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }
            }
            if conflictingScope {
                Text("保护范围与直连名单或另一条规则重叠。请先调整原规则。").font(.caption).foregroundStyle(.orange)
            }
            if let error { Text(error).foregroundStyle(.red) }
            HStack {
                if let confirm {
                    Text(EgressRuleChange.reconnectCaption).font(.caption)
                    Spacer()
                    Button("取消") { self.confirm = nil }
                    Button(confirm.confirmationTitle) { self.confirm = nil; apply(confirm) }
                        .keyboardShortcut(.defaultAction)
                } else {
                    Button("取消") { dismiss() }.keyboardShortcut(.cancelAction)
                    Spacer()
                    Button("开始保护") {
                        guard let proposal else { return }
                        if proposal.needsReconnect(connected: manager.showsConnected) { confirm = proposal }
                        else { apply(proposal) }
                    }
                    .keyboardShortcut(.defaultAction).disabled(proposal == nil)
                }
            }
        }
        .formStyle(.grouped).frame(width: 550, height: 520)
        .disabled(saving)
        .task(id: setupQuery) { await load(setupQuery) }
        .onDisappear { request = UUID() }
    }

    private struct SetupQuery: Equatable {
        let hosts: [String]
        let method: String?
        let online: Bool
        let connectedSince: Date?
        let retry: Int
    }

    @MainActor private func load(_ query: SetupQuery) async {
        let current = UUID()
        request = current
        probes = [:]
        countries = []
        confirm = nil
        probing = false
        guard query.online, !query.hosts.isEmpty, query.hosts.count <= 8 else { return }
        probing = true
        try? await Task.sleep(nanoseconds: 350_000_000)
        guard !Task.isCancelled, request == current else { return }
        manager.probeEgressWebsites(query.hosts, method: query.method, isCurrent: { request == current && setupQuery == query }) { results in
            probes = results
            if let suggested = suggestedEgressCountry(results) { countries = [suggested] }
            probing = false
        }
    }

    private func apply(_ change: EgressRuleChange) {
        guard online, proposal?.after == change.after else {
            error = "网站或规则已修改，请重新检查出口。"
            return
        }
        let website = scopes.count == 1 ? scopes[0].website : "\(scopes.count) 个网站"
        saving = true
        manager.saveEgress(change.after, replacing: change.before) { ok in
            saving = false
            if ok {
                saved(change, website)
                dismiss()
            } else {
                error = "规则未保存。请检查后台服务，或重新打开表单。"
            }
        }
    }
}

struct EgressCountrySelection: View {
    @Binding var countries: [String]
    @State private var selecting = false
    @State private var search = ""

    private var choices: [String] {
        Locale.Region.isoRegions.map(\.identifier).filter {
            $0.utf8.count == 2 && !countries.contains($0)
                && (search.isEmpty || egressCountryName($0).localizedCaseInsensitiveContains(search))
        }.sorted { egressCountryName($0).localizedCompare(egressCountryName($1)) == .orderedAscending }
    }

    var body: some View {
        ForEach(countries, id: \.self) { code in
            HStack {
                Text(egressCountryName(code))
                Spacer()
                Button { countries.removeAll { $0 == code } } label: {
                    Image(systemName: "xmark.circle").accessibilityLabel("移除 " + egressCountryName(code))
                }.buttonStyle(.borderless)
            }
        }
        Button("添加允许的出口国家") { search = ""; selecting = true }
            .popover(isPresented: $selecting) {
                VStack(alignment: .leading, spacing: 8) {
                    TextField("搜索国家或地区", text: $search)
                    List(choices, id: \.self) { code in
                        Button(egressCountryName(code)) {
                            countries.append(code)
                            countries.sort()
                            selecting = false
                        }.buttonStyle(.plain)
                    }
                }.padding(12).frame(width: 280, height: 320)
            }
    }
}
