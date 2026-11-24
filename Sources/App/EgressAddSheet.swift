import SwiftUI

/// Adding websites to exit protection, in two steps (UI-DESIGN.md
/// 「出口保护页」): tick what each program is using right now, or type a
/// web address; then see where they leave from and start. Opened from the
/// page, a website's detail (fixed rule) and the Connections page.
struct EgressAddSheet: View {
    @Environment(\.dismiss) private var dismiss
    @ObservedObject private var manager = HelperClient.shared

    private enum Step { case choose, confirm }

    let fixedRule: UInt32?
    let preview: [ConnectionRow]?
    let focusProcess: String?
    let saved: (EgressRuleChange, String) -> Void
    private let preselectedHosts: [String]
    private let preselectedAddresses: [String]
    /// Screenshots only: fixed lookup results instead of the background service.
    private let previewProbes: [String: EgressProtection.SetupProbe]?

    @State private var step = Step.choose
    @State private var input = ""
    @State private var groups: [EgressProgramGroup] = []
    @State private var loaded = false
    @State private var chosen = Set<String>()
    @State private var typed: [String] = []
    @State private var wholeSite = true

    @State private var rule: UInt32?
    @State private var newRuleID = UInt32.random(in: 1...UInt32.max)
    @State private var countries: [String] = []
    @State private var rangeSelection: EgressExitRangeSelection?
    @State private var rangeProofRejected = false
    @State private var probes: [String: EgressProtection.SetupProbe] = [:]
    @State private var probing = false
    @State private var request = UUID()
    @State private var retry = 0
    @State private var saving = false
    @State private var error: String?

    init(rule: UInt32? = nil, preselectedHosts: [String] = [], preselectedAddresses: [String] = [],
         focusProcess: String? = nil, preview: [ConnectionRow]? = nil,
         previewProbes: [String: EgressProtection.SetupProbe]? = nil,
         saved: @escaping (EgressRuleChange, String) -> Void) {
        self.previewProbes = previewProbes
        _step = State(initialValue: previewProbes == nil ? .choose : .confirm)
        fixedRule = rule
        self.preselectedHosts = preselectedHosts
        self.preselectedAddresses = preselectedAddresses
        self.focusProcess = focusProcess
        self.preview = preview
        self.saved = saved
        _rule = State(initialValue: rule)
    }

    // MARK: - Choice

    private var candidates: [EgressCandidate] { groups.flatMap(\.items) }
    private var chosenHosts: [String] {
        var hosts = typed.filter { chosen.contains("t:" + $0) }
        for item in candidates where chosen.contains(item.id) {
            if let host = item.host, !hosts.contains(host) { hosts.append(host) }
        }
        return hosts
    }
    private var chosenAddresses: [String] {
        Array(Set(candidates.filter { chosen.contains($0.id) }.compactMap(\.address))).sorted()
    }
    private var scopes: [EgressWebsiteScope] {
        EgressWebsiteScope.unique(chosenHosts.compactMap { EgressWebsiteScope($0, includesSubdomains: wholeSite) })
    }
    private var typedScope: EgressWebsiteScope? {
        guard !input.isEmpty, let scope = EgressWebsiteScope(input, includesSubdomains: true) else { return nil }
        let known = candidates.contains { $0.id == "w:" + scope.website } || typed.contains(scope.host)
        return known ? nil : scope
    }
    private var filtered: [EgressProgramGroup] {
        let query = input.trimmingCharacters(in: .whitespaces)
        guard !query.isEmpty else { return groups }
        return groups.compactMap { group in
            if group.process.localizedCaseInsensitiveContains(query) { return group }
            let items = group.items.filter { item in item.examples.contains { $0.localizedCaseInsensitiveContains(query) } }
            return items.isEmpty ? nil : .init(process: group.process, items: items)
        }
    }

    // MARK: - Confirmation

    private var targetRule: UInt32? { fixedRule ?? rule }
    private var online: Bool { manager.showsConnected && !manager.usesCisco && manager.protectsDrops }
    private var config: EgressProtection { ProfileStore.loadAppSettings().egressProtection ?? EgressProtection() }
    private var rules: [EgressProtection.Group] { config.rulesForEditing.groups }
    private var setupQuery: SetupQuery {
        .init(hosts: step == .confirm ? scopes.map(\.host) : [], online: online,
              connectedSince: manager.connectedSince, retry: retry)
    }
    private var hasVerifiedSite: Bool { probes.values.contains { $0.verifiedMethod != nil } }
    private var rangeOffers: [EgressExitRangeOffer] {
        guard online, targetRule == nil else { return [] }
        return EgressExitRangeOffer.from(probes, countries: countries, config: config)
    }
    private var canConfirmRanges: Bool {
        rangeSelection == nil || (!rangeProofRejected && rangeSelection?.verified(in: rangeOffers) == true)
    }
    private var conflictingScope: Bool {
        let direct = DirectSites.sites(ProfileStore.loadAppSettings())
        return scopes.contains { $0.conflicts(in: config, rule: targetRule, direct: direct) }
    }
    private var addressesNeedWebsite: Bool { targetRule == nil && scopes.isEmpty && !chosenAddresses.isEmpty }

    private var proposal: EgressRuleChange? {
        let addresses = chosenAddresses
        if scopes.isEmpty {
            guard let target = targetRule, !addresses.isEmpty else { return nil }
            return EgressRuleChange(config: config) { result in
                guard let index = result.groups.firstIndex(where: { $0.id == target }) else { return }
                for address in addresses where !result.groups[index].cidrs.contains(address + "/32") {
                    result.groups[index].cidrs.append(address + "/32")
                }
            }
        }
        guard online, !probing, !conflictingScope, scopes.count <= 8,
              scopes.allSatisfy({ probes[$0.host]?.isComplete == true }),
              targetRule != nil || (hasVerifiedSite && !countries.isEmpty),
              let change = EgressWebsiteScope.adding(scopes, to: config, rule: targetRule, newRuleID: newRuleID,
                                                    methods: verifiedMethods(probes, config: config), countries: countries,
                                                    activateExisting: false) else { return nil }
        var after = change.after
        if let index = after.groups.firstIndex(where: { $0.id == (targetRule ?? newRuleID) }) {
            for address in addresses where !after.groups[index].cidrs.contains(address + "/32") {
                after.groups[index].cidrs.append(address + "/32")
            }
        }
        return .init(before: change.before, after: after)
    }

    // MARK: - Body

    var body: some View {
        VStack(spacing: 0) {
            switch step {
            case .choose: chooseStep
            case .confirm: confirmStep
            }
        }
        .frame(width: 620, height: 580)
        .disabled(saving)
        .onAppear(perform: load)
        .task(id: setupQuery) { await probe(setupQuery) }
        .onDisappear { request = UUID() }
    }

    private var chooseStep: some View {
        VStack(spacing: 0) {
            VStack(alignment: .leading, spacing: 4) {
                Text(fixedRule == nil ? "添加要保护的网站" : "往「\(rules.first { $0.id == fixedRule }?.name ?? "")」里加网站")
                    .font(.title3.weight(.semibold))
                Text("勾选下面正在走 VPN 的网站，或直接输入网址。下一步会查它们现在从哪个国家出去。")
                    .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding([.horizontal, .top], 20).padding(.bottom, 12)
            HStack(spacing: 8) {
                HStack(spacing: 6) {
                    Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                    TextField("", text: $input, prompt: Text("输入网址，或筛选下面的列表"))
                        .textFieldStyle(.plain)
                        .onSubmit(addTyped)
                }
                .padding(.horizontal, 8).padding(.vertical, 6)
                .background(RoundedRectangle(cornerRadius: 7).fill(Color.primary.opacity(0.06)))
                if let scope = typedScope {
                    Button("加入 \(scope.website)", action: addTyped)
                }
                Button { load() } label: { Image(systemName: "arrow.clockwise") }
                    .help("重新读取正在走 VPN 的连接")
            }
            .padding(.horizontal, 20).padding(.bottom, 10)
            List {
                if !typed.isEmpty {
                    Section("你输入的") {
                        ForEach(typed, id: \.self) { host in
                            check("t:" + host, title: wholeSite ? DirectSites.site(of: host) + " 及子域名" : host,
                                  caption: "手动输入", icon: "character.cursor.ibeam")
                        }
                    }
                }
                ForEach(filtered) { group in
                    Section {
                        ForEach(group.items) { item in candidateRow(item) }
                    } header: { programHeader(group) }
                }
                if loaded && filtered.isEmpty && typed.isEmpty {
                    Text(placeholder).foregroundStyle(.secondary)
                        .frame(maxWidth: .infinity, alignment: .center).padding(.vertical, 30)
                }
            }
            .listStyle(.inset)
            Divider()
            HStack(spacing: 12) {
                Toggle("包含子域名", isOn: $wholeSite).toggleStyle(.checkbox)
                    .help("例如勾了 example.com，也一起保护 a.example.com、b.example.com")
                Spacer()
                Text(selectionSummary).font(.callout).foregroundStyle(.secondary)
                Button("取消") { dismiss() }.keyboardShortcut(.cancelAction)
                Button("下一步") { error = nil; step = .confirm }
                    .keyboardShortcut(.defaultAction)
                    .disabled(scopes.isEmpty && chosenAddresses.isEmpty || scopes.count > 8)
            }
            .padding(16)
        }
    }

    private var placeholder: String {
        if !input.isEmpty { return "没有匹配的连接。输入完整网址后按回车加入。" }
        if !manager.showsConnected && preview == nil { return "VPN 没连上，这里暂时是空的。可以直接输入网址。" }
        return "现在没有可以加的走 VPN 的连接。可以直接输入网址。"
    }

    private var selectionSummary: String {
        let sites = scopes.count
        let addresses = chosenAddresses.count
        if sites > 8 { return "一次最多 8 个网站" }
        switch (sites, addresses) {
        case (0, 0): return "还没选"
        case (_, 0): return "已选 \(sites) 个网站"
        case (0, _): return "已选 \(addresses) 个地址"
        default: return "已选 \(sites) 个网站、\(addresses) 个地址"
        }
    }

    private func programHeader(_ group: EgressProgramGroup) -> some View {
        let ids = Set(group.items.map(\.id))
        let all = ids.isSubset(of: chosen)
        let sites = group.items.filter { $0.host != nil }.count
        let bare = group.items.count - sites
        return HStack {
            Text(group.process).font(.callout.weight(.semibold)).foregroundStyle(.primary)
            Text([sites > 0 ? "\(sites) 个网站" : nil, bare > 0 ? "\(bare) 个只有地址" : nil]
                .compactMap { $0 }.joined(separator: "，"))
                .font(.caption).foregroundStyle(.secondary)
            Spacer()
            Button(all ? "全不选" : "全选") {
                if all { chosen.subtract(ids) } else { chosen.formUnion(ids) }
            }
            .buttonStyle(.borderless).font(.caption)
        }
    }

    private func candidateRow(_ item: EgressCandidate) -> some View {
        switch item.kind {
        case .website(let site):
            let others = item.examples.filter { $0 != site }
            let caption = others.isEmpty ? "正在访问" : "访问了 " + others.prefix(3).joined(separator: "、") + (others.count > 3 ? " 等" : "")
            return check(item.id, title: wholeSite ? site + " 及子域名" : (item.host ?? site), caption: caption, icon: "globe")
        case .address(let ip):
            return check(item.id, title: ip, caption: "没有网站名（程序直接连的地址），只能跟着同一个保护一起拦", icon: "number")
        }
    }

    private func check(_ id: String, title: String, caption: String, icon: String) -> some View {
        Toggle(isOn: Binding(get: { chosen.contains(id) }, set: { on in
            if on { chosen.insert(id) } else { chosen.remove(id) }
        })) {
            HStack(spacing: 8) {
                Image(systemName: icon).foregroundStyle(.secondary).frame(width: 16)
                VStack(alignment: .leading, spacing: 1) {
                    Text(title).lineLimit(1)
                    Text(caption).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                }
            }
        }
        .toggleStyle(.checkbox)
        .padding(.vertical, 2)
    }

    private var confirmStep: some View {
        VStack(spacing: 0) {
            HStack(spacing: 10) {
                Button { step = .choose; request = UUID() } label: { Label("返回", systemImage: "chevron.left") }
                    .buttonStyle(.borderless)
                Text("确认出口").font(.title3.weight(.semibold))
                Spacer()
            }
            .padding(.horizontal, 20).padding(.top, 18).padding(.bottom, 6)
            Form {
                Section("要保护的") {
                    ForEach(scopes, id: \.host) { scope in siteResult(scope) }
                    ForEach(chosenAddresses, id: \.self) { address in
                        HStack(spacing: 10) {
                            Image(systemName: "number").foregroundStyle(.secondary).frame(width: 18)
                            Text(address).font(.body.monospacedDigit())
                            Spacer()
                            Text("只有地址 · 跟着一起拦").font(.caption).foregroundStyle(.secondary)
                        }
                    }
                    if !scopes.isEmpty && online && !probing
                        && probes.values.contains(where: { !$0.isComplete }) {
                        Button("再查一次") { retry += 1 }.buttonStyle(.borderless)
                    }
                }
                if !scopes.isEmpty && !online {
                    Section {
                        EgressCallout(icon: "network.slash", tint: .orange,
                                      text: manager.usesCisco ? "要先在「分流」页打开「按网站分流」"
                                          : !manager.protectsDrops ? "要先打开断线保护"
                                          : "先连上 VPN，才能查到它们现在从哪里出去") {
                            if !manager.usesCisco, manager.protectsDrops, !manager.switchIsOn {
                                Button("连接 VPN") { manager.connectForEgressSetup() }
                            }
                        }
                    }
                }
                if fixedRule == nil && !rules.isEmpty {
                    Section("放进") {
                        Picker("", selection: $rule) {
                            Text("新的保护（按现在的出口）").tag(UInt32?.none)
                            ForEach(rules) { group in
                                Text("\(group.name) · 只从 \(egressCountriesLabel(group.expect)) 出去"
                                     + (group.enabled ? "" : "（暂停中）")).tag(Optional(group.id))
                            }
                        }
                        .pickerStyle(.radioGroup).labelsHidden()
                    }
                }
                if targetRule == nil && hasVerifiedSite && !probing {
                    Section("允许的出口") {
                        HStack(alignment: .firstTextBaseline) {
                            VStack(alignment: .leading, spacing: 2) {
                                Text("国家或地区")
                                Text("从这些地方出去才放行").font(.caption).foregroundStyle(.secondary)
                            }
                            Spacer(minLength: 12)
                            EgressCountryChips(countries: countries,
                                               remove: { code in countries.removeAll { $0 == code } },
                                               add: { code in if !countries.contains(code) { countries.append(code) } })
                        }
                        EgressExitRangePicker(offers: rangeOffers, selection: $rangeSelection)
                        if rangeSelection != nil && !canConfirmRanges {
                            EgressCallout(icon: "exclamationmark.triangle.fill", tint: .orange,
                                          text: "出口地址要重新查一次才能确认") {
                                Button("只核对国家") { rangeSelection = nil }
                                Button("再查一次") { retry += 1 }
                            }
                        }
                    }
                } else if let target = rules.first(where: { $0.id == targetRule }) {
                    Section("允许的出口") {
                        Text("沿用「\(target.name)」：只从 \(egressCountriesLabel(target.expect)) 出去")
                            .foregroundStyle(.secondary)
                    }
                }
                if let problem {
                    Section {
                        EgressCallout(icon: "exclamationmark.triangle.fill", tint: .orange, text: problem) { EmptyView() }
                    }
                }
            }
            .formStyle(.grouped)
            Divider()
            let reconnect = proposal?.needsReconnect(connected: manager.showsConnected) == true
            HStack(spacing: 12) {
                if reconnect {
                    Label("会重连一次 VPN，通常不用在手机上确认", systemImage: "arrow.triangle.2.circlepath")
                        .font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
                Button("取消") { dismiss() }.keyboardShortcut(.cancelAction)
                Button(reconnect ? "开始保护并重连" : (targetRule == nil ? "开始保护" : "加进去")) {
                    if let proposal { apply(proposal) }
                }
                .keyboardShortcut(.defaultAction)
                .disabled(proposal == nil || !canConfirmRanges)
            }
            .padding(16)
        }
    }

    private var problem: String? {
        if let error { return error }
        if addressesNeedWebsite { return "只有地址的连接没法自己检查出口：请再勾一个网站，或放进已有的保护。" }
        if conflictingScope { return "其中有网站已在「不走 VPN」名单或另一个保护里。请先在原处移除。" }
        if !probes.isEmpty && !probing && targetRule == nil && !hasVerifiedSite {
            return "这些网站都不能直接检查出口。请放进已有的保护，或再勾一个能检查的网站。"
        }
        if targetRule == nil && hasVerifiedSite && countries.isEmpty { return "选一个允许出去的国家或地区。" }
        return nil
    }

    private func siteResult(_ scope: EgressWebsiteScope) -> some View {
        let result = probes[scope.host]
        let (icon, tint): (String, Color) = {
            guard let result else { return ("globe", .secondary) }
            if result.verifiedMethod != nil { return ("checkmark.circle.fill", .green) }
            if result.status == "unsupported" { return ("link", .secondary) }
            return ("exclamationmark.triangle.fill", .orange)
        }()
        return HStack(spacing: 10) {
            Image(systemName: icon).foregroundStyle(tint).frame(width: 18)
            Text(scope.includesSubdomains ? scope.website + " 及子域名" : scope.host).lineLimit(1)
            Spacer(minLength: 8)
            if probing && result == nil && online {
                ProgressView().controlSize(.small)
                Text("正在查…").font(.caption).foregroundStyle(.secondary)
            } else if let result {
                Text(result.shortCaption).font(.caption).foregroundStyle(.secondary).lineLimit(1)
            } else if !online {
                Text("连上 VPN 后查").font(.caption).foregroundStyle(.secondary)
            }
        }
    }

    // MARK: - Actions

    private func load() {
        let settings = ProfileStore.loadAppSettings()
        let direct = DirectSites.sites(settings)
        let current = settings.egressProtection ?? EgressProtection()
        func show(_ rows: [ConnectionRow]) {
            groups = EgressCandidates.grouped(rows, recent: preview == nil ? EgressRecentVisits.shared.visits : [],
                                              config: current, direct: direct, focus: focusProcess)
            if !loaded { preselect() }
            loaded = true
        }
        if let preview { show(preview); return }
        manager.fetchConnections { rows in show(rows ?? []) }
    }

    private func preselect() {
        for host in preselectedHosts {
            guard let scope = EgressWebsiteScope(host, includesSubdomains: true) else { continue }
            if candidates.contains(where: { $0.id == "w:" + scope.website }) { chosen.insert("w:" + scope.website) }
            else if !typed.contains(scope.host) { typed.append(scope.host); chosen.insert("t:" + scope.host) }
        }
        for address in preselectedAddresses where candidates.contains(where: { $0.id == "a:" + address }) {
            chosen.insert("a:" + address)
        }
    }

    private func addTyped() {
        guard let scope = EgressWebsiteScope(input, includesSubdomains: true) else { return }
        if candidates.contains(where: { $0.id == "w:" + scope.website }) {
            chosen.insert("w:" + scope.website)
        } else {
            if !typed.contains(scope.host) { typed.append(scope.host) }
            chosen.insert("t:" + scope.host)
        }
        input = ""
    }

    private struct SetupQuery: Equatable {
        let hosts: [String]
        let online: Bool
        let connectedSince: Date?
        let retry: Int
    }

    @MainActor private func probe(_ query: SetupQuery) async {
        let current = UUID()
        request = current
        probes = [:]
        countries = []
        rangeSelection = nil
        rangeProofRejected = false
        probing = false
        if let previewProbes {
            probes = previewProbes.filter { query.hosts.contains($0.key) }
            if let suggested = suggestedEgressCountry(probes) { countries = [suggested] }
            return
        }
        guard query.online, !query.hosts.isEmpty, query.hosts.count <= 8 else { return }
        probing = true
        try? await Task.sleep(nanoseconds: 250_000_000)
        guard !Task.isCancelled, request == current else { return }
        manager.probeEgressWebsites(query.hosts, isCurrent: { request == current && setupQuery == query }) { results in
            probes = results
            if let suggested = suggestedEgressCountry(results) { countries = [suggested] }
            probing = false
        }
    }

    private func apply(_ change: EgressRuleChange) {
        guard proposal?.after == change.after, canConfirmRanges else {
            error = "网站或设置刚变过，请再查一次。"
            return
        }
        let website = scopes.count == 1 ? scopes[0].website
            : scopes.isEmpty ? "\(chosenAddresses.count) 个地址" : "\(scopes.count) 个网站"
        saving = true
        error = nil
        func completed(_ ok: Bool, result: EgressRuleChange) {
            saving = false
            if ok {
                saved(result, website)
                dismiss()
            } else if error == nil {
                error = "没有保存。请确认后台服务在运行，再试一次。"
            }
        }
        if let rangeSelection, targetRule == nil {
            guard let setup = EgressExitRangeSetup(proposed: change.after, previous: change.before,
                                                  group: newRuleID, selection: rangeSelection, offers: rangeOffers) else {
                saving = false
                return
            }
            manager.confirmExitRangeSetup(setup) { ok in
                if !ok {
                    rangeProofRejected = true
                    error = "出口地址没能确认，原设置没动。请再查一次。"
                }
                completed(ok, result: .init(before: change.before, after: setup.proposed))
            }
        } else {
            manager.saveEgress(change.after, replacing: change.before) { completed($0, result: change) }
        }
    }
}
