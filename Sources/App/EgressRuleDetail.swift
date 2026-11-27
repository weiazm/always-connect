import SwiftUI

/// One protection rule (DESIGN §66.25): the sites it covers, where they
/// may leave from, and what was blocked (UI-DESIGN「出口保护页」).
struct EgressRuleDetail: View {
    @Environment(\.dismiss) private var dismiss
    let rule: EgressProtection.Group
    let config: EgressProtection
    let status: EgressProtection.Status?
    let connected: Bool
    let refresh: () -> Void
    let edit: ((inout EgressProtection.Group) -> Void) -> Void
    let remove: () -> Void
    let saveSites: (_ original: [String], _ replacement: [String], _ done: @escaping (String?) -> Void) -> Void
    @State private var originalSites: [String]
    @State private var input: String
    @State private var issues: [EgressRuleInput.Issue] = []
    @State private var saveError: String?
    @State private var saving = false
    @State private var renaming = false
    @State private var name = ""
    @State private var showDelete = false
    @State private var rechecking = false

    init(rule: EgressProtection.Group, config: EgressProtection, status: EgressProtection.Status?, connected: Bool,
         refresh: @escaping () -> Void, edit: @escaping ((inout EgressProtection.Group) -> Void) -> Void,
         remove: @escaping () -> Void,
         saveSites: @escaping ([String], [String], @escaping (String?) -> Void) -> Void) {
        self.rule = rule
        self.config = config
        self.status = status
        self.connected = connected
        self.refresh = refresh
        self.edit = edit
        self.remove = remove
        self.saveSites = saveSites
        _originalSites = State(initialValue: rule.sites)
        _input = State(initialValue: rule.sites.joined(separator: "\n"))
    }

    private var state: EgressProtection.GroupState? { status?.groups.first { $0.id == rule.id } }
    private var badge: EgressRuleBadge { .of(rule, config: config, state: state, connected: connected) }

    var body: some View {
        VStack(spacing: 0) {
            header.padding(20)
            Divider()
            Form {
                let decisions = (status?.decisions(config: config) ?? []).filter { $0.rule == rule.id }
                if connected && !decisions.isEmpty {
                    Section("需要你决定") {
                        EgressDecisionList(decisions: decisions, refresh: refresh)
                    }
                }
                if connected, let state, state.blocked {
                    if rule.unverified == .whenWrong && state.observed.contains(where: { $0.country != nil }) {
                        Text("有服务器出口不对，查不到出口的连接也先拦住。")
                            .font(.callout).foregroundStyle(.orange)
                    }
                    if state.observed.contains(where: { $0.country == nil }) {
                        Section("查不到出口的服务器") {
                            ForEach(state.observed.filter { $0.country == nil }) { observation in
                                Text(observation.plainCaption).help(observation.addressHelp)
                            }
                            Button(rechecking ? "正在检查…" : "重新检查") {
                                rechecking = true
                                HelperClient.shared.recheckEgressRule(rule.id) { _ in
                                    rechecking = false
                                    refresh()
                                }
                            }
                            .disabled(rechecking)
                        }
                    }
                }
                Section("查不到出口时") {
                    EgressUnverifiedPicker(selection: Binding(get: { rule.unverified }, set: { value in
                        edit { $0.unverified = value }
                    }))
                }
                Section {
                    EgressRuleText(input: $input, height: 145)
                    EgressRuleIssues(issues: issues)
                } header: {
                    Text("要保护的网站或网段")
                } footer: {
                    Text("直接在框里增删改，点「完成」保存。网址、*.example.com、粘贴的 Clash 规则行会统一成上面这种写法。")
                        .font(.caption).foregroundStyle(.secondary)
                }

                Section {
                    HStack(alignment: .firstTextBaseline) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("国家或地区")
                            Text("从这些地方出去才放行").font(.caption).foregroundStyle(.secondary)
                        }
                        Spacer(minLength: 12)
                        EgressCountryChips(countries: rule.expect,
                                           remove: { code in edit { $0.expect.removeAll { $0 == code } } },
                                           add: { code in edit { if !$0.expect.contains(code) { $0.expect.append(code) } } })
                    }
                    if let unverified = state?.unverifiedCount, unverified > 0, connected {
                        Text("这次连接有 \(unverified) 次查不到出口，已放行。")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    if let steered = state?.steered, !steered.isEmpty, connected {
                        Text("已为 \(steered.prefix(3).joined(separator: "、"))\(steered.count > 3 ? " 等 \(steered.count) 个" : "") 换到出口正确的入口（同一 CDN，仍走 Cisco）。")
                            .font(.caption).foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                } header: {
                    Text("允许的出口")
                }
                if let paths = state?.paths, connected, !paths.isEmpty {
                    let routes = ProfileStore.loadAppSettings().activeProxyRoutes
                    Section("各路线最近出口") {
                        ForEach(paths) { row in
                            HStack(spacing: 8) {
                                EgressRouteTag(path: row.path, routes: routes, compact: false)
                                Text(row.country.map { egressCountryLabel($0) } ?? (row.error ?? "尚未核实"))
                                    .font(.callout)
                                Spacer()
                                if row.blockedCount > 0 {
                                    Text("拦下 \(row.blockedCount) 次").font(.caption).foregroundStyle(.orange)
                                }
                                if row.lastCheck.isFinite && row.lastCheck > 0 {
                                    Text(Date(timeIntervalSince1970: row.lastCheck), format: .dateTime.hour().minute())
                                        .font(.caption.monospacedDigit()).foregroundStyle(.secondary)
                                }
                            }
                        }
                    }
                }
                if let records = status?.records.filter({ $0.group == rule.id }), connected, !records.isEmpty {
                    Section("最近拦截") {
                        ForEach(records.prefix(8), id: \.started) { record in recordRow(record) }
                    }
                }
            }
            .formStyle(.grouped)
            Divider()
            HStack(spacing: 12) {
                Button("删除这个保护…", role: .destructive) { showDelete = true }
                    .buttonStyle(.borderless).foregroundStyle(.red)
                Spacer()
                if let saveError {
                    Text(saveError).font(.caption).foregroundStyle(.orange).fixedSize(horizontal: false, vertical: true)
                }
                Button(saving ? "正在保存…" : "完成", action: finish).keyboardShortcut(.defaultAction)
            }
            .padding(16)
        }
        .frame(width: 600, height: 560)
        .disabled(saving)
        .interactiveDismissDisabled(saving)
        .onChange(of: input) { _ in
            issues = []
            saveError = nil
        }
        .onAppear(perform: refresh)
        .alert("改名", isPresented: $renaming) {
            TextField("名称", text: $name)
            Button("取消", role: .cancel) {}
            Button("保存") {
                let value = name.trimmingCharacters(in: .whitespacesAndNewlines)
                if !value.isEmpty && !value.contains(where: \.isNewline) && value != rule.name { edit { $0.name = value } }
            }
        } message: { Text("只是给自己看的名字，不影响保护。") }
        .alert("删除「\(rule.name)」的出口保护？", isPresented: $showDelete) {
            Button("取消", role: .cancel) {}
            Button("删除", role: .destructive, action: remove)
        } message: { Text("以后不再核对出口。只想临时停一下，可以用右上角的开关暂停。") }
    }

    private func finish() {
        if input == originalSites.joined(separator: "\n") {
            dismiss()
            return
        }
        let parsed = EgressRuleInput(input)
        issues = parsed.issues
        guard let sites = parsed.replacementSites else {
            if !issues.isEmpty {
                saveError = "第 \(issues[0].id) 行有问题，请修正后保存。"
            } else if parsed.sites.isEmpty {
                saveError = "请至少保留一条规则。"
            } else {
                saveError = "每个保护最多 \(EgressRuleInput.siteLimit) 条规则。"
            }
            return
        }
        if sites == originalSites {
            dismiss()
            return
        }
        saving = true
        saveError = nil
        saveSites(originalSites, sites) { error in
            saving = false
            if let error { saveError = error } else { dismiss() }
        }
    }

    private var header: some View {
        HStack(alignment: .center, spacing: 14) {
            EgressSiteAvatar(name: rule.sites.first ?? rule.name, size: 44)
                .opacity(rule.enabled ? 1 : 0.45)
            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 6) {
                    Text(rule.name).font(.title3.weight(.semibold)).lineLimit(1)
                    Button { name = rule.name; renaming = true } label: {
                        Image(systemName: "pencil").foregroundStyle(.secondary)
                    }
                    .buttonStyle(.borderless).help("改名")
                }
                HStack(spacing: 8) {
                    EgressStatusPill(badge: badge)
                    Text(headerLine).font(.callout).foregroundStyle(.secondary).lineLimit(2)
                }
            }
            Spacer(minLength: 12)
            Toggle(isOn: Binding(get: { rule.enabled }, set: { on in edit { $0.enabled = on } })) {
                Text(rule.enabled ? "保护中" : "已暂停").foregroundStyle(.secondary)
            }
            .toggleStyle(.always)
            .fixedSize()
            .disabled(!rule.enabled && (rule.sites.isEmpty || rule.expect.isEmpty))
        }
    }

    private var headerLine: String {
        if rule.enabled, let problem = badge.problem { return problem }
        let countries = "只从 " + egressCountriesLabel(rule.expect) + " 出去"
        guard rule.enabled else { return countries + " · 暂停期间不核对" }
        guard connected else { return countries + " · Cisco 连上后开始检查" }
        if let state, state.lastCheck.isFinite, state.lastCheck > 0 {
            let time = Date(timeIntervalSince1970: state.lastCheck).formatted(date: .omitted, time: .shortened)
            return countries + " · \(time) 核实过"
        }
        return countries
    }

    private func recordRow(_ record: EgressProtection.BlockRecord) -> some View {
        let open = record.ended == nil
        let routes = ProfileStore.loadAppSettings().activeProxyRoutes
        let routePath = record.path ?? record.observed.first?.path
        return VStack(alignment: .leading, spacing: 3) {
            HStack(spacing: 6) {
                Image(systemName: open ? "hand.raised.fill" : "checkmark.circle")
                    .foregroundStyle(open ? Color.orange : Color.secondary)
                Text(record.host ?? record.name)
                EgressRouteTag(path: routePath, routes: routes)
                Spacer()
                Text(open ? "拦截中" : "已恢复").font(.caption).foregroundStyle(open ? Color.orange : Color.secondary)
                Text(Date(timeIntervalSince1970: record.started), format: .dateTime.hour().minute())
                    .font(.caption.monospacedDigit()).foregroundStyle(.secondary)
            }
            ForEach(record.observed.indices, id: \.self) { index in
                Text(record.observed[index].plainCaption).font(.caption).foregroundStyle(.secondary)
                    .help(record.observed[index].addressHelp)
                    .padding(.leading, 26)
            }
        }
    }
}

extension EgressProtection.Observation {
    /// The record line in words: the site and where it left from. The
    /// addresses are in `addressHelp` (hover), not in the line (user,
    /// 2026-11-25: "ip我怎么看懂是哪个域名").
    var plainCaption: String {
        let place = country.map { "从 \(egressCountryLabel($0)) 出去" } ?? (host.isEmpty ? "看不到网站名" : "查不到出口")
        return displayedHost + " " + place
    }

    var addressHelp: String {
        "服务器 \(peerAddress ?? "—")" + (ip.map { "，出口地址 \($0)" } ?? "")
    }
}
