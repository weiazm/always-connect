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
    let pause: (UInt32) -> Void
    let remove: () -> Void
    @State private var renaming = false
    @State private var name = ""
    @State private var showDelete = false

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
                        EgressDecisionList(decisions: decisions, refresh: refresh, pause: pause)
                    }
                }
                Section {
                    EgressSitesEditor(sites: Binding(get: { rule.sites }, set: { sites in
                        // A rule needs at least one site; delete the rule instead.
                        guard !sites.isEmpty else { return }
                        edit { $0.sites = sites }
                    }))
                } header: {
                    Text("要保护的网站")
                } footer: {
                    Text("任何程序访问这里的网站（含子域名）时检查出口，别的连接不受影响。至少留一个。")
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
                        Text("这次连接有 \(unverified) 条查不到出口（对方服务器不支持查询），已先放行。")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                } header: {
                    Text("允许的出口")
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
                Button("完成") { dismiss() }.keyboardShortcut(.defaultAction)
            }
            .padding(16)
        }
        .frame(width: 600, height: 560)
        .onAppear(perform: refresh)
        .alert("改名", isPresented: $renaming) {
            TextField("名称", text: $name)
            Button("取消", role: .cancel) {}
            Button("保存") {
                let value = name.trimmingCharacters(in: .whitespacesAndNewlines)
                if !value.isEmpty && value != rule.name { edit { $0.name = value } }
            }
        } message: { Text("只是给自己看的名字，不影响保护。") }
        .alert("删除「\(rule.name)」的出口保护？", isPresented: $showDelete) {
            Button("取消", role: .cancel) {}
            Button("删除", role: .destructive, action: remove)
        } message: { Text("以后不再核对出口。只想临时停一下，可以用右上角的开关暂停。") }
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
        guard connected else { return countries + " · VPN 连上后开始检查" }
        if let state, state.lastCheck.isFinite, state.lastCheck > 0 {
            let time = Date(timeIntervalSince1970: state.lastCheck).formatted(date: .omitted, time: .shortened)
            return countries + " · \(time) 核实过"
        }
        return countries
    }

    private func recordRow(_ record: EgressProtection.BlockRecord) -> some View {
        let open = record.ended == nil
        return VStack(alignment: .leading, spacing: 3) {
            HStack {
                Image(systemName: open ? "hand.raised.fill" : "checkmark.circle")
                    .foregroundStyle(open ? Color.orange : Color.secondary)
                Text(record.host ?? record.name)
                Spacer()
                Text(open ? "拦截中" : "已恢复").font(.caption).foregroundStyle(open ? Color.orange : Color.secondary)
                Text(Date(timeIntervalSince1970: record.started), format: .dateTime.hour().minute())
                    .font(.caption.monospacedDigit()).foregroundStyle(.secondary)
            }
            ForEach(record.observed.indices, id: \.self) { index in
                Text(record.observed[index].plainCaption).font(.caption).foregroundStyle(.secondary)
                    .padding(.leading, 26)
            }
        }
    }
}

extension EgressProtection.Observation {
    /// The record line without lookup jargon: host, server, where it left from.
    var plainCaption: String {
        let server = peerAddress.map { "（服务器 \($0)）" } ?? ""
        let place = country.map { "从 \(egressCountryLabel($0)) 出去" } ?? "没查到出口"
        let exit = ip.map { "，出口 \($0)" } ?? ""
        let reference = evidenceKind == .thirdParty ? "（第三方查询，仅供参考）" : ""
        return host + server + " " + place + exit + reference
    }
}
