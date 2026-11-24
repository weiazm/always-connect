import SwiftUI

/// One protection rule (DESIGN §66.24): the apps it covers, where they may
/// leave from, and what was blocked (UI-DESIGN「出口保护页」).
struct EgressRuleDetail: View {
    @Environment(\.dismiss) private var dismiss
    let rule: EgressProtection.Group
    let config: EgressProtection
    let status: EgressProtection.Status?
    let connected: Bool
    let refresh: () -> Void
    let addApp: () -> Void
    let edit: ((inout EgressProtection.Group) -> Void) -> Void
    let pause: (UInt32) -> Void
    let remove: () -> Void
    @State private var renaming = false
    @State private var name = ""
    @State private var removing: String?
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
                    ForEach(rule.apps, id: \.self) { app in appRow(app) }
                    Button(action: addApp) { Label("添加 App…", systemImage: "plus.circle.fill") }
                        .buttonStyle(.borderless)
                } header: {
                    Text("App")
                } footer: {
                    Text("App 里的辅助程序一起算。它们以外的程序不受这条保护影响。")
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
        .confirmationDialog("不再保护 \(removing.map(EgressApps.displayName) ?? "")？", isPresented: Binding(
            get: { removing != nil }, set: { if !$0 { removing = nil } }
        ), titleVisibility: .visible, presenting: removing) { app in
            Button("移除", role: .destructive) { edit { $0.apps.removeAll { $0 == app } } }
            Button("取消", role: .cancel) {}
        } message: { _ in Text("它的连接以后不再核对出口。") }
        .alert("删除「\(rule.name)」的出口保护？", isPresented: $showDelete) {
            Button("取消", role: .cancel) {}
            Button("删除", role: .destructive, action: remove)
        } message: { Text("这些 App 以后不再核对出口。只想临时停一下，可以用右上角的开关暂停。") }
    }

    private var header: some View {
        HStack(alignment: .center, spacing: 14) {
            Image(nsImage: EgressApps.icon(rule.apps.first ?? "")).resizable().frame(width: 44, height: 44)
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
            .disabled(!rule.enabled && (rule.apps.isEmpty || rule.expect.isEmpty))
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

    private func appRow(_ app: String) -> some View {
        HStack(spacing: 10) {
            Image(nsImage: EgressApps.icon(app)).resizable().frame(width: 20, height: 20)
            VStack(alignment: .leading, spacing: 1) {
                Text(EgressApps.displayName(app)).lineLimit(1)
                Text(app.hasPrefix("/") ? app : "命令行程序（按名字匹配）")
                    .font(.caption).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
            }
            Spacer(minLength: 8)
            Button { removing = app } label: { Image(systemName: "minus.circle").foregroundStyle(.secondary) }
                .buttonStyle(.borderless).help("不再保护这个 App")
                .disabled(rule.apps.count <= 1)
        }
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
        let cause = exitRangeFailureCaption.map { "：\($0)" } ?? ""
        let reference = evidenceKind == .thirdParty ? "（第三方查询，仅供参考）" : ""
        return host + server + " " + place + exit + reference + cause
    }
}
