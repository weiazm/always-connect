import SwiftUI

/// One protected website (a rule): what it covers, where it may leave
/// from, and what was blocked. Raw members and lookup methods stay
/// behind 「高级编辑…」 (UI-DESIGN.md「出口保护页」).
struct EgressRuleDetail: View {
    @Environment(\.dismiss) private var dismiss
    let rule: EgressProtection.Group
    let config: EgressProtection
    let status: EgressProtection.Status?
    let connected: Bool
    let refresh: () -> Void
    let addWebsite: () -> Void
    let advanced: () -> Void
    let edit: ((inout EgressProtection.Group) -> Void) -> Void
    let pause: (UInt32) -> Void
    let remove: () -> Void
    @State private var renaming = false
    @State private var name = ""
    @State private var removing: SiteEntry?
    @State private var removingRange: String?
    @State private var showDelete = false

    private var state: EgressProtection.GroupState? { status?.groups.first { $0.id == rule.id } }
    private var badge: EgressRuleBadge { .of(rule, config: config, state: state, connected: connected) }
    private var canEnable: Bool { !config.directMembers(in: rule).isEmpty && !rule.expect.isEmpty }

    /// The generated apex + wildcard pair reads as one website.
    struct SiteEntry: Identifiable {
        let id: String
        let title: String
        let patterns: [String]
        let checked: Bool
    }

    private var entries: [SiteEntry] {
        let patterns = Set(rule.members.map(\.pattern))
        return rule.members.compactMap { member in
            let pattern = member.pattern
            let checked = config.method(member.method)?.isDirect == true && member.concreteHost != nil
            if pattern.hasPrefix("*.") {
                let root = String(pattern.dropFirst(2))
                if patterns.contains(root) {
                    let apexChecked = rule.members.first { $0.pattern == root }.map {
                        config.method($0.method)?.isDirect == true
                    } ?? false
                    return .init(id: pattern, title: root + " 及子域名", patterns: [root, pattern], checked: checked || apexChecked)
                }
                return .init(id: pattern, title: root + " 的子域名", patterns: [pattern], checked: checked)
            }
            if patterns.contains("*." + pattern) { return nil }
            if pattern.hasPrefix("geosite:") {
                return .init(id: pattern, title: "清单 " + pattern.dropFirst("geosite:".count), patterns: [pattern], checked: false)
            }
            return .init(id: pattern, title: pattern, patterns: [pattern], checked: checked)
        }
    }

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
                    ForEach(entries) { entry in siteRow(entry) }
                    ForEach(rule.cidrs, id: \.self) { range in addressRow(range) }
                    Button(action: addWebsite) { Label("添加网站…", systemImage: "plus.circle.fill") }
                        .buttonStyle(.borderless)
                } header: {
                    Text("网站")
                } footer: {
                    Text("带「及子域名」的，下面的子网站一起保护。只有地址的连接跟着这些网站一起拦。")
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
                    EgressExitRangeDetail(rule: rule, connected: connected, refresh: refresh, edit: edit)
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
                Button("高级编辑…", action: advanced)
                Button("完成") { dismiss() }.keyboardShortcut(.defaultAction)
            }
            .padding(16)
        }
        .frame(width: 620, height: 600)
        .onAppear(perform: refresh)
        .alert("改名", isPresented: $renaming) {
            TextField("名称", text: $name)
            Button("取消", role: .cancel) {}
            Button("保存") {
                let value = name.trimmingCharacters(in: .whitespacesAndNewlines)
                if !value.isEmpty && value != rule.name { edit { $0.name = value } }
            }
        } message: { Text("只是给自己看的名字，不影响保护。") }
        .confirmationDialog("不再保护 \(removing?.title ?? "")？", isPresented: Binding(
            get: { removing != nil }, set: { if !$0 { removing = nil } }
        ), titleVisibility: .visible, presenting: removing) { entry in
            Button("移除", role: .destructive) {
                edit { $0.members.removeAll { entry.patterns.contains($0.pattern) } }
            }
            Button("取消", role: .cancel) {}
        } message: { _ in Text("以后访问它不再核对出口。想恢复可以再添加一次。") }
        .confirmationDialog("不再跟着保护 \(removingRange ?? "")？", isPresented: Binding(
            get: { removingRange != nil }, set: { if !$0 { removingRange = nil } }
        ), titleVisibility: .visible, presenting: removingRange) { range in
            Button("移除", role: .destructive) { edit { $0.cidrs.removeAll { $0 == range } } }
            Button("取消", role: .cancel) {}
        }
        .alert("删除「\(rule.name)」的出口保护？", isPresented: $showDelete) {
            Button("取消", role: .cancel) {}
            Button("删除", role: .destructive, action: remove)
        } message: { Text("这些网站以后不再核对出口。只想临时停一下，可以用右上角的开关暂停。") }
    }

    private var header: some View {
        HStack(alignment: .center, spacing: 14) {
            EgressSiteAvatar(name: rule.name, size: 44).opacity(rule.enabled ? 1 : 0.45)
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
            .disabled(!canEnable && !rule.enabled)
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

    private func siteRow(_ entry: SiteEntry) -> some View {
        let site = state?.sites?.first { site in
            rule.members.contains { entry.patterns.contains($0.pattern) && ($0.matchesSite(site.host) || $0.pattern == site.host) }
        }
        let (caption, tint) = siteCaption(entry, site)
        return HStack(spacing: 10) {
            Image(systemName: entry.checked ? "checkmark.seal" : "link")
                .foregroundStyle(.secondary).frame(width: 18)
                .help(entry.checked ? "直接检查这个网站的出口" : "不能直接检查，跟着这个保护一起拦")
            Text(entry.title).lineLimit(1)
            Spacer(minLength: 8)
            Text(caption).font(.caption).foregroundStyle(tint).lineLimit(1)
            Button { removing = entry } label: { Image(systemName: "minus.circle").foregroundStyle(.secondary) }
                .buttonStyle(.borderless).help("不再保护这个网站")
        }
    }

    private func siteCaption(_ entry: SiteEntry, _ site: EgressProtection.SiteState?) -> (String, Color) {
        guard entry.checked else { return ("跟着一起保护", .secondary) }
        guard rule.enabled, connected else { return ("直接检查", .secondary) }
        guard let site else { return ("等待检查", .secondary) }
        if site.state == "blocked" { return ("出口核实不了，已拦住", .red) }
        if site.blockedCount > 0 { return ("这次拦下 \(site.blockedCount) 次", .orange) }
        guard let country = site.country, site.lastCheck.isFinite, site.lastCheck > 0 else { return ("等待检查", .secondary) }
        let time = Date(timeIntervalSince1970: site.lastCheck).formatted(date: .omitted, time: .shortened)
        return ("\(time) · \(egressCountryLabel(country))", .secondary)
    }

    private func addressRow(_ range: String) -> some View {
        HStack(spacing: 10) {
            Image(systemName: "number").foregroundStyle(.secondary).frame(width: 18)
            Text(range.hasSuffix("/32") ? String(range.dropLast(3)) : range).font(.body.monospacedDigit())
            Spacer(minLength: 8)
            Text("只有地址").font(.caption).foregroundStyle(.secondary)
            Button { removingRange = range } label: { Image(systemName: "minus.circle").foregroundStyle(.secondary) }
                .buttonStyle(.borderless).help("不再跟着保护这个地址")
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
