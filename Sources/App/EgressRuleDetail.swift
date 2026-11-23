import SwiftUI

extension EgressProtection.Level {
    var color: Color {
        switch self {
        case .ok, .unknown: return .secondary
        case .partial: return .orange
        case .blocked: return .red
        }
    }
}

struct EgressChangeNotice: Identifiable {
    let id = UUID()
    let text: String
    let change: EgressRuleChange
}

struct EgressChangeBanner: View {
    let notice: EgressChangeNotice
    let undo: () -> Void
    var body: some View {
        HStack {
            Label(notice.text, systemImage: "checkmark.circle")
                .font(.caption).fixedSize(horizontal: false, vertical: true)
            Spacer()
            Button("撤销", action: undo).buttonStyle(.borderless)
        }
        .padding(8)
        .background(.quaternary, in: RoundedRectangle(cornerRadius: 6))
    }
}

struct EgressReconnectPrompt: View {
    let change: EgressRuleChange
    let cancel: () -> Void
    var canConfirm = true
    let confirm: () -> Void
    var body: some View {
        HStack {
            Text(EgressRuleChange.reconnectCaption).font(.caption)
                .fixedSize(horizontal: false, vertical: true)
            Spacer()
            Button("取消", action: cancel)
            Button(change.confirmationTitle, action: confirm).disabled(!canConfirm)
        }
    }
}

struct EgressRuleDetail: View {
    @ObservedObject private var manager = HelperClient.shared
    @Environment(\.dismiss) private var dismiss
    let rule: EgressProtection.Group
    let status: EgressProtection.Status?
    let refresh: () -> Void
    let addWebsite: () -> Void
    let advanced: () -> Void
    let edit: ((inout EgressProtection.Group) -> Void) -> Void
    let remove: () -> Void
    @State private var name = ""
    @State private var pendingApproval: EgressCountryApproval?
    @State private var approving = false
    @State private var checking = false
    @State private var showDelete = false
    @State private var message: String?

    private var state: EgressProtection.GroupState? { status?.groups.first { $0.id == rule.id } }
    private var availableApprovals: [EgressCountryApproval] {
        guard let status else { return [] }
        return status.approvals(for: rule.id).filter { approval in
            status.records.first { $0.group == rule.id && $0.started == approval.started }?.expected == rule.expect
        }
    }

    var body: some View {
        Form {
            Section("规则") {
                HStack {
                    TextField("规则名称", text: $name)
                    Button("保存名称") { edit { $0.name = name } }
                        .disabled(name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || name == rule.name)
                }
                Text(state?.blockCaption ?? (state?.displayLevel == .ok ? "正常" : "尚未核实出口"))
                    .foregroundStyle((state?.displayLevel ?? .unknown).color)
                if let message { Text(message).font(.caption).foregroundStyle(.secondary) }
                if manager.showsConnected, state?.displayLevel == .blocked || state?.displayLevel == .partial {
                    Button(checking ? "正在重新检查…" : "重新检查") { recheck() }.disabled(checking)
                }
            }
            Section("允许的出口国家") {
                ForEach(rule.expect, id: \.self) { country in
                    HStack {
                        Text(egressCountryName(country))
                        Spacer()
                        Button("移除", role: .destructive) { edit { $0.expect.removeAll { $0 == country } } }
                            .disabled(rule.expect.count <= 1)
                    }
                }
            }
            EgressExitRangeDetail(rule: rule, status: status, refresh: refresh, edit: edit)
            Section("网站") {
                ForEach(rule.members) { member in
                    HStack {
                        Text(member.pattern)
                        Spacer()
                        if let site = state?.sites?.first(where: { $0.host == member.pattern || $0.host == member.concreteHost }) {
                            Text(siteCaption(site)).font(.caption).foregroundStyle(.secondary)
                        } else {
                            Text(member.method == nil ? "跟随这条规则" : "等待检查")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                    }
                }
                ForEach(rule.cidrs, id: \.self) { Text($0) }
                Button("添加网站", action: addWebsite)
            }
            if let records = status?.records.filter({ $0.group == rule.id }), !records.isEmpty {
                Section("最近拦截") {
                    ForEach(records, id: \.started) { record in
                        VStack(alignment: .leading, spacing: 4) {
                            Label(record.host ?? record.name, systemImage: "shield")
                            Text(Date(timeIntervalSince1970: record.started), style: .time)
                                .font(.caption).foregroundStyle(.secondary)
                            ForEach(record.observed.indices, id: \.self) { index in
                                Text(record.observed[index].observationCaption).font(.caption).foregroundStyle(.secondary)
                            }
                        }
                    }
                    ForEach(availableApprovals) { approval in
                        Button("允许 \(egressCountryName(approval.country))") { pendingApproval = approval }
                            .disabled(approving)
                    }
                }
            }
            HStack {
                Button("高级", action: advanced)
                Button("删除规则", role: .destructive) { showDelete = true }
                Spacer()
                Button("完成") { dismiss() }.keyboardShortcut(.defaultAction)
            }
        }
        .formStyle(.grouped).frame(width: 570, height: 500)
        .onAppear { name = rule.name; refresh() }
        .alert("删除这条规则？", isPresented: $showDelete) {
            Button("取消", role: .cancel) {}
            Button("删除规则", role: .destructive, action: remove)
        } message: { Text("此操作会移除这条规则对网站的出口保护。") }
        .alert("以后也允许这个出口？", isPresented: Binding(
            get: { pendingApproval != nil }, set: { if !$0 { pendingApproval = nil } }
        ), presenting: pendingApproval) { approval in
            Button("取消", role: .cancel) {}
            Button("允许 " + egressCountryName(approval.country)) { allow(approval) }
        } message: { approval in
            Text("已确认 \(approval.observation.host) 的服务器 \(approval.observation.peerAddress ?? "") 从 \(egressCountryName(approval.country)) 出去。允许后，这条规则也会核对该国家的连接。"
                 + (rule.exitRangeCheck ? "出口仍须符合已允许的网段。" : ""))
        }
    }

    private func siteCaption(_ site: EgressProtection.SiteState) -> String {
        if site.state == "blocked" { return "出口无法核实，已拦截" }
        let count = site.blockedCount
        if count > 0 { return "本次已拦下 \(count) 次连接" }
        guard let country = site.country, site.lastCheck.isFinite && site.lastCheck > 0 else { return "尚未核实出口" }
        let time = Date(timeIntervalSince1970: site.lastCheck).formatted(date: .omitted, time: .shortened)
        return "\(time) · \(egressCountryName(country))"
    }

    private func recheck() {
        checking = true
        manager.recheckEgressRule(rule.id) { ok in
            checking = false
            message = ok ? "重新检查已完成。下方显示当前状态。" : "这次未完成重新检查。请查看当前拦截状态。"
            refresh()
        }
    }

    private func allow(_ approval: EgressCountryApproval) {
        approving = true
        manager.allowEgressCountry(approval) { ok in
            approving = false
            message = ok ? "已允许 " + egressCountryName(approval.country) : "出口观测已变化或未能确认。请重新检查。"
            refresh()
        }
    }
}
