import SwiftUI

struct EgressExitRangeDetail: View {
    @ObservedObject private var manager = HelperClient.shared
    let rule: EgressProtection.Group
    let status: EgressProtection.Status?
    let refresh: () -> Void
    let edit: ((inout EgressProtection.Group) -> Void) -> Void

    @State private var offers: [EgressExitRangeOffer] = []
    @State private var selection: EgressExitRangeSelection?
    @State private var sampleConfiguration: EgressProtection?
    @State private var request = UUID()
    @State private var busy = false
    @State private var pending: Decision?
    @State private var message: String?

    private enum Decision {
        case enable(EgressExitRangeSetup)
        case allow(EgressExitRangeApproval)
        case disable

        var title: String {
            switch self {
            case .enable: return "开启出口网段核对？"
            case .allow: return "允许此出口范围？"
            case .disable: return "停止核对出口网段？"
            }
        }

        var caption: String {
            switch self {
            case .enable(let setup):
                let ranges = setup.proposed.groups.first { $0.id == setup.group }?.exitRanges ?? []
                return "后续连接须同时满足允许的国家和这些出口范围：" + ranges.joined(separator: "、") + "。"
            case .allow(let approval):
                return "允许出口范围 \(approval.cidr)。同一规则里仍会核对国家和每条新连接的实际出口。"
            case .disable:
                return "关闭后，这条规则仍核对国家。同一国家的新出口地址将不再因为网段变化被拦截。"
            }
        }

        var button: String {
            switch self {
            case .enable: return "确认开启"
            case .allow(let approval): return "允许 \(approval.cidr)"
            case .disable: return "停止核对"
            }
        }
    }

    var body: some View {
        Section("允许的出口网段") {
            if rule.exitRangeCheck {
                Text("新连接必须同时符合允许的国家和出口网段。")
                    .font(.caption).foregroundStyle(.secondary)
                ForEach(rule.exitRanges, id: \.self) { Text($0) }
                if rule.exitRanges.contains(where: { $0.contains(":") }) {
                    Text("IPv6 出口网段校验尚未在真实 VPN 上实测。")
                        .font(.caption).foregroundStyle(.secondary)
                }
                Button("停止核对出口网段", role: .destructive) { pending = .disable }.disabled(busy)
                ForEach(status?.exitChanges(for: rule) ?? []) { change in
                    VStack(alignment: .leading, spacing: 6) {
                        Text("出口换了新地址 \(change.exit.address)，已拦截相关新连接。")
                            .foregroundStyle(.orange)
                        Text(change.observation.observationCaption)
                            .font(.caption).foregroundStyle(.secondary)
                        HStack {
                            Button("只允许 \(change.exit.address)") { pending = .allow(change.approval(for: change.exit.single)) }
                            Button("允许网段 \(change.exit.subnet)") { pending = .allow(change.approval(for: change.exit.subnet)) }
                        }
                        if change.exit.isIPv6 {
                            Text("IPv6 出口网段校验尚未在真实 VPN 上实测。")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                    }
                    .disabled(busy || !manager.showsConnected)
                }
            } else {
                Text("当前只核对国家。开启后，未允许的出口网段会拦截相关新连接。")
                    .font(.caption).foregroundStyle(.secondary)
                Button(busy ? "正在核对…" : "检查出口并查看网段建议") { check() }
                    .disabled(busy || !manager.showsConnected || !rule.enabled)
                if !manager.showsConnected || !rule.enabled {
                    Text("请连接自建 VPN 并开启这条网站规则后再检查。")
                        .font(.caption).foregroundStyle(.secondary)
                }
                EgressExitRangePicker(offers: offers, selection: $selection)
                    .disabled(busy)
                if !offers.isEmpty {
                    Button("开启出口网段核对") { confirmSetup() }
                        .disabled(busy || selection?.verified(in: offers) != true)
                }
            }
            if let message { Text(message).font(.caption).foregroundStyle(.secondary) }
        }
        .onDisappear { request = UUID() }
        .confirmationDialog(pending?.title ?? "确认出口网段", isPresented: Binding(
            get: { pending != nil }, set: { if !$0 { pending = nil } }
        ), titleVisibility: .visible, presenting: pending) { change in
            Button(change.button) { apply(change) }
            Button(rule.exitRangeCheck ? "继续拦截" : "取消", role: .cancel) {}
        } message: { change in Text(change.caption) }
    }

    private func check() {
        let config = ProfileStore.loadAppSettings().egressProtection ?? EgressProtection()
        guard config.enabled, config.groups.contains(rule), manager.showsConnected, !manager.usesCisco else { return }
        let members = config.directMembers(in: rule).prefix(8).compactMap { member -> (host: String, method: String)? in
            guard let host = member.concreteHost, let method = member.method else { return nil }
            return (host, method)
        }
        let currentRequest = UUID()
        let session = manager.connectedSince
        request = currentRequest
        sampleConfiguration = config
        busy = true
        offers = []
        selection = nil
        message = nil
        var collected: [EgressExitRangeOffer] = []
        func next(_ index: Int) {
            guard request == currentRequest else { return }
            guard manager.showsConnected, manager.connectedSince == session,
                  (ProfileStore.loadAppSettings().egressProtection ?? EgressProtection()) == config else {
                busy = false
                message = "VPN 或规则已变化，请重新检查。"
                return
            }
            guard members.indices.contains(index) else {
                busy = false
                offers = collected
                if collected.isEmpty { message = "没有来自已允许国家的直接出口 IP。请检查这条规则的检测方式。" }
                return
            }
            let member = members[index]
            manager.probeEgressSetup(host: member.host, method: member.method) { result in
                if let result, result.method == member.method {
                    let newOffers = EgressExitRangeOffer.from(
                        [member.host: result], countries: rule.expect, config: config
                    ).filter { offer in !collected.contains { $0.proof == offer.proof } }
                    collected.append(contentsOf: newOffers)
                }
                next(index + 1)
            }
        }
        next(0)
    }

    private func confirmSetup() {
        guard manager.showsConnected, let sampleConfiguration, let selection,
              let setup = EgressExitRangeSetup(proposed: sampleConfiguration, previous: sampleConfiguration,
                                              group: rule.id, selection: selection, offers: offers) else { return }
        pending = .enable(setup)
    }

    private func apply(_ decision: Decision) {
        pending = nil
        switch decision {
        case .enable(let setup):
            busy = true
            manager.confirmExitRangeSetup(setup) { ok in
                busy = false
                offers = []
                selection = nil
                message = ok ? "已开启出口网段核对。" : "未能确认开启。原设置已保留，请重新检查后再试。"
                refresh()
            }
        case .allow(let approval):
            busy = true
            manager.allowEgressRange(approval) { ok in
                busy = false
                message = ok ? "已允许 \(approval.cidr)。下方显示当前拦截状态。"
                    : "未能确认该出口范围。原设置已保留，请重新检查。"
                refresh()
            }
        case .disable:
            edit { if $0 == rule { $0.exitRangeCheck = false } }
        }
    }
}
