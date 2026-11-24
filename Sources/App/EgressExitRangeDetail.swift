import SwiftUI

/// The stricter check inside 「允许的出口」: besides the country, only
/// the exit addresses the user confirmed. Turning it on first looks up
/// the current exit, so the user only ever confirms what was observed.
/// A changed exit is asked about in 「需要你决定」 (EgressDecisionList).
struct EgressExitRangeDetail: View {
    @ObservedObject private var manager = HelperClient.shared
    let rule: EgressProtection.Group
    let connected: Bool
    let refresh: () -> Void
    let edit: ((inout EgressProtection.Group) -> Void) -> Void

    @State private var offers: [EgressExitRangeOffer] = []
    @State private var selection: EgressExitRangeSelection?
    @State private var sampleConfiguration: EgressProtection?
    @State private var request = UUID()
    @State private var busy = false
    @State private var confirmStop = false
    @State private var message: String?

    var body: some View {
        if rule.exitRangeCheck {
            HStack(alignment: .firstTextBaseline) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("核对出口地址")
                    Text("国家对了还不够，出口地址也得在这些范围里：")
                        .font(.caption).foregroundStyle(.secondary)
                    Text(rule.exitRanges.joined(separator: "、")).font(.callout.monospacedDigit())
                    if rule.exitRanges.contains(where: { $0.contains(":") }) {
                        Text("IPv6 出口地址的核对还没在真实 VPN 上实测过。").font(.caption).foregroundStyle(.secondary)
                    }
                }
                Spacer(minLength: 12)
                Button("停止核对…") { confirmStop = true }
            }
            .confirmationDialog("只核对国家？", isPresented: $confirmStop, titleVisibility: .visible) {
                Button("停止核对出口地址", role: .destructive) {
                    edit { if $0 == rule { $0.exitRangeCheck = false } }
                }
                Button("取消", role: .cancel) {}
            } message: { Text("之后同一国家换了新出口地址，也不会再拦。") }
        } else {
            HStack(alignment: .firstTextBaseline) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("核对出口地址")
                    Text(offers.isEmpty ? "现在只看国家。更严一点：先查一次现在的出口地址，由你确认放行范围。"
                         : "勾选要放行的出口，之后出口换到别处就先拦住再问你。")
                        .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 12)
                if offers.isEmpty {
                    Button(busy ? "正在查…" : "查现在的出口") { check() }
                        .disabled(busy || !connected || !rule.enabled)
                        .help(!connected || !rule.enabled ? "连上 VPN 并打开这个保护后才能查" : "")
                }
            }
            if !offers.isEmpty {
                EgressExitRangePicker(offers: offers, selection: $selection, showsToggle: false)
                    .disabled(busy)
                HStack {
                    Spacer()
                    Button("取消") { offers = []; selection = nil; request = UUID() }
                    Button("开始核对") { confirmSetup() }
                        .disabled(busy || selection?.verified(in: offers) != true)
                }
            }
            if let message { Text(message).font(.caption).foregroundStyle(.secondary) }
        }
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
                message = "VPN 或设置刚变过，请再查一次。"
                return
            }
            guard members.indices.contains(index) else {
                busy = false
                offers = collected
                if let first = collected.first {
                    selection = .init(proof: first.proof, ranges: Set(first.suggestions.recommended))
                } else {
                    message = "这次没查到允许国家里的出口地址。请稍后再查。"
                }
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
        busy = true
        manager.confirmExitRangeSetup(setup) { ok in
            busy = false
            offers = []
            self.selection = nil
            message = ok ? nil : "没能确认。原设置没动，请再查一次。"
            refresh()
        }
    }
}
