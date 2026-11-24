import SwiftUI

/// Which observed exits to allow. The recommended range is ticked; single
/// addresses are one disclosure away. Only observed exits are offered.
struct EgressExitRangePicker: View {
    let offers: [EgressExitRangeOffer]
    @Binding var selection: EgressExitRangeSelection?
    var showsToggle = true

    private var offer: EgressExitRangeOffer? {
        offers.first { $0.proof == selection?.proof }
    }

    var body: some View {
        if !offers.isEmpty {
            VStack(alignment: .leading, spacing: 6) {
                if showsToggle {
                    Toggle(isOn: Binding(
                        get: { selection != nil },
                        set: { on in
                            if on, let first = offers.first { select(first) }
                            else { selection = nil }
                        })) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("还要核对出口地址（更严）")
                            Text("国家对了还不够，出口地址也得是下面勾的；换了就先拦住再问你。")
                                .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                        }
                    }
                    .toggleStyle(.checkbox)
                }
                if let offer {
                    if offers.count > 1 {
                        Picker("按哪个网站查到的出口", selection: Binding(
                            get: { offer.proof },
                            set: { value in if let next = offers.first(where: { $0.proof == value }) { select(next) } }
                        )) {
                            ForEach(offers) { Text($0.host).tag($0.proof) }
                        }
                        .fixedSize()
                    }
                    let current = offer.suggestions.addresses.map(\.address).joined(separator: "、")
                    ForEach(offer.suggestions.recommended, id: \.self) { cidr in
                        Toggle(isOn: rangeBinding(cidr)) {
                            VStack(alignment: .leading, spacing: 1) {
                                Text(cidr.hasSuffix("/128") ? "只放行 \(cidr)" : "放行 \(cidr)")
                                Text("推荐 · 包含现在的出口 \(current)").font(.caption).foregroundStyle(.secondary)
                            }
                        }
                        .toggleStyle(.checkbox)
                    }
                    DisclosureGroup("改成只放行单个地址") {
                        VStack(alignment: .leading, spacing: 4) {
                            ForEach(offer.suggestions.addresses) { exit in
                                if exit.isIPv6 {
                                    Toggle("放行 \(exit.subnet)", isOn: rangeBinding(exit.subnet)).toggleStyle(.checkbox)
                                } else {
                                    Toggle("只放行 \(exit.address)", isOn: rangeBinding(exit.single)).toggleStyle(.checkbox)
                                }
                            }
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    if offer.suggestions.addresses.contains(where: \.isIPv6) {
                        Text("IPv6 出口地址的核对还没在真实 VPN 上实测过。")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }
            }
            .padding(.leading, showsToggle ? 0 : 2)
        }
    }

    private func select(_ offer: EgressExitRangeOffer) {
        selection = .init(proof: offer.proof, ranges: Set(offer.suggestions.recommended))
    }

    private func rangeBinding(_ range: String) -> Binding<Bool> {
        Binding(get: { selection?.ranges.contains(range) == true }, set: { on in
            guard var draft = selection, let offer else { return }
            if on {
                for address in offer.suggestions.addresses {
                    if range == address.subnet { draft.ranges.remove(address.single) }
                    if range == address.single { draft.ranges.remove(address.subnet) }
                }
                draft.ranges.insert(range)
            } else {
                draft.ranges.remove(range)
            }
            selection = draft
        })
    }
}
