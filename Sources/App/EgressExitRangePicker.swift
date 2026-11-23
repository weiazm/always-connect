import SwiftUI

struct EgressExitRangePicker: View {
    let offers: [EgressExitRangeOffer]
    @Binding var selection: EgressExitRangeSelection?

    private var offer: EgressExitRangeOffer? {
        offers.first { $0.proof == selection?.proof }
    }

    var body: some View {
        if !offers.isEmpty {
            Toggle("同时核对出口网段", isOn: Binding(
                get: { selection != nil },
                set: { on in
                    if on, let first = offers.first { select(first) }
                    else { selection = nil }
                }))
            if let offer {
                if offers.count > 1 {
                    Picker("使用此网站的观测", selection: Binding(
                        get: { offer.proof },
                        set: { value in if let next = offers.first(where: { $0.proof == value }) { select(next) } }
                    )) {
                        ForEach(offers) { Text($0.host).tag($0.proof) }
                    }
                }
                Text("直接观测的出口 IP：" + offer.suggestions.addresses.map(\.address).joined(separator: "、"))
                    .font(.caption).foregroundStyle(.secondary)
                ForEach(offer.suggestions.recommended, id: \.self) { cidr in
                    Toggle((cidr.hasSuffix("/128") ? "只允许 " : "允许网段 ") + cidr, isOn: rangeBinding(cidr))
                }
                DisclosureGroup("其他范围") {
                    ForEach(offer.suggestions.addresses) { exit in
                        if exit.isIPv6 {
                            Toggle("允许网段 \(exit.subnet)", isOn: rangeBinding(exit.subnet))
                        } else {
                            Toggle("只允许 \(exit.address)", isOn: rangeBinding(exit.single))
                        }
                    }
                }
                if offer.suggestions.addresses.contains(where: \.isIPv6) {
                    Text("IPv6 出口网段校验尚未在真实 VPN 上实测。")
                        .font(.caption).foregroundStyle(.secondary)
                }
                Text("只有你确认的地址或网段才会加入允许列表。")
                    .font(.caption).foregroundStyle(.secondary)
            }
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
