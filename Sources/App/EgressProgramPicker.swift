import SwiftUI

/// One program's current VPN connections, merged by website or bare address,
/// so a user can tick everything a program uses instead of typing names.
struct EgressProgramCandidate: Identifiable, Hashable {
    enum Kind: Hashable { case website(String), address(String) }
    let kind: Kind
    let examples: [String]
    var id: String {
        switch kind {
        case .website(let site): return "w:" + site
        case .address(let ip): return "a:" + ip
        }
    }
    var title: String {
        switch kind {
        case .website(let site): return site + " 及子域名"
        case .address(let ip): return ip
        }
    }
    var caption: String {
        switch kind {
        case .website: return examples.prefix(3).joined(separator: "、") + (examples.count > 3 ? " 等" : "")
        case .address: return "只有地址，没有网站名（程序没经过本机查地址）"
        }
    }

    /// Rows are the connection list's current, in-memory snapshot: no new sampling.
    static func from(process: String, rows: [(host: String?, remote: String, via: String)]) -> [Self] {
        var sites: [String: Set<String>] = [:]
        var addresses = Set<String>()
        for row in rows where row.via == "vpn" {
            if let host = row.host, let scope = EgressWebsiteScope(host, includesSubdomains: true) {
                sites[scope.website, default: []].insert(scope.host)
            } else if isPublicIPv4(row.remote) {
                addresses.insert(row.remote)
            }
        }
        return sites.keys.sorted().map { .init(kind: .website($0), examples: sites[$0]!.sorted()) }
            + addresses.sorted().map { .init(kind: .address($0), examples: [$0]) }
    }

    static func isPublicIPv4(_ text: String) -> Bool {
        let parts = text.split(separator: ".").compactMap { UInt8($0) }
        guard parts.count == 4, text.split(separator: ".").count == 4 else { return false }
        switch (parts[0], parts[1]) {
        case (10, _), (127, _), (0, _), (169, 254), (192, 168): return false
        case (172, 16...31), (100, 64...127): return false
        default: return parts[0] < 224
        }
    }
}

struct EgressProgramPicker: View {
    @Environment(\.dismiss) private var dismiss
    let process: String
    let candidates: [EgressProgramCandidate]
    let rules: [EgressProtection.Group]
    @State var chosen: Set<String>
    @State private var rule: UInt32?
    let confirm: (_ hosts: [String], _ addresses: [String], _ rule: UInt32?) -> Void

    init(process: String, candidates: [EgressProgramCandidate], rules: [EgressProtection.Group],
         preselected: Set<String>, confirm: @escaping ([String], [String], UInt32?) -> Void) {
        self.process = process
        self.candidates = candidates
        self.rules = rules
        self._chosen = State(initialValue: preselected)
        self._rule = State(initialValue: rules.first(where: \.enabled)?.id)
        self.confirm = confirm
    }

    private var websites: [EgressProgramCandidate] { candidates.filter { if case .website = $0.kind { return true }; return false } }
    private var addresses: [EgressProgramCandidate] { candidates.filter { if case .address = $0.kind { return true }; return false } }
    private var pickedAddresses: [String] {
        addresses.filter { chosen.contains($0.id) }.compactMap { if case .address(let ip) = $0.kind { return ip }; return nil }
    }
    private var pickedHosts: [String] {
        websites.filter { chosen.contains($0.id) }.compactMap(\.examples.first)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            VStack(alignment: .leading, spacing: 4) {
                Text("保护「\(process)」用到的网站").font(.headline)
                Text("下面是它现在走 VPN 的全部连接。勾上的会加进同一条规则，每条新连接都先确认出口。")
                    .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
            List {
                if !websites.isEmpty {
                    Section("网站") { ForEach(websites) { row($0) } }
                }
                if !addresses.isEmpty {
                    Section("只有地址的连接") { ForEach(addresses) { row($0) } }
                }
            }
            .listStyle(.inset(alternatesRowBackgrounds: true))
            .frame(minHeight: 220)
            HStack {
                Button(chosen.count == candidates.count ? "全不选" : "全选") {
                    chosen = chosen.count == candidates.count ? [] : Set(candidates.map(\.id))
                }.buttonStyle(.borderless)
                Spacer()
                Picker("加到", selection: $rule) {
                    ForEach(rules) { group in
                        Text(group.name + (group.enabled ? "" : "（已停用）")).tag(Optional(group.id))
                    }
                    Text("新建规则（按现在的出口）").tag(UInt32?.none)
                }.fixedSize()
            }
            if rule == nil && !pickedAddresses.isEmpty {
                Label("新建规则时先加网站；只有地址的连接请在规则建好后再加进去。", systemImage: "info.circle")
                    .font(.caption).foregroundStyle(.secondary)
            }
            HStack {
                Spacer()
                Button("取消") { dismiss() }.keyboardShortcut(.cancelAction)
                Button("加入 \(chosen.count) 项") {
                    confirm(pickedHosts, rule == nil ? [] : pickedAddresses, rule)
                    dismiss()
                }
                .keyboardShortcut(.defaultAction)
                .disabled(chosen.isEmpty || (rule == nil && pickedHosts.isEmpty))
            }
        }
        .padding(20)
        .frame(width: 520, height: 460)
    }

    private func row(_ item: EgressProgramCandidate) -> some View {
        Toggle(isOn: Binding(get: { chosen.contains(item.id) }, set: { on in
            if on { chosen.insert(item.id) } else { chosen.remove(item.id) }
        })) {
            VStack(alignment: .leading, spacing: 2) {
                Text(item.title)
                Text(item.caption).font(.caption).foregroundStyle(.secondary)
            }
        }
        .toggleStyle(.checkbox)
    }
}
