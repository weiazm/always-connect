import SwiftUI

/// The sites a rule protects (DESIGN §66.25): typed in, or picked from the
/// websites recently reached through the VPN. A site covers its subdomains.
struct EgressSitesEditor: View {
    @ObservedObject private var manager = HelperClient.shared
    @Binding var sites: [String]
    var preview: [ConnectionRow]? = nil
    @State private var input = ""
    @State private var recent: [String] = []

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            if !sites.isEmpty {
                FlowChips(items: sites) { site in
                    HStack(spacing: 4) {
                        Text(site + " 及子域名")
                        Button { sites.removeAll { $0 == site } } label: {
                            Image(systemName: "xmark.circle.fill").foregroundStyle(.secondary)
                        }
                        .buttonStyle(.borderless)
                        .accessibilityLabel("不再保护 " + site)
                    }
                    .padding(.horizontal, 8).padding(.vertical, 3)
                    .background(Capsule().fill(Color.secondary.opacity(0.14)))
                }
            }
            HStack {
                TextField("", text: $input, prompt: Text("输入域名，例如 example.com"))
                    .textFieldStyle(.roundedBorder)
                    .onSubmit { add(input) }
                Button("添加") { add(input) }.disabled(DirectSites.clean(input) == nil)
            }
            let suggestions = recent.filter { !sites.contains($0) }
            if !suggestions.isEmpty {
                Text("最近经 VPN 访问过的网站，点一下加入：").font(.caption).foregroundStyle(.secondary)
                FlowChips(items: Array(suggestions.prefix(24))) { site in
                    Button { add(site) } label: {
                        Label(site, systemImage: "plus").font(.callout)
                    }
                    .buttonStyle(.borderless)
                    .padding(.horizontal, 8).padding(.vertical, 3)
                    .background(Capsule().strokeBorder(Color.secondary.opacity(0.35)))
                }
            }
        }
        .onAppear(perform: load)
    }

    private func add(_ text: String) {
        guard let site = DirectSites.clean(text) else { return }
        if !sites.contains(site) { sites.append(site) }
        input = ""
    }

    /// One snapshot of the connections when the editor opens; no sampling.
    private func load() {
        func show(_ rows: [ConnectionRow]) {
            var counts: [String: Int] = [:]
            for row in rows where row.via == "vpn" {
                guard let host = row.host, let site = DirectSites.clean(DirectSites.site(of: host)) else { continue }
                counts[site, default: 0] += 1
            }
            recent = counts.sorted { ($0.value, $1.key) > ($1.value, $0.key) }.map(\.key)
        }
        if let preview { show(preview); return }
        manager.fetchConnections { rows in show(rows ?? []) }
    }
}

/// Chips that wrap onto as many lines as they need.
struct FlowChips<Item: Hashable, Chip: View>: View {
    let items: [Item]
    @ViewBuilder let chip: (Item) -> Chip

    var body: some View {
        FlowLayout(spacing: 6) {
            ForEach(items, id: \.self) { chip($0) }
        }
    }
}

private struct FlowLayout: Layout {
    var spacing: CGFloat

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        let width = proposal.width ?? 500
        var x: CGFloat = 0, y: CGFloat = 0, line: CGFloat = 0
        for view in subviews {
            let size = view.sizeThatFits(.unspecified)
            if x > 0 && x + size.width > width { x = 0; y += line + spacing; line = 0 }
            x += size.width + spacing
            line = max(line, size.height)
        }
        return CGSize(width: width, height: y + line)
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        var x = bounds.minX, y = bounds.minY, line: CGFloat = 0
        for view in subviews {
            let size = view.sizeThatFits(.unspecified)
            if x > bounds.minX && x + size.width > bounds.maxX { x = bounds.minX; y += line + spacing; line = 0 }
            view.place(at: CGPoint(x: x, y: y), proposal: ProposedViewSize(size))
            x += size.width + spacing
            line = max(line, size.height)
        }
    }
}

/// Adding a protection: the sites, then the allowed countries.
struct EgressSiteSheet: View {
    @Environment(\.dismiss) private var dismiss
    var preview: [ConnectionRow]? = nil
    let save: (_ sites: [String], _ countries: [String], _ done: @escaping (Bool) -> Void) -> Void
    @State private var sites: [String] = []
    @State private var countries: [String]
    @State private var saving = false
    @State private var error: String?

    init(sites: [String] = [], countries: [String] = [], preview: [ConnectionRow]? = nil,
         save: @escaping ([String], [String], @escaping (Bool) -> Void) -> Void) {
        self.preview = preview
        self.save = save
        _sites = State(initialValue: sites)
        _countries = State(initialValue: countries)
    }

    var body: some View {
        VStack(spacing: 0) {
            VStack(alignment: .leading, spacing: 4) {
                Text("添加要保护的网站").font(.title3.weight(.semibold))
                Text("任何程序访问这些网站（含子域名）时，先确认从哪个国家出去，不对就拦下再问你。别的连接不受影响；查不出出口的先放行。")
                    .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(20)
            Form {
                Section("要保护的网站") {
                    EgressSitesEditor(sites: $sites, preview: preview)
                }
                Section("只从这里出去") {
                    HStack(alignment: .firstTextBaseline) {
                        Text("国家或地区")
                        Spacer(minLength: 12)
                        EgressCountryChips(countries: countries,
                                           remove: { code in countries.removeAll { $0 == code } },
                                           add: { code in if !countries.contains(code) { countries.append(code) } })
                    }
                }
            }
            .formStyle(.grouped)
            Divider()
            HStack(spacing: 12) {
                if let error {
                    Label(error, systemImage: "exclamationmark.triangle.fill").font(.caption).foregroundStyle(.orange)
                } else if sites.isEmpty || countries.isEmpty {
                    Text(sites.isEmpty ? "先加一个要保护的网站" : "再选一个允许的国家或地区").font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
                Button("取消") { dismiss() }.keyboardShortcut(.cancelAction)
                Button("开始保护") {
                    saving = true
                    error = nil
                    save(sites, countries) { ok in
                        saving = false
                        if ok { dismiss() } else { error = "没有保存。请稍后再试。" }
                    }
                }
                .keyboardShortcut(.defaultAction)
                .disabled(sites.isEmpty || countries.isEmpty || saving)
            }
            .padding(16)
        }
        .frame(width: 580, height: 560)
        .disabled(saving)
    }
}
