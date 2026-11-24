import SwiftUI

struct EgressRuleText: View {
    @Binding var input: String
    var height: CGFloat = 76

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("每行一条，支持 Clash 写法或分流名单写法。")
                .font(.caption).foregroundStyle(.secondary)
            TextEditor(text: $input)
                .font(.system(.callout, design: .monospaced))
                .frame(height: height)
                .overlay(RoundedRectangle(cornerRadius: 4).strokeBorder(Color.secondary.opacity(0.35)).allowsHitTesting(false))
                .accessibilityLabel("出口保护规则，每行一条")
        }
    }
}

struct EgressRuleIssues: View {
    let issues: [EgressRuleInput.Issue]

    var body: some View {
        if !issues.isEmpty {
            ScrollView {
                VStack(alignment: .leading, spacing: 3) {
                    ForEach(issues) { issue in
                        Text("第 \(issue.id) 行  \(issue.message)")
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .frame(height: CGFloat(min(issues.count, 4) * 18))
            .font(.caption).foregroundStyle(.orange)
        }
    }
}

struct EgressUnverifiedPicker: View {
    @Binding var selection: EgressProtection.Unverified

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Picker("查不到出口时", selection: $selection) {
                ForEach(EgressProtection.Unverified.allCases) { policy in
                    Text(policy.label).tag(policy)
                }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            Text(selection.explanation)
                .font(.caption).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}

private struct EgressRecentSites: View {
    var preview: [ConnectionRow]?
    let add: (String) -> Void
    @State private var recent: [String] = []

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            if !recent.isEmpty {
                Text("最近经 VPN 访问过的网站，点一下加入").font(.caption).foregroundStyle(.secondary)
                FlowChips(items: recent) { site in
                    Button { add(site) } label: { Label(site, systemImage: "plus").font(.callout) }
                        .buttonStyle(.borderless)
                        .padding(.horizontal, 8).padding(.vertical, 3)
                        .background(Capsule().strokeBorder(Color.secondary.opacity(0.35)))
                }
            }
        }
        .onAppear(perform: load)
    }

    private func load() {
        func show(_ rows: [ConnectionRow]) {
            var counts: [String: Int] = [:]
            for row in rows where row.via == "vpn" {
                guard let host = row.host, let site = DirectSites.clean(DirectSites.site(of: host)),
                      !isValidIPv4Address(site) else { continue }
                counts[site, default: 0] += 1
            }
            recent = counts.sorted { ($0.value, $1.key) > ($1.value, $0.key) }.prefix(24).map(\.key)
        }
        if let preview { show(preview); return }
        HelperClient.shared.fetchConnections { rows in show(rows ?? []) }
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

struct EgressSiteSheet: View {
    @Environment(\.dismiss) private var dismiss
    var preview: [ConnectionRow]? = nil
    let save: (EgressRuleInput, [String], EgressProtection.Unverified, @escaping (Bool) -> Void) -> Void
    @State private var input: String
    @State private var countries: [String]
    @State private var unverified = EgressProtection.Unverified.whenWrong
    @State private var saving = false
    @State private var error: String?

    init(sites: [String] = [], countries: [String] = [], preview: [ConnectionRow]? = nil,
         save: @escaping (EgressRuleInput, [String], EgressProtection.Unverified, @escaping (Bool) -> Void) -> Void) {
        self.preview = preview
        self.save = save
        _input = State(initialValue: EgressRuleInput.clashText(sites))
        _countries = State(initialValue: countries)
    }

    var body: some View {
        let parsed = EgressRuleInput(input)
        VStack(spacing: 0) {
            Text("添加出口保护").font(.title3.weight(.semibold))
                .frame(maxWidth: .infinity, alignment: .leading).padding(20)
            Form {
                Section("要保护的网站或网段") {
                    EgressRuleText(input: $input)
                    if !input.isEmpty {
                        Text("识别 \(parsed.lines.count) 条（分成 \(parsed.groupCount) 条保护） · 不支持或无效 \(parsed.issues.count) 条")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    EgressRuleIssues(issues: parsed.issues)
                    if parsed.lines.contains(where: { $0.group != nil }) {
                        Text("有策略组名的规则按组名归入保护，同名保护沿用原来的出口设置。")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    EgressRecentSites(preview: preview) { site in
                        guard !parsed.lines.contains(where: { $0.site == site && $0.group == nil }) else { return }
                        if !input.isEmpty && input.last?.isNewline != true { input += "\n" }
                        input += EgressRuleInput.clash(site)
                    }
                }
                Section("允许的出口") {
                    EgressCountryChips(countries: countries,
                                       remove: { code in countries.removeAll { $0 == code } },
                                       add: { code in if !countries.contains(code) { countries.append(code) } })
                }
                Section("查不到出口时") {
                    EgressUnverifiedPicker(selection: $unverified)
                }
            }
            .formStyle(.grouped)
            Divider()
            HStack(spacing: 12) {
                if let error {
                    Label(error, systemImage: "exclamationmark.triangle.fill").font(.caption).foregroundStyle(.orange)
                }
                Spacer()
                Button("取消") { dismiss() }.keyboardShortcut(.cancelAction)
                Button("开始保护") {
                    saving = true
                    error = nil
                    save(parsed, countries, unverified) { ok in
                        saving = false
                        if ok { dismiss() } else { error = "没有保存。请检查规则数量和出口设置。" }
                    }
                }
                .keyboardShortcut(.defaultAction)
                .disabled(parsed.lines.isEmpty || countries.isEmpty || saving)
            }
            .padding(16)
        }
        .frame(width: 600, height: 600)
        .disabled(saving)
    }
}
