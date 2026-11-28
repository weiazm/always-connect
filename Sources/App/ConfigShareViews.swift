import AppKit
import SwiftUI
import UniformTypeIdentifiers

/// Settings → 通用: share these settings as a file, or take someone's
/// (DESIGN §七十五, UI-DESIGN 分享配置). Both sheets exist only while open.
struct ShareSection: View {
    @State private var exporting = false
    @State private var choosing = false
    @State private var importing: ImportFile?
    @State private var message: String?
    @State private var undo: ConfigShare.Undo?
    @State private var undoing = false

    struct ImportFile: Identifiable {
        let id = UUID()
        let text: String
        let preview: ConfigShare.Preview
    }

    var body: some View {
        Section {
            LabeledContent {
                HStack(spacing: 8) {
                    Button("导入…") { message = nil; undo = nil; choosing = true }
                    Button("导出…") { message = nil; exporting = true }
                }
            } label: {
                IconLabel(title: "分享配置", subtitle: "把分流名单、代理、出口保护、Cisco 服务器导成一个文件给别人用",
                          symbol: "square.and.arrow.up.on.square.fill", color: SettingsTone.account)
            }
            .sheet(isPresented: $exporting) { ShareExportSheet() }
            .sheet(item: $importing) { file in
                ShareImportSheet(text: file.text, preview: file.preview) { outcome in
                    message = outcome.line
                    undo = outcome.undo
                }
            }
            .fileImporter(isPresented: $choosing, allowedContentTypes: [ShareFileDocument.type, .json, .plainText]) { result in
                open(result)
            }
            if let message {
                HStack(alignment: .firstTextBaseline, spacing: 8) {
                    Text(message).font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                    Spacer()
                    if let undo {
                        Button(undoing ? "正在撤销…" : "撤销") { revert(undo) }.disabled(undoing)
                    }
                }
            }
        } header: {
            Text("配置")
        }
    }

    private func open(_ result: Result<URL, Error>) {
        guard case .success(let url) = result else { return }
        let opened = url.startAccessingSecurityScopedResource()
        defer { if opened { url.stopAccessingSecurityScopedResource() } }
        let size = (try? url.resourceValues(forKeys: [.fileSizeKey]).fileSize) ?? 0
        guard size <= 1 << 20, let data = try? Data(contentsOf: url),
              let text = String(data: data, encoding: .utf8) else {
            message = "这个文件读不出来：太大，或者不是文本文件。"
            return
        }
        guard let preview = ConfigShare.preview(text) else { message = "这个文件读不出来。"; return }
        guard preview.ok else { message = preview.error ?? "这个文件读不出来。"; return }
        importing = ImportFile(text: text, preview: preview)
    }

    private func revert(_ change: ConfigShare.Undo) {
        undoing = true
        ConfigShare.undo(change) { ok in
            undoing = false
            undo = nil
            message = ok ? "已撤销这次导入。" : "已撤销，但出口保护没能改回去，请到「出口保护」页看一下。"
        }
    }
}

/// The file as saved: plain UTF-8 text.
struct ShareFileDocument: FileDocument {
    static let type = UTType(filenameExtension: "toml") ?? .plainText
    static var readableContentTypes: [UTType] { [type] }
    var text: String

    init(text: String) { self.text = text }
    init(configuration: ReadConfiguration) throws {
        text = String(decoding: configuration.file.regularFileContents ?? Data(), as: UTF8.self)
    }
    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper {
        FileWrapper(regularFileWithContents: Data(text.utf8))
    }
}

/// The file text, read-only, with the `{…}` placeholders marked and
/// comments dimmed.
struct ShareFileText: View {
    var text: String

    var body: some View {
        ScrollView {
            Text(attributed)
                .font(.system(size: 11, design: .monospaced))
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(12)
        }
        .background(RoundedRectangle(cornerRadius: 8, style: .continuous).fill(Color.primary.opacity(0.04)))
        .overlay(RoundedRectangle(cornerRadius: 8, style: .continuous).stroke(Color.primary.opacity(0.08)))
    }

    private var attributed: AttributedString {
        var out = AttributedString()
        for line in text.split(separator: "\n", omittingEmptySubsequences: false) {
            if line.hasPrefix("#") {
                var comment = AttributedString(line + "\n")
                comment.foregroundColor = .secondary
                out += comment
                continue
            }
            var rest = Substring(line)
            while let open = rest.firstIndex(of: "{"), let close = rest[open...].firstIndex(of: "}") {
                out += AttributedString(rest[..<open])
                var mark = AttributedString(rest[open...close])
                mark.foregroundColor = .orange
                mark.backgroundColor = Color.orange.opacity(0.14)
                out += mark
                rest = rest[rest.index(after: close)...]
            }
            out += AttributedString(rest + "\n")
        }
        return out
    }
}

private struct SharePill: View {
    var text: String
    var color: Color
    var body: some View {
        Text(text).font(.caption2.weight(.medium)).foregroundStyle(color)
            .padding(.horizontal, 6).padding(.vertical, 2)
            .background(Capsule().fill(color.opacity(0.15)))
    }
}

// MARK: - Export

/// Left: what goes into the file; right: the file itself, as it will be saved.
struct ShareExportSheet: View {
    @Environment(\.dismiss) private var dismiss
    private let local: ConfigShare.Local
    @State private var direct: Bool
    @State private var proxies: Set<String>
    @State private var egress: Set<UInt32>
    @State private var cisco: Bool
    @State private var general = true
    @State private var fullLinks = false
    /// The settings with the proxies' passwords, read when full links are first asked for.
    @State private var secretLocal: ConfigShare.Local?
    @State private var saving = false
    @State private var note: String?

    init() {
        let l = ConfigShare.local()
        local = l
        _direct = State(initialValue: !l.direct_sites.isEmpty || !l.direct_exceptions.isEmpty)
        _proxies = State(initialValue: Set(l.proxies.map(\.id)))
        _egress = State(initialValue: Set(l.egress.map(\.id)))
        _cisco = State(initialValue: !l.cisco.servers.isEmpty)
    }

    private var result: ConfigShare.Exported? {
        ConfigShare.export(ConfigShare.ExportRequest(
            local: fullLinks ? (secretLocal ?? local) : local, direct: direct, proxies: Array(proxies),
            egress: Array(egress), cisco: cisco, general: general, full_links: fullLinks,
            app_version: UpdateChecker.currentVersion, date: ConfigShare.today))
    }

    var body: some View {
        let exported = result
        VStack(spacing: 0) {
            VStack(alignment: .leading, spacing: 3) {
                Text("导出配置").font(.title3.weight(.semibold))
                Text("右边就是将要保存的文件，改左边的选项会立即更新").font(.callout).foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity, alignment: .leading).padding(.horizontal, 20).padding(.top, 20).padding(.bottom, 8)
            HStack(alignment: .top, spacing: 0) {
                options(exported)
                    .frame(width: 360)
                VStack(alignment: .leading, spacing: 6) {
                    HStack(spacing: 6) {
                        Text("AlwaysConnect-分享配置.toml").font(.callout.weight(.medium))
                        Spacer()
                        if let exported {
                            if exported.to_fill > 0 { SharePill(text: "\(exported.to_fill) 个代理待对方换链接", color: .orange) }
                            SharePill(text: exported.contains_secrets ? "含密码" : "不含密码",
                                      color: exported.contains_secrets ? .red : .green)
                        }
                    }
                    ShareFileText(text: exported?.text ?? "")
                }
                .padding(.vertical, 18).padding(.trailing, 20)
            }
            Divider()
            HStack(spacing: 12) {
                if let note { Text(note).font(.caption).foregroundStyle(.secondary) }
                Spacer()
                Button("拷贝文本") {
                    guard let text = exported?.text else { return }
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(text, forType: .string)
                    note = "已拷贝。"
                }
                .disabled(exported == nil)
                Button("取消") { dismiss() }.keyboardShortcut(.cancelAction)
                Button("导出…") { saving = true }
                    .keyboardShortcut(.defaultAction)
                    .disabled(exported == nil)
            }
            .padding(16)
        }
        .frame(width: 980, height: 680)
        .fileExporter(isPresented: $saving, document: ShareFileDocument(text: exported?.text ?? ""),
                      contentType: ShareFileDocument.type, defaultFilename: "AlwaysConnect-分享配置") { outcome in
            switch outcome {
            case .success: dismiss()
            case .failure: note = "没有导出。请换个保存位置再试。"
            }
        }
    }

    @ViewBuilder private func options(_ exported: ConfigShare.Exported?) -> some View {
        Form {
            Section("内容") {
                Toggle("分流直连 · \(local.direct_sites.count) 条", isOn: $direct)
                    .toggleStyle(.checkbox)
                    .disabled(local.direct_sites.isEmpty && local.direct_exceptions.isEmpty)
                group("分流代理 · \(local.proxies.count) 个", all: Set(local.proxies.map(\.id)), selection: $proxies) {
                    ForEach(local.proxies, id: \.id) { p in
                        Toggle(p.name.isEmpty ? "未命名代理" : p.name, isOn: member(p.id, of: $proxies)).toggleStyle(.checkbox)
                    }
                }
                group("出口保护 · \(local.egress.count) 条", all: Set(local.egress.map(\.id)), selection: $egress) {
                    ForEach(local.egress, id: \.id) { g in
                        Toggle(g.name, isOn: member(g.id, of: $egress)).toggleStyle(.checkbox)
                    }
                }
                Toggle("Cisco 服务器 · \(local.cisco.servers.count) 台", isOn: $cisco)
                    .toggleStyle(.checkbox)
                    .disabled(local.cisco.servers.isEmpty)
                Toggle("通用开关 · 5 项", isOn: $general).toggleStyle(.checkbox)
            }
            Section {
                Toggle(isOn: Binding(get: { fullLinks }, set: { on in
                    if on && secretLocal == nil { secretLocal = ConfigShare.local(secrets: true) }
                    fullLinks = on
                })) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("代理的完整链接")
                        Text("含地址、账号和密码；拿到文件的人能直接用你的代理")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }
                .disabled(proxies.isEmpty)
            } header: {
                Text("敏感信息")
            } footer: {
                VStack(alignment: .leading, spacing: 4) {
                    Footnote("不打开时，链接里的地址、账号、密码写成橙色的 {…}，对方导入时粘贴自己的链接。Cisco 账号和密码不导出。")
                    if let renamed = exported?.renamed, !renamed.isEmpty {
                        Footnote("代理名「\(renamed.joined(separator: "」「"))」里带了服务器地址或账号，文件里改用编号。")
                    }
                }
            }
        }
        .formStyle(.grouped)
    }

    /// A part with items: the box ticks all or none, the items one by one.
    private func group<ID: Hashable, Items: View>(_ title: String, all: Set<ID>, selection: Binding<Set<ID>>,
                                                 @ViewBuilder items: () -> Items) -> some View {
        let content = items()
        return DisclosureGroup {
            content
        } label: {
            Toggle(title, isOn: Binding(get: { !selection.wrappedValue.isEmpty },
                                        set: { selection.wrappedValue = $0 ? all : [] }))
                .toggleStyle(.checkbox)
                .disabled(all.isEmpty)
        }
    }

    private func member<ID: Hashable>(_ id: ID, of set: Binding<Set<ID>>) -> Binding<Bool> {
        Binding(get: { set.wrappedValue.contains(id) },
                set: { on in if on { set.wrappedValue.insert(id) } else { set.wrappedValue.remove(id) } })
    }
}

// MARK: - Import

/// One column: what would be added (each part can be opened to read its
/// rules), then one link box per proxy. Only adds.
struct ShareImportSheet: View {
    @Environment(\.dismiss) private var dismiss
    let text: String
    let preview: ConfigShare.Preview
    let done: (ConfigShare.Outcome) -> Void

    @State private var direct: Bool
    @State private var egress: Bool
    @State private var cisco: Bool
    @State private var general = false
    @State private var open: Set<String> = []
    @State private var links: [Int: String]
    @State private var working = false

    init(text: String, preview: ConfigShare.Preview, done: @escaping (ConfigShare.Outcome) -> Void) {
        self.text = text
        self.preview = preview
        self.done = done
        let d = preview.direct
        _direct = State(initialValue: (d?.added_rules ?? 0) + (d?.added_exceptions ?? 0) > 0)
        _egress = State(initialValue: !preview.egress.isEmpty)
        _cisco = State(initialValue: (preview.cisco?.added ?? 0) > 0 || preview.cisco?.group != nil || preview.cisco?.selected != nil)
        _links = State(initialValue: Dictionary(uniqueKeysWithValues: preview.proxies.map { ($0.index, $0.complete ? $0.link : "") }))
    }

    private var linkProblem: Bool {
        links.values.contains { ConfigShare.parseLink($0)?.problem != nil }
    }

    private var nothing: Bool {
        !direct && !egress && !cisco && !general && preview.proxies.isEmpty
    }

    var body: some View {
        VStack(spacing: 0) {
            Form {
                Section {
                    if let d = preview.direct { directRow(d) }
                    if !preview.egress.isEmpty { egressRow }
                    if let c = preview.cisco { ciscoRow(c) }
                    if !preview.general.isEmpty { generalRow }
                    if preview.direct == nil && preview.egress.isEmpty && preview.cisco == nil && preview.general.isEmpty {
                        Text("文件里没有规则、出口保护或服务器。").foregroundStyle(.secondary)
                    }
                } header: {
                    VStack(alignment: .leading, spacing: 14) {
                        PageHeader(symbol: "square.and.arrow.down.fill", color: SettingsTone.account, title: "导入配置",
                                   status: headerLine)
                        Text("会加到你的设置里")
                    }
                } footer: {
                    Footnote("只加不删：你已有的规则、代理和设置都保留，同名的导入后加「（导入）」。点一行展开看具体内容。")
                }
                if !preview.proxies.isEmpty { proxySection }
                if !preview.skipped.isEmpty {
                    Section {
                        DisclosureGroup("文件里有 \(preview.skipped.count) 项用不了，已跳过") {
                            ForEach(preview.skipped, id: \.self) { Text($0).font(.caption).foregroundStyle(.secondary) }
                        }
                    }
                }
            }
            .formStyle(.grouped)
            Divider()
            HStack(spacing: 12) {
                if linkProblem { Text("有链接读不出来，改好或清空后才能导入").font(.caption).foregroundStyle(.orange) }
                Spacer()
                Button("取消") { dismiss() }.keyboardShortcut(.cancelAction)
                Button(working ? "正在导入…" : "导入") { run() }
                    .keyboardShortcut(.defaultAction)
                    .disabled(working || linkProblem || nothing)
            }
            .padding(16)
        }
        .frame(width: 640, height: 720)
    }

    private var headerLine: String {
        var parts = ["AlwaysConnect-分享配置"]
        if preview.legacy_egress { parts = ["出口保护备份"] }
        if !preview.app_version.isEmpty { parts.append("\(preview.app_version) 导出") }
        parts.append(preview.contains_secrets ? "含密码" : "不含密码")
        return parts.joined(separator: " · ")
    }

    // MARK: Rows

    private func directRow(_ d: ConfigShare.Preview.Direct) -> some View {
        let added = d.added_rules + d.added_exceptions
        var badge = [String]()
        if d.added_rules > 0 { badge.append("+\(d.added_rules) 规则") }
        if d.added_exceptions > 0 { badge.append("+\(d.added_exceptions) 例外") }
        let fresh = (d.rules + d.groups.flatMap(\.rules) + d.exceptions).filter(\.new).map(\.text)
        let sample = fresh.prefix(2).joined(separator: "、") + (fresh.count > 2 ? " 等" : "")
        return part("direct", title: "分流直连", subtitle: added == 0 ? "文件里的你都有了" : sample,
                    symbol: "arrow.triangle.branch", color: SettingsTone.direct,
                    badge: badge.isEmpty ? "已都有" : badge.joined(separator: "  "), on: $direct, enabled: added > 0) {
            RuleBox(title: "规则 · 命中的网站不走 Cisco（按网站分流时）", items: d.rules)
            ForEach(d.groups, id: \.self) { g in RuleBox(title: "分组「\(g.name)」", items: g.rules) }
            if !d.exceptions.isEmpty { RuleBox(title: "例外 · 命中的照常走 Cisco", items: d.exceptions) }
        }
    }

    private var egressRow: some View {
        let names = preview.egress.map(\.import_name).joined(separator: "、")
        return part("egress", title: "出口保护", subtitle: names + " · 先暂停", symbol: "checkmark.shield.fill",
                    color: SettingsTone.shield, badge: "+\(preview.egress.count)", on: $egress, enabled: true) {
            ForEach(preview.egress, id: \.self) { e in
                RuleBox(title: "「\(e.import_name)」只允许从 \(e.countries.joined(separator: "、")) 出去",
                        items: e.rules.map { ConfigShare.Item(text: $0, new: true) })
                if !e.exceptions.isEmpty {
                    RuleBox(title: "例外 · 不受这条保护", items: e.exceptions.map { ConfigShare.Item(text: $0, new: true) })
                }
            }
        }
    }

    private func ciscoRow(_ c: ConfigShare.Preview.Cisco) -> some View {
        let added = c.servers.filter(\.new).map(\.name)
        var extra = [String]()
        if let group = c.group { extra.append("组 \(group)") }
        if let selected = c.selected { extra.append("选中 \(selected)") }
        let subtitle = (added.isEmpty ? ["服务器你都有了"] : [added.joined(separator: "、")]) + extra
        let enabled = !added.isEmpty || !extra.isEmpty
        return part("cisco", title: "Cisco 服务器", subtitle: subtitle.joined(separator: " · "), symbol: "server.rack",
                    color: SettingsTone.vpn, badge: added.isEmpty ? (enabled ? "设置" : "已都有") : "+\(added.count)",
                    on: $cisco, enabled: enabled) {
            RuleBox(title: "服务器", items: c.servers.map {
                ConfigShare.Item(text: [$0.name, $0.address ?? $0.cisco_entry ?? ""].filter { !$0.isEmpty }.joined(separator: "  "),
                                 new: $0.new)
            })
            if !extra.isEmpty {
                Text("你本机还没有设置的才会填上：" + extra.joined(separator: "、")).font(.caption).foregroundStyle(.secondary)
            }
        }
    }

    private var generalRow: some View {
        let changes = preview.general
        return part("general", title: "通用开关",
                    subtitle: changes.map { "\($0.label) \($0.local ? "开" : "关") → \($0.file ? "开" : "关")" }.joined(separator: "、"),
                    symbol: "switch.2", color: SettingsTone.neutral, badge: "改 \(changes.count) 项", on: $general, enabled: true) {
            ForEach(changes, id: \.self) { c in
                Text("\(c.label)：本机\(c.local ? "开" : "关") → 文件\(c.file ? "开" : "关")").font(.callout)
            }
            if changes.contains(where: { $0.key == "drop_protection" && !$0.file }) {
                Text("关掉断线保护会同时关掉出口保护。").font(.caption).foregroundStyle(.orange)
            }
        }
    }

    private func part<Detail: View>(_ key: String, title: String, subtitle: String, symbol: String, color: Color,
                                    badge: String, on: Binding<Bool>, enabled: Bool,
                                    @ViewBuilder detail: () -> Detail) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                Button { toggle(key) } label: {
                    HStack(spacing: 8) {
                        Image(systemName: open.contains(key) ? "chevron.down" : "chevron.right")
                            .font(.caption.weight(.semibold)).foregroundStyle(.secondary).frame(width: 12)
                        IconLabel(title: title, subtitle: subtitle, symbol: symbol, color: color)
                            .lineLimit(1).truncationMode(.tail)
                        Spacer(minLength: 8)
                    }
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                SharePill(text: badge, color: on.wrappedValue && enabled ? .green : .secondary)
                Toggle("", isOn: on).labelsHidden().toggleStyle(.switch).controlSize(.small).disabled(!enabled)
            }
            if open.contains(key) {
                VStack(alignment: .leading, spacing: 6) { detail() }.padding(.leading, 20)
            }
        }
    }

    private func toggle(_ key: String) {
        if open.contains(key) { open.remove(key) } else { open.insert(key) }
    }

    // MARK: Proxies

    private var proxySection: some View {
        Section {
            ForEach(preview.proxies) { p in proxyRow(p) }
        } header: {
            HStack(spacing: 6) {
                Text("代理 · 粘贴你自己的链接")
                Spacer()
                HoverHelp(action: {}) { formats.frame(width: 360, alignment: .leading) }
            }
        } footer: {
            VStack(alignment: .leading, spacing: 4) {
                formats
                Footnote("没有就空着：代理先停用，它的规则照样导入，之后在「分流代理」里补。")
            }
        }
    }

    private var formats: some View {
        VStack(alignment: .leading, spacing: 3) {
            Footnote("链接格式（和「分流代理」里的代理地址框一样）：")
            Group {
                Text("socks5://用户名:密码@地址:端口      没有账号就写 socks5://地址:端口")
                Text("http://用户名:密码@地址:端口")
                Text("hysteria2://密码@地址:端口/?sni=域名&obfs=salamander&obfs-password=混淆密码")
            }
            .font(.system(size: 11, design: .monospaced)).foregroundStyle(.secondary)
            .textSelection(.enabled)
        }
    }

    private func proxyRow(_ p: ConfigShare.Preview.Proxy) -> some View {
        let key = "proxy-\(p.index)"
        let link = Binding(get: { links[p.index] ?? "" }, set: { links[p.index] = $0 })
        let parsed = ConfigShare.parseLink(link.wrappedValue)
        var counts = "\(p.kind) · \(p.rules.count) 条规则"
        if !p.exceptions.isEmpty { counts += " · \(p.exceptions.count) 条例外" }
        if p.import_name != p.name { counts += " · 导入后叫「\(p.import_name)」" }
        return VStack(alignment: .leading, spacing: 8) {
            Button { toggle(key) } label: {
                HStack(spacing: 8) {
                    Image(systemName: open.contains(key) ? "chevron.down" : "chevron.right")
                        .font(.caption.weight(.semibold)).foregroundStyle(.secondary).frame(width: 12)
                    IconLabel(title: p.name, subtitle: counts, symbol: "point.3.connected.trianglepath.dotted",
                              color: SettingsTone.proxy)
                    Spacer()
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            HStack(spacing: 6) {
                TextField("", text: link, prompt: Text(p.hint))
                    .textFieldStyle(.roundedBorder).labelsHidden()
                    .font(.system(size: 12, design: .monospaced))
                Group {
                    if let parsed, parsed.link != nil {
                        Image(systemName: "checkmark.circle.fill").foregroundStyle(.green)
                    } else if parsed?.problem != nil {
                        Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange)
                    } else {
                        Image(systemName: "circle.dashed").foregroundStyle(.tertiary)
                    }
                }
                .frame(width: 16)
            }
            .padding(.leading, 20)
            if let parsed {
                Text(parsed.link?.summary ?? parsed.problem ?? "")
                    .font(.caption).foregroundStyle(parsed.link == nil ? Color.orange : Color.green)
                    .padding(.leading, 20)
            }
            if open.contains(key) {
                VStack(alignment: .leading, spacing: 6) {
                    RuleBox(title: "经这个代理的网站", items: p.rules.map { ConfigShare.Item(text: $0, new: true) })
                    if !p.exceptions.isEmpty {
                        RuleBox(title: "例外 · 跳过这个代理", items: p.exceptions.map { ConfigShare.Item(text: $0, new: true) })
                    }
                }
                .padding(.leading, 20)
            }
        }
        .padding(.vertical, 2)
    }

    private func run() {
        working = true
        let choices = ConfigShare.Choices(direct: direct, proxies: true, egress: egress, cisco: cisco, general: general,
                                          links: links)
        ConfigShare.importNow(text, choices: choices) { outcome in
            working = false
            done(outcome)
            dismiss()
        }
    }
}

/// A part's rules, one per line; ones this Mac has are dimmed.
private struct RuleBox: View {
    var title: String
    var items: [ConfigShare.Item]

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title).font(.caption.weight(.medium)).foregroundStyle(.secondary)
            ScrollView {
                VStack(alignment: .leading, spacing: 3) {
                    ForEach(Array(items.enumerated()), id: \.offset) { _, item in
                        HStack(spacing: 6) {
                            Text(item.text).font(.system(size: 12, design: .monospaced))
                                .foregroundStyle(item.new ? Color.primary : Color.secondary)
                                .textSelection(.enabled)
                            if !item.new { Text("已有，跳过").font(.caption2).foregroundStyle(.tertiary) }
                        }
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .frame(maxHeight: items.count > 8 ? 160 : nil)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(10)
        .background(RoundedRectangle(cornerRadius: 7, style: .continuous).fill(Color.primary.opacity(0.04)))
    }
}
