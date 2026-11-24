import AppKit
import SwiftUI
import UniformTypeIdentifiers

/// Fixed data instead of the background service (offscreen screenshots).
struct EgressPagePreview {
    var config: EgressProtection
    var status: EgressProtection.Status?
    var connected = true
    var available = true
    var connections: [ConnectionRow] = []
}

/// Settings → 出口保护 (UI-DESIGN.md「出口保护页」, 2026-11-24 redesign).
/// Layout B chosen by the maintainer (2026-11-24): one status line with
/// 添加网站 and a ⋯ menu, then a compact table of websites; a question about
/// a website appears right under its row.
struct EgressProtectionPage: View {
    @ObservedObject private var manager = HelperClient.shared
    @ObservedObject private var window = SettingsWindow.shared
    var preview: EgressPagePreview? = nil
    @State private var stored = ProfileStore.loadAppSettings().egressProtection ?? EgressProtection()
    @State private var status: EgressProtection.Status?
    @State private var confirm: EgressRuleChange?
    @State private var sheet: Sheet?
    @State private var busy = false
    @State private var visible = false
    @State private var message: String?
    @State private var notice: EgressChangeNotice?
    @State private var importing = false
    @State private var exporting = false
    @State private var confirmDropProtection = false

    enum Sheet: Identifiable {
        case add(UInt32?), details(UInt32), advanced(UInt32), unknownWeb, methods
        var id: String {
            switch self {
            case .add(let id): return "add-\(id ?? 0)"
            case .details(let id): return "details-\(id)"
            case .advanced(let id): return "advanced-\(id)"
            case .unknownWeb: return "unknown-web"
            case .methods: return "methods"
            }
        }
    }

    init(preview: EgressPagePreview? = nil, sheet: Sheet? = nil) {
        self.preview = preview
        if let preview {
            _stored = State(initialValue: preview.config)
            _status = State(initialValue: preview.status)
        }
        _sheet = State(initialValue: sheet)
    }

    private var config: EgressProtection { stored.rulesForEditing }
    private var connected: Bool { preview?.connected ?? manager.showsConnected }
    private var available: Bool { preview?.available ?? (!manager.usesCisco && manager.protectsDrops) }
    private var active: [EgressProtection.Group] { config.groups.filter(\.enabled) }
    private var liveStatus: EgressProtection.Status? { connected ? status : nil }

    var body: some View {
        let decisions = liveStatus?.decisions(config: config) ?? []
        Form {
            Section {
                statusBar
                if let count = liveStatus?.unknownWebCount, count > 0, config.isActive, config.blocksUnidentifiedWeb {
                    HStack {
                        Label("认不出网站名的网页连接，这次拦下 \(count) 条", systemImage: "questionmark.diamond")
                            .font(.callout).foregroundStyle(.secondary)
                        Spacer()
                        Button("查看…") { sheet = .unknownWeb }.buttonStyle(.borderless)
                    }
                }
                if let confirm {
                    EgressReconnectPrompt(change: confirm, cancel: { self.confirm = nil }) {
                        self.confirm = nil
                        apply(confirm)
                    }
                }
                if let notice {
                    EgressChangeBanner(notice: notice) { undo(notice) }
                }
                if let message {
                    EgressCallout(icon: "exclamationmark.triangle.fill", tint: .orange, text: message) {
                        Button("知道了") { self.message = nil }
                    }
                }
            } footer: {
                Text("选好的网站只从你认可的国家或地区出去；出口一变，先拦住再问你。开着时每条新连接约多等半秒，走 VPN 的连接不用 QUIC（浏览器会自动改用普通 HTTPS）。")
                    .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
            Section {
                if config.groups.isEmpty {
                    emptyState
                } else {
                    tableHeader
                    ForEach(config.groups) { group in
                        ruleRow(group, decisions: decisions.filter { $0.rule == group.id })
                    }
                }
            }
            .disabled(!available || busy)
            if let records = liveStatus?.records, !records.isEmpty {
                Section {
                    DisclosureGroup {
                        ForEach(records.prefix(8), id: \.started) { record in recordRow(record) }
                    } label: {
                        let open = records.filter { $0.ended == nil }.count
                        Text("最近拦截 · \(records.count) 条" + (open > 0 ? "（\(open) 条拦截中）" : ""))
                    }
                }
            }
        }
        .formStyle(.grouped)
        .onAppear { visible = true; refresh(); openRequestedRule() }
        .onDisappear { visible = false; status = nil }
        .onChange(of: window.egressRuleToOpen) { _ in openRequestedRule() }
        .onChange(of: window.unknownEgressRequested) { _ in openRequestedRule() }
        .onChange(of: manager.showsConnected) { _ in refresh() }
        .background {
            if visible && config.isActive && preview == nil {
                Color.clear.onReceive(Timer.publish(every: 5, tolerance: 1, on: .main, in: .common).autoconnect()) { _ in refresh() }
            }
        }
        .task(id: notice?.id) {
            guard let notice else { return }
            try? await Task.sleep(nanoseconds: 12_000_000_000)
            if !Task.isCancelled && self.notice?.id == notice.id { self.notice = nil }
        }
        .sheet(item: $sheet) { page in sheetView(page) }
        .fileImporter(isPresented: $importing, allowedContentTypes: [.json]) { result in
            do {
                let url = try result.get()
                let opened = url.startAccessingSecurityScopedResource()
                defer { if opened { url.stopAccessingSecurityScopedResource() } }
                var imported = try JSONDecoder().decode(EgressProtection.self, from: Data(contentsOf: url))
                imported.enabled = false
                imported.blockUnidentifiedWeb = nil
                for index in imported.groups.indices { imported.groups[index].exitRangeCheck = false }
                let offline = imported.rulesForEditing
                change { $0 = offline }
                if message == nil {
                    notice = nil
                    message = "已导入 \(offline.groups.count) 个保护，都先处于暂停状态；逐个打开前会重新确认出口。"
                }
            } catch { message = "这个文件读不出来。请选之前导出的 JSON 文件。" }
        }
        .fileExporter(isPresented: $exporting, document: EgressConfigFile(config: stored),
                      contentType: .json, defaultFilename: "AlwaysConnect-出口保护") { result in
            if case .failure = result { message = "没有导出。请换个保存位置再试。" }
        }
        .alert("打开断线保护？", isPresented: $confirmDropProtection) {
            Button("取消", role: .cancel) {}
            Button("打开") {
                var settings = ProfileStore.loadAppSettings()
                settings.dropProtection = true
                ProfileStore.saveAppSettings(settings)
                manager.dropProtectionChanged()
            }
        } message: { Text("VPN 断开时会暂时拦住网络，直到重新连上或你手动断开。") }
    }

    // MARK: - Top

    private var statusBar: some View {
        let look = statusLook
        return HStack(spacing: 10) {
            Circle().fill(look.tint).frame(width: 10, height: 10)
            Text(look.line).fontWeight(.medium).foregroundStyle(look.lineColor)
            Spacer(minLength: 8)
            if preview == nil && manager.usesCisco {
                Button("去「分流」打开") { UserDefaults.standard.set("split", forKey: "settingsTab") }
            } else if !(preview?.available ?? manager.protectsDrops) {
                Button("打开断线保护") { confirmDropProtection = true }
            }
            moreMenu
            Button { sheet = .add(nil) } label: { Label("添加网站", systemImage: "plus") }
                .buttonStyle(.borderedProminent)
                .disabled(!available || busy)
        }
        .padding(.vertical, 2)
    }

    private var moreMenu: some View {
        Menu {
            if config.isActive {
                Button("认不出网站的连接…") { sheet = .unknownWeb }
            }
            Button("检查出口的方法…") { sheet = .methods }
            Divider()
            Button("导入备份…") { importing = true }
            Button("导出备份…") { exporting = true }.disabled(config.groups.isEmpty)
        } label: {
            Image(systemName: "ellipsis.circle").font(.title3)
        }
        .menuStyle(.borderlessButton).menuIndicator(.hidden).fixedSize()
        .disabled(!available || busy)
        .help("更多：认不出网站的连接、检查出口的方法、备份")
    }

    private struct StatusLook {
        var tint: Color
        var line: String
        var lineColor: Color = .primary
    }

    private var statusLook: StatusLook {
        let sites = Set(active.flatMap(\.websiteNames)).count
        if preview == nil && manager.usesCisco {
            return .init(tint: .gray, line: "要先在「分流」页打开「按网站分流」才能用", lineColor: .secondary)
        }
        if !available { return .init(tint: .gray, line: "要先打开断线保护才能用", lineColor: .secondary) }
        if config.groups.isEmpty { return .init(tint: .gray, line: "还没开始用：先添加一个网站", lineColor: .secondary) }
        if active.isEmpty { return .init(tint: .gray, line: "已全部暂停", lineColor: .secondary) }
        guard connected else { return .init(tint: .accentColor, line: "\(sites) 个网站受保护 · VPN 连上后开始检查") }
        switch liveStatus?.displayLevel(expectedRules: Set(active.map(\.id))) ?? .unknown {
        case .ok: return .init(tint: .green, line: "一切正常 · 正在保护 \(sites) 个网站")
        case .partial:
            let count = liveStatus?.blockedCount ?? 0
            return .init(tint: .orange, line: count > 0 ? "这次已拦下 \(count) 条出口不对的连接" : "有些连接出口不对，已拦下",
                         lineColor: .orange)
        case .blocked: return .init(tint: .red, line: "有网站被拦住了，需要你决定", lineColor: .red)
        case .unknown: return .init(tint: .accentColor, line: "正在核实出口… · \(sites) 个网站受保护")
        }
    }

    private var emptyState: some View {
        VStack(spacing: 10) {
            Image(systemName: "globe.asia.australia.fill").font(.system(size: 34)).foregroundStyle(.secondary)
            Text("还没有受保护的网站").font(.headline)
            Text("添加后，App 会记下它现在从哪个国家出去。\n以后出口变了，就先拦住再问你。")
                .font(.callout).foregroundStyle(.secondary).multilineTextAlignment(.center)
            Button("添加网站…") { sheet = .add(nil) }
                .buttonStyle(.borderedProminent).controlSize(.large).padding(.top, 4)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 22)
    }

    // MARK: - Table

    private static let countryWidth: CGFloat = 160
    private static let stateWidth: CGFloat = 96
    private static let switchWidth: CGFloat = 56

    private var tableHeader: some View {
        HStack(spacing: 8) {
            Text("网站").frame(maxWidth: .infinity, alignment: .leading)
            Text("只从这里出去").frame(width: Self.countryWidth, alignment: .leading)
            Text("状态").frame(width: Self.stateWidth, alignment: .leading)
            Text("保护").frame(width: Self.switchWidth)
        }
        .font(.caption).foregroundStyle(.secondary)
    }

    private func ruleRow(_ group: EgressProtection.Group, decisions: [EgressDecision]) -> some View {
        let state = liveStatus?.groups.first { $0.id == group.id }
        let badge = EgressRuleBadge.of(group, config: config, state: state, connected: connected)
        let canEnable = !config.directMembers(in: group).isEmpty && !group.expect.isEmpty
        let sites = group.websiteNames.map { $0.hasSuffix("/32") ? String($0.dropLast(3)) : $0 }
        let problem = group.enabled && decisions.isEmpty ? badge.problem : nil
        return VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                Button { sheet = .details(group.id) } label: {
                    HStack(spacing: 8) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(group.name).fontWeight(.medium).lineLimit(1)
                            if let problem {
                                Text(problem).font(.caption).foregroundStyle(badge.color).lineLimit(2)
                            } else {
                                Text(sites.joined(separator: "、") + (group.exitRangeCheck ? " · 核对出口地址" : ""))
                                    .font(.caption).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                            }
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                        Text(egressCountriesLabel(group.expect)).lineLimit(1)
                            .foregroundStyle(group.enabled ? Color.primary : Color.secondary)
                            .frame(width: Self.countryWidth, alignment: .leading)
                        EgressStatusPill(badge: badge).frame(width: Self.stateWidth, alignment: .leading)
                    }
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .help("点开看详情")
                Toggle("", isOn: Binding(get: { group.enabled }, set: { on in
                    if on && !canEnable { sheet = .details(group.id); return }
                    changeRule(group.id) { $0.enabled = on }
                }))
                .labelsHidden().toggleStyle(.always).fixedSize()
                .frame(width: Self.switchWidth)
                .help(group.enabled ? "暂停保护这个网站" : "恢复保护")
            }
            if !decisions.isEmpty {
                EgressDecisionList(decisions: decisions, refresh: refresh, pause: pause)
            }
        }
        .padding(.vertical, 3)
    }

    private func recordRow(_ record: EgressProtection.BlockRecord) -> some View {
        let date = Date(timeIntervalSince1970: record.started)
        let cause = record.observed.lazy.compactMap(\.exitRangeFailureCaption).first
            ?? record.observed.first(where: { $0.country != nil && $0.isOutside(record.expected) })
                .map { "出口在 \(egressCountryLabel($0.country ?? ""))，不在允许范围" }
            ?? "没能核实出口"
        let open = record.ended == nil
        return Button { sheet = .details(record.group) } label: {
            HStack(spacing: 10) {
                Image(systemName: open ? "hand.raised.fill" : "checkmark.circle")
                    .foregroundStyle(open ? Color.orange : Color.secondary).frame(width: 18)
                VStack(alignment: .leading, spacing: 2) {
                    Text(record.host ?? record.name).lineLimit(1)
                    Text(cause).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                }
                Spacer()
                Text(open ? "拦截中" : "已恢复").font(.caption)
                    .foregroundStyle(open ? Color.orange : Color.secondary)
                Text(date, format: .dateTime.hour().minute()).font(.caption.monospacedDigit()).foregroundStyle(.secondary)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }

    // MARK: - Sheets

    @ViewBuilder private func sheetView(_ page: Sheet) -> some View {
        switch page {
        case .add(let rule):
            EgressAddSheet(rule: rule, preview: preview?.connections) { change, site in
                notice = .init(text: "已开始保护 \(site)", change: change)
                refresh()
            }
        case .details(let id):
            if let group = config.groups.first(where: { $0.id == id }) {
                EgressRuleDetail(rule: group, config: config, status: liveStatus, connected: connected, refresh: refresh,
                                 addWebsite: { sheet = .add(id) }, advanced: { sheet = .advanced(id) },
                                 edit: { edit in changeRule(id, edit: edit) }, pause: pause,
                                 remove: { sheet = nil; change { $0.groups.removeAll { $0.id == id } } })
            }
        case .advanced(let id):
            if let group = config.groups.first(where: { $0.id == id }) {
                EgressGroupEditor(group: group, config: config) { group, done in
                    changeRule(id, edit: { $0 = group }, completion: done)
                }
            }
        case .unknownWeb:
            EgressUnknownWebView(config: stored, status: liveStatus, refresh: refresh)
        case .methods:
            EgressMethodsSheet(config: config) { edit, done in change(edit, completion: done) }
        }
    }

    private func openRequestedRule() {
        guard visible, preview == nil else { return }
        if window.unknownEgressRequested {
            window.unknownEgressRequested = false
            if config.isActive && available { sheet = .unknownWeb }
            return
        }
        guard let id = window.egressRuleToOpen else { return }
        window.egressRuleToOpen = nil
        if config.groups.contains(where: { $0.id == id }) { sheet = .details(id) }
    }

    // MARK: - Changes

    private func pause(_ id: UInt32) { changeRule(id) { $0.enabled = false } }

    private func changeRule(_ id: UInt32, edit: (inout EgressProtection.Group) -> Void, completion: ((Bool) -> Void)? = nil) {
        change({ config in
            if let index = config.groups.firstIndex(where: { $0.id == id }) { edit(&config.groups[index]) }
        }, completion: completion)
    }

    private func change(_ edit: (inout EgressProtection) -> Void, completion: ((Bool) -> Void)? = nil) {
        guard preview == nil else { return }
        let previous = ProfileStore.loadAppSettings().egressProtection ?? EgressProtection()
        let change = EgressRuleChange(config: previous, edit: edit)
        guard change.after.permitsActivation(comparedTo: previous) else {
            message = "先加一个能直接检查出口的网站，才能打开这个保护。"
            completion?(false)
            return
        }
        if change.needsReconnect(connected: manager.showsConnected) {
            // The question must be where the user is looking: close any sheet.
            sheet = nil
            confirm = change
            completion?(false)
        } else { apply(change, completion: completion) }
    }

    private func apply(_ change: EgressRuleChange, completion: ((Bool) -> Void)? = nil) {
        busy = true
        manager.saveEgress(change.after, replacing: change.before) { ok in
            busy = false
            message = ok ? nil : "没有保存。设置可能刚被改过，请关掉设置窗口再打开试试。"
            refresh()
            completion?(ok)
        }
    }

    private func undo(_ notice: EgressChangeNotice) {
        let change = notice.change.undo
        self.notice = nil
        if change.needsReconnect(connected: manager.showsConnected) { confirm = change }
        else { apply(change) }
    }

    private func refresh() {
        guard preview == nil else { return }
        stored = ProfileStore.loadAppSettings().egressProtection ?? EgressProtection()
        guard visible, config.isActive, manager.showsConnected else { status = nil; return }
        manager.fetchEgressJSON { json in
            guard visible, config.isActive, manager.showsConnected else { return }
            status = json.flatMap { try? JSONDecoder().decode(EgressProtection.Status.self, from: Data($0.utf8)) }
        }
    }
}

struct EgressConfigFile: FileDocument {
    static let readableContentTypes: [UTType] = [.json]
    let config: EgressProtection

    init(config: EgressProtection) { self.config = config }
    init(configuration: ReadConfiguration) throws {
        config = try JSONDecoder().decode(EgressProtection.self, from: configuration.file.regularFileContents ?? Data())
    }
    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        return FileWrapper(regularFileWithContents: try encoder.encode(config))
    }
}

/// The ways of looking up a website's exit country. Two built in; the
/// rest are for people who know what a response header is.
struct EgressMethodsSheet: View {
    @Environment(\.dismiss) private var dismiss
    let config: EgressProtection
    let change: ((inout EgressProtection) -> Void, @escaping (Bool) -> Void) -> Void
    @State private var editing: EgressProtection.Method?

    var body: some View {
        VStack(spacing: 0) {
            VStack(alignment: .leading, spacing: 4) {
                Text("检查出口的方法").font(.title3.weight(.semibold))
                Text("App 用这些方法问网站「你看到我从哪个国家来」。自带的两种覆盖大多数网站；只有某个网站一直查不出出口时，才需要加新的。")
                    .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(20)
            Form {
                Section {
                    ForEach(config.availableMethods) { method in
                        let custom = config.methods.contains { $0.id == method.id }
                            && !EgressProtection.Method.presets.contains { $0.id == method.id }
                        HStack {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(method.name)
                                Text(method.isDirect ? "直接问网站本身，结果可以用来放行或拦截" : "问第三方，只作参考")
                                    .font(.caption).foregroundStyle(.secondary)
                            }
                            Spacer()
                            Button("编辑…") { editing = method }
                            if custom {
                                Button("删除", role: .destructive) {
                                    change({ $0.methods.removeAll { $0.id == method.id } }, { _ in })
                                }
                            }
                        }
                    }
                    Button {
                        editing = .init(id: UUID().uuidString, name: "", url: "https://{host}/",
                                        extract: .init(kind: .json, key: "country"))
                    } label: { Label("添加方法…", systemImage: "plus.circle.fill") }
                    .buttonStyle(.borderless)
                }
            }
            .formStyle(.grouped)
            Divider()
            HStack {
                Spacer()
                Button("完成") { dismiss() }.keyboardShortcut(.defaultAction)
            }
            .padding(16)
        }
        .frame(width: 520, height: 420)
        .sheet(item: $editing) { method in
            EgressMethodEditor(method: method) { value, done in
                change({ current in
                    current.methods.removeAll { $0.id == value.id }
                    current.methods.append(value)
                }, done)
            }
        }
    }
}
