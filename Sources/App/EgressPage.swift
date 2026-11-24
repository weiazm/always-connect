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
        case add(UInt32?), details(UInt32), unknownWeb
        var id: String {
            switch self {
            case .add(let id): return "add-\(id ?? 0)"
            case .details(let id): return "details-\(id)"
            case .unknownWeb: return "unknown-web"
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

    /// Only app rules are shown and edited (§66.24); website rules are retired.
    private var config: EgressProtection {
        var result = stored.rulesForEditing
        result.groups.removeAll { !$0.byApp }
        return result
    }
    private var legacyRules: [EgressProtection.Group] { stored.groups.filter { !$0.byApp } }
    private var connected: Bool { preview?.connected ?? manager.showsConnected }
    private var available: Bool { preview?.available ?? (!manager.usesCisco && manager.protectsDrops) }
    private var active: [EgressProtection.Group] { config.groups.filter(\.enabled) }
    private var liveStatus: EgressProtection.Status? { connected ? status : nil }

    var body: some View {
        let decisions = liveStatus?.decisions(config: config) ?? []
        Form {
            Section {
                statusBar
                if !legacyRules.isEmpty {
                    EgressCallout(icon: "arrow.triangle.2.circlepath", tint: .accentColor,
                                  text: "出口保护改成了按 App 保护",
                                  caption: "以前按网站设的 \(legacyRules.count) 个保护\(stored.isActive ? "还在生效" : "已不再使用")；添加 App 后会自动替换。") {
                        Button("现在移除") { change { _ in } }
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
                Text("选好的 App 经 VPN 的每条新连接先确认从哪个国家出去，不对就拦下再问你；别的程序完全不受影响。查不到出口的连接先放行并记数。选中 App 的连接约多等半秒，也不用 QUIC。")
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
                var offline = imported.rulesForEditing
                offline.groups.removeAll { !$0.byApp }
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
            Button { sheet = .add(nil) } label: { Label("添加 App", systemImage: "plus") }
                .buttonStyle(.borderedProminent)
                .disabled(!available || busy)
        }
        .padding(.vertical, 2)
    }

    private var moreMenu: some View {
        Menu {
            Button("导入备份…") { importing = true }
            Button("导出备份…") { exporting = true }.disabled(config.groups.isEmpty)
        } label: {
            Image(systemName: "ellipsis.circle").font(.title3)
        }
        .menuStyle(.borderlessButton).menuIndicator(.hidden).fixedSize()
        .disabled(!available || busy)
        .help("备份：导入、导出")
    }

    private struct StatusLook {
        var tint: Color
        var line: String
        var lineColor: Color = .primary
    }

    private var statusLook: StatusLook {
        let sites = Set(active.flatMap(\.apps)).count
        if preview == nil && manager.usesCisco {
            return .init(tint: .gray, line: "要先在「分流」页打开「按网站分流」才能用", lineColor: .secondary)
        }
        if !available { return .init(tint: .gray, line: "要先打开断线保护才能用", lineColor: .secondary) }
        if config.groups.isEmpty { return .init(tint: .gray, line: "还没开始用：先添加一个 App", lineColor: .secondary) }
        if active.isEmpty { return .init(tint: .gray, line: "已全部暂停", lineColor: .secondary) }
        guard connected else { return .init(tint: .accentColor, line: "\(sites) 个 App 受保护 · VPN 连上后开始检查") }
        switch liveStatus?.displayLevel(expectedRules: Set(active.map(\.id))) ?? .unknown {
        case .ok: return .init(tint: .green, line: "一切正常 · 正在保护 \(sites) 个 App")
        case .partial:
            let count = liveStatus?.blockedCount ?? 0
            return .init(tint: .orange, line: count > 0 ? "这次已拦下 \(count) 条出口不对的连接" : "有些连接出口不对，已拦下",
                         lineColor: .orange)
        case .blocked: return .init(tint: .red, line: "有连接被拦住了，需要你决定", lineColor: .red)
        case .unknown: return .init(tint: .accentColor, line: "\(sites) 个 App 受保护 · 等它们连网时核实出口")
        }
    }

    private var emptyState: some View {
        VStack(spacing: 10) {
            Image(systemName: "app.badge.checkmark").font(.system(size: 34)).foregroundStyle(.secondary)
            Text("还没有受保护的 App").font(.headline)
            Text("选好 App 和允许的国家。它经 VPN 的每条连接都会先确认出口，\n不对就拦下再问你；别的程序不受影响。")
                .font(.callout).foregroundStyle(.secondary).multilineTextAlignment(.center)
            Button("添加 App…") { sheet = .add(nil) }
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
            Text("App").frame(maxWidth: .infinity, alignment: .leading)
            Text("只从这里出去").frame(width: Self.countryWidth, alignment: .leading)
            Text("状态").frame(width: Self.stateWidth, alignment: .leading)
            Text("保护").frame(width: Self.switchWidth)
        }
        .font(.caption).foregroundStyle(.secondary)
    }

    private func ruleRow(_ group: EgressProtection.Group, decisions: [EgressDecision]) -> some View {
        let state = liveStatus?.groups.first { $0.id == group.id }
        let badge = EgressRuleBadge.of(group, config: config, state: state, connected: connected)
        let canEnable = (group.byApp || !config.directMembers(in: group).isEmpty) && !group.expect.isEmpty
        let problem = group.enabled && decisions.isEmpty ? badge.problem : nil
        let unverified = connected ? state?.unverifiedCount ?? 0 : 0
        return VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                Button { sheet = .details(group.id) } label: {
                    HStack(spacing: 10) {
                        Image(nsImage: EgressApps.icon(group.apps.first ?? "")).resizable().frame(width: 26, height: 26)
                            .opacity(group.enabled ? 1 : 0.45)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(group.name).fontWeight(.medium).lineLimit(1)
                            if let problem {
                                Text(problem).font(.caption).foregroundStyle(badge.color).lineLimit(2)
                            } else {
                                Text(group.appNames.joined(separator: "、")
                                     + (unverified > 0 ? " · \(unverified) 条查不到出口，已放行" : ""))
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
                .help(group.enabled ? "暂停保护这个 App" : "恢复保护")
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
        case .add(let id):
            EgressAppPicker(rule: config.groups.first { $0.id == id },
                            countries: config.groups.last?.expect ?? []) { apps, countries, done in
                addApps(apps, countries: countries, to: id, done: done)
            }
        case .details(let id):
            if let group = config.groups.first(where: { $0.id == id }) {
                EgressRuleDetail(rule: group, config: config, status: liveStatus, connected: connected, refresh: refresh,
                                 addApp: { sheet = .add(id) },
                                 edit: { edit in changeRule(id, edit: edit) }, pause: pause,
                                 remove: { sheet = nil; change { $0.groups.removeAll { $0.id == id } } })
            }
        case .unknownWeb:
            EgressUnknownWebView(config: stored, status: liveStatus, refresh: refresh)
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

    private func addApps(_ apps: [String], countries: [String], to id: UInt32?, done: @escaping (Bool) -> Void) {
        let names = apps.map(EgressApps.displayName)
        if let id {
            changeRule(id, edit: { rule in
                for app in apps where !rule.apps.contains(app) { rule.apps.append(app) }
            }, completion: done)
            return
        }
        var group = EgressProtection.newGroup(in: stored, name: names.count > 1 ? "\(names[0]) 等 \(names.count) 个" : names[0])
        group.enabled = true
        group.apps = apps
        group.expect = countries
        change({ $0.groups.append(group) }, completion: { ok in
            if ok { message = nil }
            done(ok)
        })
    }

    private func changeRule(_ id: UInt32, edit: (inout EgressProtection.Group) -> Void, completion: ((Bool) -> Void)? = nil) {
        change({ config in
            if let index = config.groups.firstIndex(where: { $0.id == id }) { edit(&config.groups[index]) }
        }, completion: completion)
    }

    private func change(_ edit: (inout EgressProtection) -> Void, completion: ((Bool) -> Void)? = nil) {
        guard preview == nil else { return }
        let previous = ProfileStore.loadAppSettings().egressProtection ?? EgressProtection()
        // Website rules are retired (§66.24): any save keeps only app rules.
        let change = EgressRuleChange(config: previous) { config in
            config.groups.removeAll { !$0.byApp }
            edit(&config)
        }
        guard change.after.permitsActivation(comparedTo: previous) else {
            message = "先选允许的国家或地区，才能打开这个保护。"
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
