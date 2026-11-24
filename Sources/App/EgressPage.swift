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
        case addSites, details(UInt32)
        var id: String {
            switch self {
            case .addSites: return "add-sites"
            case .details(let id): return "details-\(id)"
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
                Text("命中规则的新连接先检查出口，走错国家就拦。查不到出口时按各保护的设置处理。出口保护开启时，VPN 内的 QUIC 流量会被拦。")
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
                var imported = try JSONDecoder().decode(EgressProtection.self, from: Data(contentsOf: url)).withoutExpandedMatches
                imported.enabled = false
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
            Button { sheet = .addSites } label: { Label("添加保护", systemImage: "plus") }
                .buttonStyle(.borderedProminent)
                .disabled(!available || busy)
        }
        .padding(.vertical, 2)
    }

    private var moreMenu: some View {
        Menu {
            Button("拷贝全部规则") {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(EgressRuleInput.text(of: config), forType: .string)
            }
            .disabled(!config.groups.contains { !$0.sites.isEmpty })
            Button("导入备份…") { importing = true }
            Button("导出备份…") { exporting = true }.disabled(config.groups.isEmpty)
        } label: {
            Image(systemName: "ellipsis.circle").font(.title3)
        }
        .menuStyle(.borderlessButton).menuIndicator(.hidden).fixedSize()
        .disabled(!available || busy)
        .help("拷贝规则或管理备份")
    }

    private struct StatusLook {
        var tint: Color
        var line: String
        var lineColor: Color = .primary
    }

    private var statusLook: StatusLook {
        let ruleCount = active.count
        if preview == nil && manager.usesCisco {
            return .init(tint: .gray, line: "要先在「分流」页打开「按网站分流」才能用", lineColor: .secondary)
        }
        if !available { return .init(tint: .gray, line: "要先打开断线保护才能用", lineColor: .secondary) }
        if config.groups.isEmpty { return .init(tint: .gray, line: "还没开始用：先添加一个保护", lineColor: .secondary) }
        if active.isEmpty { return .init(tint: .gray, line: "已全部暂停", lineColor: .secondary) }
        guard connected else { return .init(tint: .accentColor, line: "\(ruleCount) 个保护已开启 · VPN 连上后开始检查") }
        switch liveStatus?.displayLevel(expectedRules: Set(active.map(\.id))) ?? .unknown {
        case .ok: return .init(tint: .green, line: "一切正常 · \(ruleCount) 个保护已开启")
        case .partial:
            let count = liveStatus?.blockedCount ?? 0
            return .init(tint: .orange, line: count > 0 ? "这次已拦下 \(count) 次连接" : "部分连接已拦下",
                         lineColor: .orange)
        case .unknown: return .init(tint: .accentColor, line: "\(ruleCount) 个保护已开启 · 有连接时核实出口")
        }
    }

    private var emptyState: some View {
        VStack(spacing: 10) {
            Image(systemName: "globe.asia.australia.fill").font(.system(size: 34)).foregroundStyle(.secondary)
            Text("还没有出口保护").font(.headline)
            Text("加入要保护的网站或网段，并选择允许的出口国家。")
                .font(.callout).foregroundStyle(.secondary).multilineTextAlignment(.center)
            Button("添加保护…") { sheet = .addSites }
                .buttonStyle(.borderedProminent).controlSize(.large).padding(.top, 4)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 22)
    }

    // MARK: - Table

    private static let countryWidth: CGFloat = 160
    private static let stateWidth: CGFloat = 96
    private static let switchWidth: CGFloat = 56
    private static let deleteWidth: CGFloat = 24

    private var tableHeader: some View {
        HStack(spacing: 8) {
            Text("保护规则").frame(maxWidth: .infinity, alignment: .leading)
            Text("只从这里出去").frame(width: Self.countryWidth, alignment: .leading)
            Text("状态").frame(width: Self.stateWidth, alignment: .leading)
            Text("保护").frame(width: Self.switchWidth)
            Color.clear.frame(width: Self.deleteWidth, height: 1)
        }
        .font(.caption).foregroundStyle(.secondary)
    }

    private func ruleRow(_ group: EgressProtection.Group, decisions: [EgressDecision]) -> some View {
        let state = liveStatus?.groups.first { $0.id == group.id }
        let badge = EgressRuleBadge.of(group, config: config, state: state, connected: connected)
        let canEnable = !group.sites.isEmpty && !group.expect.isEmpty
        let problem = group.enabled && decisions.isEmpty ? badge.problem : nil
        let unverified = connected ? state?.unverifiedCount ?? 0 : 0
        return VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                Button { sheet = .details(group.id) } label: {
                    HStack(spacing: 10) {
                        EgressSiteAvatar(name: group.sites.first ?? group.name, size: 26)
                            .opacity(group.enabled ? 1 : 0.45)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(group.name).fontWeight(.medium).lineLimit(1)
                            // The rules themselves, not only how many (user, 2026-11-24).
                            Text(group.sites.joined(separator: "、"))
                                .font(.caption).foregroundStyle(.secondary).lineLimit(1).truncationMode(.tail)
                                .help(group.sites.joined(separator: "\n"))
                            Text("\(group.sites.count) 条规则 · 查不到出口时：\(group.unverified.label)")
                                .font(.caption).foregroundStyle(.secondary).lineLimit(1)
                            if let problem {
                                Text(problem).font(.caption).foregroundStyle(badge.color).lineLimit(2)
                            } else if unverified > 0 {
                                Text("\(unverified) 次查不到出口，已放行").font(.caption).foregroundStyle(.secondary)
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
                .help(group.enabled ? "暂停这个保护" : "恢复保护")
                // Deleting is one click away on the row (user, 2026-11-24:
                // "应该直接漏出一个删除的能力"); the banner offers 撤销.
                Button { deleteRule(group.id) } label: {
                    Image(systemName: "trash").foregroundStyle(.secondary)
                }
                .buttonStyle(.borderless)
                .frame(width: Self.deleteWidth)
                .help("删除这个保护（可以撤销）")
                .accessibilityLabel("删除「\(group.name)」")
            }
            if !decisions.isEmpty {
                EgressDecisionList(decisions: decisions, refresh: refresh)
            }
        }
        .padding(.vertical, 3)
        .contextMenu {
            Button("查看详情") { sheet = .details(group.id) }
            Button(group.enabled ? "暂停" : "恢复") {
                if !group.enabled && !canEnable { sheet = .details(group.id); return }
                changeRule(group.id) { $0.enabled = !group.enabled }
            }
            Divider()
            Button("删除", role: .destructive) { deleteRule(group.id) }
        }
    }

    private func recordRow(_ record: EgressProtection.BlockRecord) -> some View {
        let date = Date(timeIntervalSince1970: record.started)
        let cause = record.observed.first(where: { $0.country != nil && $0.isOutside(record.expected) })
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
        case .addSites:
            EgressSiteSheet(countries: config.groups.last?.expect ?? [], preview: preview?.connections) { input, countries, unverified, done in
                addRules(input, countries: countries, unverified: unverified, done: done)
            }
        case .details(let id):
            if let group = config.groups.first(where: { $0.id == id }) {
                EgressRuleDetail(rule: group, config: config, status: liveStatus, connected: connected, refresh: refresh,
                                 edit: { edit in changeRule(id, edit: edit) },
                                 remove: { deleteRule(id) },
                                 saveSites: { original, sites, done in
                                     replaceSites(id, original: original, sites: sites, done: done)
                                 })
            }
        }
    }

    private func openRequestedRule() {
        guard visible, preview == nil else { return }
        guard let id = window.egressRuleToOpen else { return }
        window.egressRuleToOpen = nil
        if config.groups.contains(where: { $0.id == id }) { sheet = .details(id) }
    }

    // MARK: - Changes

    private func addRules(_ input: EgressRuleInput, countries: [String], unverified: EgressProtection.Unverified,
                          done: @escaping (Bool) -> Void) {
        let previous = ProfileStore.loadAppSettings().egressProtection ?? EgressProtection()
        guard let change = EgressRuleChange.adding(input, countries: countries, unverified: unverified, config: previous),
              change.after.permitsActivation(comparedTo: previous) else { done(false); return }
        if change.needsReconnect(connected: manager.showsConnected) {
            done(true)
            sheet = nil
            confirm = change
        } else {
            apply(change, completion: done)
        }
    }

    private func replaceSites(_ id: UInt32, original: [String], sites: [String], done: @escaping (String?) -> Void) {
        guard preview == nil else { done(nil); return }
        let previous = ProfileStore.loadAppSettings().egressProtection ?? EgressProtection()
        guard let change = EgressRuleChange.replacingSites(sites, expected: original, group: id, in: previous) else {
            done("规则已在别处更新。可先复制草稿，再重新打开详情。")
            return
        }
        if change.needsReconnect(connected: manager.showsConnected) {
            sheet = nil
            confirm = change
            done(nil)
        } else {
            apply(change) { ok in
                done(ok ? nil : "保存失败。草稿已保留，可以重试。")
            }
        }
    }

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

    /// Deletes at once and offers 撤销; when it is the last protection
    /// switched on and the VPN is up, the reconnect question comes first.
    private func deleteRule(_ id: UInt32) {
        guard preview == nil else { return }
        let previous = ProfileStore.loadAppSettings().egressProtection ?? EgressProtection()
        guard let name = previous.groups.first(where: { $0.id == id })?.name else { return }
        let change = EgressRuleChange(config: previous) { $0.groups.removeAll { $0.id == id } }
        sheet = nil
        if change.needsReconnect(connected: manager.showsConnected) {
            confirm = change
            return
        }
        apply(change) { ok in
            if ok { notice = EgressChangeNotice(text: "已删除「\(name)」。", change: change) }
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

    init(config: EgressProtection) { self.config = config.withoutExpandedMatches }
    init(configuration: ReadConfiguration) throws {
        config = try JSONDecoder().decode(EgressProtection.self, from: configuration.file.regularFileContents ?? Data())
    }
    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        return FileWrapper(regularFileWithContents: try encoder.encode(config))
    }
}
