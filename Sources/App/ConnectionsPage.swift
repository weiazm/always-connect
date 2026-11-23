import AppKit
import SwiftUI

@_silgen_name("ac_traffic_sample")
private func ac_traffic_sample(_ rows: UnsafePointer<CChar>) -> UnsafeMutablePointer<CChar>?
@_silgen_name("ac_traffic_stop")
private func ac_traffic_stop()
@_silgen_name("ac_string_free")
private func traffic_string_free(_ s: UnsafeMutablePointer<CChar>?)

/// Settings → 连接 (DESIGN.md §28.7, UI-DESIGN.md): every live connection
/// on this Mac, which program, which address (the name when the split
/// forwarder saw it), and whether it goes through the VPN or out the
/// local network, with the reason. Same program + address + way are one
/// row with a count, so a browser's dozen sockets read as one line.
/// With 按网站分流 on, a row going through the VPN can be put on the
/// "不走 VPN" list in one click (§四十四). Speeds per row and for the two
/// ways come from the Rust core while the page is open (§四十五).
struct ConnectionsPage: View {
    struct Row: Identifiable, Hashable {
        var process: String
        var address: String
        /// The name the forwarder saw, and the bare address.
        var host: String? = nil
        var remote: String = ""
        /// "HTTPS (TCP 443)", "QUIC (UDP 443)", "DNS (UDP 53)", ...
        var protocolName: String
        var via: String
        var reason: String
        var count: Int
        /// Bytes per second since the previous refresh (§四十五).
        var down: Int = 0
        var up: Int = 0
        var speed: Int { down + up }
        /// The sort key: the first click on 速度 puts the busiest first.
        var busiest: Int { -speed }
        var id: String { process + "|" + address + "|" + protocolName + "|" + via + "|" + reason }
    }

    enum Filter: String, CaseIterable, Identifiable {
        case all = "全部", vpn = "走 VPN", direct = "直连"
        var id: String { rawValue }
    }

    /// Fixed data instead of the background service (screenshots).
    var preview: [ConnectionRow]? = nil
    @State private var rows: [Row] = []
    @State private var filter: Filter = .all
    @State private var search = ""
    @State private var message: String?
    @State private var updated: Date?
    @ObservedObject private var manager = HelperClient.shared
    @ObservedObject private var settingsWindow = SettingsWindow.shared
    /// The "不走 VPN" list, read on appear and after each change here.
    @State private var sites: [DirectSite] = []
    @State private var notice: Notice?
    @State private var egressAddition: EgressAddition?
    @State private var egressNotice: EgressAction?
    @State private var egressPending: EgressAction?
    @State private var egressRangeSelection: EgressExitRangeSelection?
    @State private var egressBusy = false
    @State private var egressVisible = false
    @State private var egressGeneration = UUID()
    @State private var protectedConfig = EgressProtection()
    @State private var protectionStatus: EgressProtection.Status?
    @State private var selected = Set<Row.ID>()
    @State private var showEgressTip = false
    /// Totals since the previous refresh; nil until there are two samples.
    @State private var totals: (vpn: [Int], direct: [Int])?
    @State private var sortOrder: [KeyPathComparator<Row>] = []

    /// What the Rust core returns (traffic.rs `Speeds`).
    struct Speeds: Decodable {
        var ready: Bool
        var rows: [[Int]]
        var vpn: [Int]
        var direct: [Int]
    }

    /// The line after an add or remove, with its undo.
    struct Notice: Equatable {
        var id = UUID()
        var text: String
        var before: [DirectSite]
    }

    private struct EgressAddition: Identifiable {
        let id = UUID()
        let sites: [String]
    }

    private struct EgressAction: Identifiable {
        let id = UUID()
        var change: EgressRuleChange
        var text: String
        var rule: UInt32?
        var scope: EgressWebsiteScope?
        var method: String?
        var source: [EgressRecentVisits.Visit] = []
        var requiresLiveSetup = false
        var setupSession: Date?
        var rangeOffers: [EgressExitRangeOffer] = []
    }
    private let timer = Timer.publish(every: 5, on: .main, in: .common).autoconnect()

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 12) {
                Picker("", selection: $filter) {
                    ForEach(Filter.allCases) { Text($0.rawValue).tag($0) }
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .frame(width: 220)
                Spacer(minLength: 0)
                HStack(spacing: 6) {
                    Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                    TextField("搜程序或地址", text: $search, prompt: Text("搜程序或地址"))
                        .textFieldStyle(.roundedBorder)
                        .labelsHidden()
                }
                .frame(minWidth: 180, maxWidth: 340)
                Button("刷新", action: refresh)
            }
            Text(summary)
                .font(.caption)
                .foregroundStyle(.secondary)
            if showEgressTip && filter == .vpn {
                Text("点行尾的「保护出口」，也可以选中多行后一起加入。")
                    .font(.caption).foregroundStyle(.secondary)
            }
            if !selectedEligible.isEmpty {
                HStack {
                    Text("已选 \(selectedEligible.count) 个网站").font(.caption)
                    Menu("保护出口") { egressDestinations(selectedEligible) }
                }
            }
            Table(shown, selection: $selected, sortOrder: $sortOrder) {
                TableColumn("程序") { row in
                    Text(row.process).lineLimit(1).help(row.process)
                }
                .width(processColumnWidth)
                TableColumn("地址") { row in
                    HStack(spacing: 4) {
                        if row.via == "vpn", let rule = protectedConfig.rule(covering: row.host) {
                            Image(systemName: "shield.fill").foregroundStyle(.secondary)
                                .help("受规则「\(rule.name)」保护")
                        }
                        Text(row.address + (row.count > 1 ? "  ×\(row.count)" : ""))
                            .lineLimit(1).truncationMode(.middle).help(row.address)
                    }
                }
                .width(min: 160, ideal: 180)
                TableColumn("协议") { row in
                    Text(row.protocolName).lineLimit(1).help(row.protocolName)
                }
                .width(protocolColumnWidth)
                // Click the header to put the busiest first (§四十五).
                TableColumn("速度", value: \.busiest) { row in
                    Text(row.speed == 0 ? "—" : "↓" + Self.rate(row.down) + " ↑" + Self.rate(row.up))
                        .font(.callout.monospacedDigit())
                        .foregroundStyle(row.speed == 0 ? Color.secondary : Color.primary)
                        .lineLimit(1)
                        .frame(maxWidth: .infinity, alignment: .trailing)
                }
                .width(92)
                TableColumn("走向") { row in
                    Text(row.via == "vpn" ? "VPN" : row.via == "local" ? "本机" : "直连")
                        .foregroundStyle(row.via == "vpn" ? Color.green : row.via == "local" ? Color.secondary : Color.orange)
                }
                .width(34)
                // The action sits at the end of the reason cell: a column
                // of its own cut "VPN 隧道本身" short (§44.3).
                TableColumn("原因") { row in
                    HStack(spacing: 4) {
                        let label = blockedDestination(row) ? "已拦（出口不对）" : reason(row)
                        Text(label).foregroundStyle(blockedDestination(row) ? Color.orange : Color.secondary).lineLimit(1).help(label)
                        Spacer(minLength: 0)
                        action(row)
                    }
                }
                .width(110)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .layoutPriority(1)
            if let notice {
                HStack(spacing: 8) {
                    Image(systemName: "checkmark.circle.fill").foregroundStyle(.green)
                    Text(notice.text).font(.caption).fixedSize(horizontal: false, vertical: true)
                    Spacer()
                    Button("撤销") { save(notice.before, notice: nil) }
                        .buttonStyle(.borderless)
                        .font(.caption)
                }
                .padding(8)
                .background(RoundedRectangle(cornerRadius: 6).fill(Color.primary.opacity(0.06)))
            }
            if let message {
                Text(message).font(.caption).foregroundStyle(.orange)
            }
            if egressBusy {
                ProgressView("正在检查选中网站的出口…").controlSize(.small)
            }
            if let pending = egressPending {
                VStack(alignment: .leading, spacing: 6) {
                    Text(pending.text).font(.callout).fixedSize(horizontal: false, vertical: true)
                    EgressExitRangePicker(offers: pending.rangeOffers, selection: $egressRangeSelection)
                    let canConfirm = egressRangeSelection == nil || egressRangeSelection?.verified(in: pending.rangeOffers) == true
                    if pending.change.needsReconnect(connected: manager.showsConnected) {
                        EgressReconnectPrompt(change: pending.change, cancel: {
                            egressPending = nil; egressRangeSelection = nil
                        }, canConfirm: canConfirm) {
                            egressPending = nil
                            applyEgress(pending)
                        }
                    } else {
                        HStack {
                            Button("取消") { egressPending = nil; egressRangeSelection = nil }
                            Button("确认") { egressPending = nil; applyEgress(pending) }.disabled(!canConfirm)
                        }
                    }
                }.padding(8).background(.quaternary, in: RoundedRectangle(cornerRadius: 6))
            }
            if let egressNotice {
                HStack {
                    Image(systemName: "checkmark.circle.fill").foregroundStyle(.green)
                    Text(egressNotice.text)
                        .font(.caption)
                    Spacer()
                    if let scope = egressNotice.scope, scope.includesSubdomains {
                        Button("只保护 \(scope.host)") { narrowEgress(egressNotice) }.buttonStyle(.borderless)
                    }
                    if let id = egressNotice.rule, egressNotice.change.before.groups.allSatisfy({ $0.id != id }) {
                        Button("查看国家") { settingsWindow.show(tab: "split", egressRule: id) }.buttonStyle(.borderless)
                    }
                    Button("撤销") { undoEgress(egressNotice) }.buttonStyle(.borderless)
                }
                .padding(8)
                .background(RoundedRectangle(cornerRadius: 6).fill(Color.primary.opacity(0.06)))
                recommendations(egressNotice)
            }
            Text("只列正在通信的连接（含所有程序）。开着按网站分流时，地址会显示访问的域名；其他情况显示 IP。每 5 秒自动刷新，速度是这 5 秒的平均，点「速度」标题按速度排。"
                 + (manager.ownConnection ? "点「加直连」把网站加入不走 VPN 的名单，在「分流」页也能改。"
                    : manager.usesCisco ? "经 Cisco 时走向由公司的名单决定；打开按网站分流后，这里可以一键加直连。"
                    : "打开按网站分流后，这里可以一键加直连。"))
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(16)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .onAppear {
            egressVisible = true
            consumeVPNFilter()
            if preview == nil { sites = DirectSites.sites(ProfileStore.loadAppSettings()) }
            refreshEgressState()
            refresh()
        }
        .onChange(of: settingsWindow.vpnConnectionsRequested) { _ in consumeVPNFilter() }
        .onChange(of: preview) { if let sample = $0 { update(sample) } }
        .onReceive(timer) { _ in if preview == nil && egressVisible { refresh(); refreshEgressState() } }
        .onDisappear {
            egressVisible = false
            egressGeneration = UUID()
            egressBusy = false
            if preview == nil { DispatchQueue.global(qos: .utility).async { ac_traffic_stop() } }
        }
        .task(id: egressNotice?.id) {
            guard let notice = egressNotice else { return }
            try? await Task.sleep(nanoseconds: 12_000_000_000)
            if !Task.isCancelled && egressNotice?.id == notice.id { egressNotice = nil }
        }
        .sheet(item: $egressAddition) { addition in
            EgressWebsiteForm(sites: addition.sites) { change, site in
                egressNotice = .init(change: change, text: "已开始保护 \(site)")
                refreshEgressState()
            }
        }
    }

    private var protocolColumnWidth: CGFloat {
        max(80, Self.textWidth(Set(rows.map(\.protocolName))) + 8)
    }

    private var processColumnWidth: CGFloat {
        min(220, max(96, Self.textWidth(Set(rows.map(\.process))) + 8))
    }

    private static func textWidth(_ values: Set<String>) -> CGFloat {
        let font = NSFont.systemFont(ofSize: NSFont.systemFontSize)
        return ceil(values.map { ($0 as NSString).size(withAttributes: [.font: font]).width }.max() ?? 0)
    }

    /// The background service calls every network it was given "局域网":
    /// it gets the list's networks and the detected local ones as one
    /// allowlist. A network the user put on the list is the list's doing
    /// (user, 2026-11-12: an added server address showed as 局域网).
    private func reason(_ row: Row) -> String {
        if row.reason == "局域网", DirectSites.covering(sites, host: nil, address: row.remote) != nil {
            return "名单直连"
        }
        return row.reason
    }

    /// The end of the reason cell: "加直连" on a VPN row, "已加入" when the list
    /// already covers it (it moves once the program reconnects), "移除"
    /// on a row the list sends direct. Nothing when the split is off:
    /// then Cisco and the company's list decide (§四十四).
    private var selectedEligible: [Row] {
        shown.filter { selected.contains($0.id) && egressScope($0) != nil && protectedConfig.rule(covering: $0.host) == nil }
    }

    private func egressScope(_ row: Row) -> EgressWebsiteScope? {
        guard row.via == "vpn", !manager.usesCisco, manager.protectsDrops, let host = row.host else { return nil }
        return EgressWebsiteScope(host, includesSubdomains: true)
    }

    private func action(_ row: Row) -> some View {
        let scope = egressScope(row)
        let bypass = DirectSites.covering(sites, host: row.host, address: row.remote)
        let directChoices = manager.ownConnection && row.via == "vpn" && bypass == nil
            ? DirectSites.choices(host: row.host, address: row.remote) : []
        let owner = protectedConfig.rule(covering: row.host)
        return Group {
            if row.via == "direct", let bypass, manager.ownConnection {
                Menu("移除") { Button("从不走 VPN 的名单删除 \(bypass)") { remove(bypass) } }
            } else if !directChoices.isEmpty || scope != nil {
                Menu(scope == nil ? "加直连" : "操作") {
                    if let scope {
                        if let owner {
                            let patterns = owner.patternsCovering(scope.host).sorted().joined(separator: "、")
                            Section("当前范围：\(patterns)") {
                                Button("移出这条规则", role: .destructive) { move(scope.host, from: owner.id, to: nil) }
                                if protectedConfig.groups.contains(where: { $0.id != owner.id }) {
                                    Menu("改到另一条规则") {
                                        ForEach(protectedConfig.groups.filter { $0.id != owner.id }) { rule in
                                            Button(rule.name) { move(scope.host, from: owner.id, to: rule.id) }
                                        }
                                    }
                                }
                            }
                        } else {
                            Menu("保护出口") { egressDestinations([row]) }
                        }
                    }
                    if !directChoices.isEmpty && owner == nil {
                        Section("加入不走 VPN 的名单") {
                            ForEach(directChoices, id: \.rule) { choice in
                                Button(choice.label) { add(choice.rule) }
                            }
                        }
                    }
                }
            } else if bypass != nil && row.via == "vpn" && manager.ownConnection {
                Text("已加入").help("已在不走 VPN 的名单里")
            }
        }
        .menuStyle(.borderlessButton).menuIndicator(.hidden).controlSize(.small).font(.caption).fixedSize()
    }

    @ViewBuilder private func egressDestinations(_ rows: [Row]) -> some View {
        let scopes = EgressWebsiteScope.unique(rows.compactMap(egressScope))
        if !scopes.isEmpty {
            let hosts = scopes.map(\.host)
            Section("保护范围：\(scopes.map(\.website).joined(separator: "、")) 及子域名") {
                ForEach(protectedConfig.rulesForEditing.groups) { rule in
                    Button("加到：\(rule.name) · \(rule.enabled ? "只允许 " + rule.expect.map(egressCountryName).joined(separator: "、") : "已停用")") {
                        addToEgress(hosts, rule: rule.id)
                    }
                }
                Button("新建规则（按现在的出口）") { addToEgress(hosts, rule: nil) }
            }
            .disabled(egressBusy)
        }
    }

    private func addToEgress(_ hosts: [String], rule: UInt32?) {
        guard !egressBusy else { return }
        let scopes = EgressWebsiteScope.unique(hosts.compactMap { EgressWebsiteScope($0, includesSubdomains: true) })
        guard !scopes.isEmpty else { return }
        guard scopes.count <= 8 else { message = "一次最多加入 8 个网站，请减少选择。"; return }
        let settings = ProfileStore.loadAppSettings()
        let stored = settings.egressProtection ?? EgressProtection()
        let direct = DirectSites.sites(settings)
        guard scopes.allSatisfy({ !$0.conflicts(in: stored, rule: rule, direct: direct) }) else {
            message = "保护范围与直连名单或另一条规则重叠。请先调整原规则。"
            return
        }
        guard manager.showsConnected, manager.protectsDrops, !manager.usesCisco else {
            if rule == nil { egressAddition = .init(sites: scopes.map(\.host)) }
            else { message = "请先连接 VPN（按网站分流）。" }
            return
        }
        message = nil
        egressBusy = true
        egressPending = nil
        egressRangeSelection = nil
        let request = UUID()
        egressGeneration = request
        let source = EgressRecentVisits.shared.visits.filter { hosts.contains($0.host) }
        let setupSession = manager.connectedSince
        manager.probeEgressWebsites(scopes.map(\.host), isCurrent: { egressVisible && egressGeneration == request }) { results in
            egressBusy = false
            guard manager.showsConnected, manager.protectsDrops, !manager.usesCisco,
                  manager.connectedSince == setupSession else { return }
            let eligible = verifiedMethods(results, config: stored)
            let proposedCountry = suggestedEgressCountry(results)
            if rule == nil && (proposedCountry == nil || results.values.contains { !$0.isComplete }) {
                egressAddition = .init(sites: scopes.map(\.host))
                return
            }
            let newID = EgressProtection.newGroup(in: stored).id
            guard let change = EgressWebsiteScope.adding(scopes, to: stored, rule: rule, newRuleID: newID,
                                                         methods: eligible, countries: proposedCountry.map { [$0] } ?? [],
                                                         activateExisting: false),
                  let target = change.after.groups.first(where: { $0.id == (rule ?? newID) }) else {
                message = "这条规则需要至少一个能直接检查出口的网站。"
                return
            }
            let website = scopes.count == 1 ? scopes[0].website : "\(scopes.count) 个网站"
            let checked = scopes.compactMap { results[$0.host].map { "\($0.host)：\($0.caption)" } }
            let line = rule == nil
                ? "\(website) 及子域名 · 只允许 " + target.expect.map(egressCountryName).joined(separator: "、")
                : "已加入「\(target.name)」：\(website) 及子域名"
            let note = target.enabled ? checked.joined(separator: " ") : "这条规则仍处于停用状态。"
            let scope = scopes.count == 1 ? scopes[0] : nil
            let offers = rule == nil ? EgressExitRangeOffer.from(results, countries: target.expect, config: stored) : []
            let action = EgressAction(change: change, text: line + "。" + note, rule: target.id,
                                      scope: scope, method: scope.flatMap { eligible[$0.host] }, source: source,
                                      requiresLiveSetup: rule == nil, setupSession: setupSession, rangeOffers: offers)
            if rule == nil || change.needsReconnect(connected: manager.showsConnected) { egressPending = action }
            else { applyEgress(action) }
        }
    }

    private func move(_ host: String, from source: UInt32, to target: UInt32?) {
        let latest = ProfileStore.loadAppSettings().egressProtection ?? EgressProtection()
        guard let (change, patterns) = EgressRuleChange.move(host: host, source: source, target: target, config: latest) else { return }
        let destination = target.flatMap { id in latest.rulesForEditing.groups.first(where: { $0.id == id }) }
        let label = destination.map { "移到「\($0.name)」" + ($0.enabled ? "，沿用它允许的国家" : "，该规则处于停用状态") } ?? "移出出口保护"
        egressRangeSelection = nil
        egressPending = .init(change: change, text: label + "：" + patterns.sorted().joined(separator: "、"), rule: target)
    }

    private func applyEgress(_ action: EgressAction, showNotice: Bool = true) {
        guard !action.requiresLiveSetup || (manager.showsConnected && manager.connectedSince == action.setupSession) else {
            message = "VPN 连接已变化，请重新检查出口。"
            return
        }
        egressBusy = true
        let selection = egressRangeSelection
        egressRangeSelection = nil
        func completed(_ ok: Bool, result: EgressRuleChange) {
            egressBusy = false
            if ok {
                var saved = action
                saved.change = result
                saved.rangeOffers = []
                if action.requiresLiveSetup { saved.text = "已开始保护 " + action.text }
                egressNotice = showNotice ? saved : nil
                selected.removeAll()
                refreshEgressState()
            } else { message = "规则未保存。配置已变化或后台未接受，请刷新后重试。" }
        }
        if action.requiresLiveSetup, let selection {
            guard let id = action.rule,
                  let setup = EgressExitRangeSetup(proposed: action.change.after, previous: action.change.before,
                                                  group: id, selection: selection, offers: action.rangeOffers)
            else { egressBusy = false; message = "请重新检查出口网段。"; return }
            manager.confirmExitRangeSetup(setup) { ok in
                completed(ok, result: .init(before: action.change.before, after: setup.proposed))
                if !ok { message = "未能确认出口范围。原设置已保留，请重新选择网站并检查出口。" }
            }
        } else {
            manager.saveEgress(action.change.after, replacing: action.change.before) { completed($0, result: action.change) }
        }
    }

    private func undoEgress(_ notice: EgressAction) {
        let change = notice.change.undo
        let action = EgressAction(change: change, text: "撤销刚才的出口保护修改")
        egressRangeSelection = nil
        if change.needsReconnect(connected: manager.showsConnected) { egressPending = action }
        else { applyEgress(action, showNotice: false) }
    }

    private func narrowEgress(_ notice: EgressAction) {
        guard let old = notice.scope, let id = notice.rule, let scope = EgressWebsiteScope(old.host, includesSubdomains: false) else { return }
        let oldConfig = notice.change.before
        let existing = oldConfig.groups.contains { $0.id == id }
        let countries = notice.change.after.groups.first { $0.id == id }?.expect ?? []
        let methods = notice.method.map { [scope.host: $0] } ?? [:]
        guard let replacement = EgressWebsiteScope.adding([scope], to: oldConfig, rule: existing ? id : nil, newRuleID: id,
                                                          methods: methods, countries: countries, activateExisting: false) else { return }
        var updated = replacement.after
        if let existing = notice.change.after.groups.first(where: { $0.id == id }),
           let index = updated.groups.firstIndex(where: { $0.id == id }) {
            updated.groups[index].exitRangeCheck = existing.exitRangeCheck
            updated.groups[index].exitRanges = existing.exitRanges
        }
        let narrow = EgressRuleChange(before: notice.change.after, after: updated)
        let action = EgressAction(change: narrow, text: "已改为只保护 \(scope.host)", rule: id)
        applyEgress(action)
    }

    @ViewBuilder private func recommendations(_ notice: EgressAction) -> some View {
        if let rule = notice.rule, protectedConfig.groups.contains(where: { $0.id == rule && $0.enabled }) {
            let related = EgressRecentVisits.shared.recommendations(for: notice.source, config: protectedConfig, direct: sites)
            if !related.isEmpty {
                HStack {
                    Text("常和它一起出现").font(.caption).foregroundStyle(.secondary)
                    ForEach(related, id: \.self) { host in
                        Button(host) { addToEgress([host], rule: rule) }.buttonStyle(.borderless)
                    }
                    Button("全部加入") { addToEgress(related, rule: rule) }.buttonStyle(.borderless)
                }.disabled(egressBusy)
            }
        }
    }

    private func consumeVPNFilter() {
        guard egressVisible, settingsWindow.vpnConnectionsRequested else { return }
        settingsWindow.vpnConnectionsRequested = false
        filter = .vpn
        showEgressTip = true
    }

    private func refreshEgressState() {
        protectedConfig = ProfileStore.loadAppSettings().egressProtection ?? EgressProtection()
        guard preview == nil, manager.showsConnected, protectedConfig.isActive else { protectionStatus = nil; return }
        manager.fetchEgressJSON { json in
            guard egressVisible, protectedConfig.isActive, manager.showsConnected else { return }
            protectionStatus = json.flatMap { try? JSONDecoder().decode(EgressProtection.Status.self, from: Data($0.utf8)) }
        }
    }

    private func blockedDestination(_ row: Row) -> Bool {
        guard row.via == "vpn", let owner = protectedConfig.rule(covering: row.host),
              let state = protectionStatus?.groups.first(where: { $0.id == owner.id }) else { return false }
        return state.observed.contains { $0.evidenceKind == .direct && $0.host == row.host
            && $0.peerAddress == row.remote && $0.country != nil && $0.isOutside(owner.expect) }
    }

    private func add(_ rule: String) {
        let before = sites
        let after = DirectSites.adding(rule, to: sites)
        guard after != before else { return }
        let name = ListRule.parse(rule)?.text ?? rule
        save(after, notice: Notice(text: "已把 \(name) 加入不走 VPN 的名单。新连接马上直连；已开着的等程序重新连接（通常一两分钟内）。",
                                   before: before))
    }

    private func remove(_ line: String) {
        let before = sites
        save(DirectSites.removing(line, from: sites),
             notice: Notice(text: "已把 \(line) 从不走 VPN 的名单删除。新连接改走 VPN。", before: before))
    }

    /// Stores and pushes the list (the same path as the 分流 page), shows
    /// the line for a while, and re-reads the connections.
    private func save(_ list: [DirectSite], notice next: Notice?) {
        sites = list
        notice = next
        if preview != nil { return }
        DirectList.save(list) { note in if let note { message = note } }
        if let next {
            DispatchQueue.main.asyncAfter(deadline: .now() + 12) {
                if notice?.id == next.id { notice = nil }
            }
        }
        refresh()
    }

    private var shown: [Row] {
        let list = sortOrder.isEmpty ? rows : rows.sorted(using: sortOrder)
        return list.filter { row in
            switch filter {
            case .all: return true
            case .vpn: return row.via == "vpn"
            case .direct: return row.via == "direct"
            }
        }.filter { row in
            search.isEmpty || row.process.localizedCaseInsensitiveContains(search)
                || row.address.localizedCaseInsensitiveContains(search)
                || row.protocolName.localizedCaseInsensitiveContains(search)
        }
    }

    private var summary: String {
        let vpn = rows.filter { $0.via == "vpn" }.reduce(0) { $0 + $1.count }
        let direct = rows.filter { $0.via == "direct" }.reduce(0) { $0 + $1.count }
        let local = rows.filter { $0.via == "local" }.reduce(0) { $0 + $1.count }
        guard updated != nil else { return "读取中…" }
        guard let totals else { return "走 VPN \(vpn) 条 · 直连 \(direct) 条 · 本机内部 \(local) 条" }
        func pair(_ v: [Int]) -> String { "↓" + Self.rate(v[0]) + "/s ↑" + Self.rate(v[1]) + "/s" }
        return "走 VPN \(vpn) 条  \(pair(totals.vpn))   ·   直连 \(direct) 条  \(pair(totals.direct))   ·   本机内部 \(local) 条"
    }

    private func refresh() {
        if let preview {
            update(preview)
            return
        }
        HelperClient.shared.fetchConnections { result in
            guard let result else {
                message = "后台服务没有回复：可能是旧版本（面板上点「更新」），或者还没装。"
                return
            }
            message = nil
            // nettop takes a few tens of ms: off the main thread.
            DispatchQueue.global(qos: .utility).async {
                let speeds = Self.sample(result)
                DispatchQueue.main.async { update(result, speeds: speeds) }
            }
        }
    }

    private func update(_ result: [ConnectionRow], speeds: Speeds? = nil) {
        if preview == nil, egressVisible { EgressRecentVisits.shared.record(result) }
        updated = Date()
        rows = Self.group(result, speeds: speeds?.ready == true ? speeds?.rows : nil)
        if let speeds, speeds.ready, speeds.vpn.count == 2, speeds.direct.count == 2 {
            totals = (speeds.vpn, speeds.direct)
        } else {
            totals = nil
        }
    }

    /// The Rust core's speeds for these rows (traffic.rs).
    private static func sample(_ connections: [ConnectionRow]) -> Speeds? {
        guard let input = try? JSONEncoder().encode(connections),
              let raw = String(data: input, encoding: .utf8)?.withCString({ ac_traffic_sample($0) }) else { return nil }
        defer { traffic_string_free(raw) }
        return try? JSONDecoder().decode(Speeds.self, from: Data(String(cString: raw).utf8))
    }

    /// "980", "12K", "1.8M" bytes (per second).
    static func rate(_ bytes: Int) -> String {
        switch bytes {
        case ..<1000: return "\(bytes)"
        case ..<1_000_000: return "\(bytes / 1000)K"
        case ..<10_000_000: return String(format: "%.1fM", Double(bytes) / 1_000_000)
        default: return "\(bytes / 1_000_000)M"
        }
    }

    static func group(_ connections: [ConnectionRow], speeds: [[Int]]? = nil) -> [Row] {
        var grouped: [String: Row] = [:]
        for (index, c) in connections.enumerated() {
            let rate = speeds.flatMap { $0.indices.contains(index) && $0[index].count == 2 ? $0[index] : nil } ?? [0, 0]
            // One row per program and address; ports would split a
            // browser's parallel connections into many lines.
            let address = c.host.map { "\($0) (\(c.remote))" } ?? c.remote
            let proto = protocolName(c.proto, c.port)
            let key = c.process + "|" + address + "|" + proto + "|" + c.via + "|" + c.reason
            if var row = grouped[key] {
                row.count += 1
                row.down += rate[0]
                row.up += rate[1]
                grouped[key] = row
            } else {
                grouped[key] = Row(process: c.process, address: address, host: c.host, remote: c.remote,
                                   protocolName: proto, via: c.via, reason: c.reason, count: 1,
                                   down: rate[0], up: rate[1])
            }
        }
        // VPN-less first is what people look for: direct, then VPN, then local.
        let order = ["direct": 0, "vpn": 1, "local": 2]
        return grouped.values.sorted {
            (order[$0.via] ?? 3, $0.process.lowercased(), $0.address) < (order[$1.via] ?? 3, $1.process.lowercased(), $1.address)
        }
    }

    /// What runs on top of TCP/UDP, from the remote port (the usual
    /// assignments; a guess, not packet inspection).
    static func protocolName(_ transport: String, _ port: Int) -> String {
        let udp = transport.uppercased() == "UDP"
        let name: String?
        switch (udp, port) {
        case (false, 443), (false, 8443): name = "HTTPS"
        case (true, 443): name = "QUIC (HTTP/3)"
        case (false, 80), (false, 8080): name = "HTTP"
        case (_, 53): name = "DNS"
        case (false, 853): name = "DNS over TLS"
        case (false, 22): name = "SSH"
        case (false, 993): name = "IMAPS"
        case (false, 465), (false, 587): name = "SMTP"
        case (false, 995): name = "POP3S"
        case (false, 5223): name = "Apple 推送"
        case (true, 123): name = "NTP"
        case (true, 3478), (true, 3479), (true, 19302): name = "STUN（音视频）"
        case (true, 5353): name = "mDNS"
        case (false, 3389): name = "远程桌面"
        case (false, 5900): name = "屏幕共享"
        case (false, 1080), (false, 7890): name = "代理"
        default: name = nil
        }
        let base = "\(udp ? "UDP" : "TCP") \(port)"
        return name.map { "\($0) · \(base)" } ?? base
    }
}
