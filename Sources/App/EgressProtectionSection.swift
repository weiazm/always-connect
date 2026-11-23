import AppKit
import SwiftUI
import Network
import UniformTypeIdentifiers

extension EgressProtection {
    static func newGroup(in config: Self, name: String = "新建组") -> Group {
        let ids = Set(config.groups.map(\.id))
        var id = UInt32.random(in: 1...UInt32.max)
        while ids.contains(id) { id = UInt32.random(in: 1...UInt32.max) }
        return Group(id: id, name: name)
    }

    /// Geosite data stays in the bundle. Send only the selected list's rules.
    func forService() -> Self {
        var config = self
        for index in config.groups.indices {
            config.groups[index].members = groups[index].members.flatMap { member in
                guard member.pattern.hasPrefix("geosite:") else { return [member] }
                guard let rule = ListRule.parse(member.pattern) else { return [] }
                return rule.expanded.map { Member(pattern: $0) }
            }
        }
        return config
    }
}

struct EgressProtectionSection: View {
    @ObservedObject private var manager = HelperClient.shared
    @ObservedObject private var window = SettingsWindow.shared
    @State private var stored = ProfileStore.loadAppSettings().egressProtection ?? EgressProtection()
    @State private var status: EgressProtection.Status?
    @State private var confirm: EgressRuleChange?
    @State private var sheet: Sheet?
    @State private var editingMethod: EgressProtection.Method?
    @State private var busy = false
    @State private var visible = false
    @State private var message: String?
    @State private var notice: EgressChangeNotice?
    @State private var importing = false
    @State private var exporting = false
    @State private var confirmDropProtection = false

    private enum Sheet: Identifiable {
        case add(UInt32?), details(UInt32), advanced(UInt32), unknownWeb
        var id: String {
            switch self {
            case .add(let id): return "add-\(id ?? 0)"
            case .details(let id): return "details-\(id)"
            case .advanced(let id): return "advanced-\(id)"
            case .unknownWeb: return "unknown-web"
            }
        }
    }

    private var config: EgressProtection { stored.rulesForEditing }
    private var available: Bool { !manager.usesCisco && manager.protectsDrops }

    var body: some View {
        Section {
            if manager.usesCisco {
                Text("切到「按网站分流」后可用").foregroundStyle(.secondary)
            } else if !manager.protectsDrops {
                HStack {
                    Text("出口保护需要断线保护").foregroundStyle(.secondary)
                    Spacer()
                    Button("打开断线保护") { confirmDropProtection = true }
                }
            }
            Group {
                if config.groups.isEmpty {
                    Text("从连接列表里点选要保护的网站").foregroundStyle(.secondary)
                } else {
                    Text(summary).font(.caption).foregroundStyle(.secondary)
                    ForEach(config.groups) { group in ruleRow(group) }
                }
                Button { sheet = .add(nil) } label: {
                    Label("添加要保护的网站", systemImage: "plus")
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
                if let message { Text(message).font(.caption).foregroundStyle(.orange) }
                if let records = status?.records, !records.isEmpty {
                    DisclosureGroup("最近拦截（\(records.count)）") {
                        ForEach(records, id: \.started) { record in
                            Button(record.host ?? record.name) { sheet = .details(record.group) }
                                .buttonStyle(.plain)
                        }
                    }
                }
                DisclosureGroup("高级") { advanced }
            }
            .disabled(!available || busy)
            if config.groups.isEmpty {
                Button("打开连接列表") { window.showVPNConnections() }
            }
        } header: { Text("出口保护") } footer: {
            Text("保护的网站每次新建连接时都会确认出口。开启后，走 VPN 的网站会使用 TCP。")
                .font(.caption).foregroundStyle(.secondary)
        }
        .onAppear { visible = true; refresh(); openRequestedRule() }
        .onDisappear { visible = false; status = nil }
        .onChange(of: window.egressRuleToOpen) { _ in openRequestedRule() }
        .onChange(of: window.unknownEgressRequested) { _ in openRequestedRule() }
        .onChange(of: manager.showsConnected) { _ in refresh() }
        .background {
            if visible && config.isActive {
                Color.clear.onReceive(Timer.publish(every: 5, tolerance: 1, on: .main, in: .common).autoconnect()) { _ in refresh() }
            }
        }
        .task(id: notice?.id) {
            guard let notice else { return }
            try? await Task.sleep(nanoseconds: 12_000_000_000)
            if !Task.isCancelled && self.notice?.id == notice.id { self.notice = nil }
        }
        .sheet(item: $sheet) { page in
            switch page {
            case .add(let rule):
                EgressWebsiteForm(rule: rule) { change, site in
                    notice = .init(text: "已开始保护 \(site)", change: change)
                    refresh()
                }
            case .details(let id):
                if let group = config.groups.first(where: { $0.id == id }) {
                    EgressRuleDetail(rule: group, status: status, refresh: refresh,
                                     addWebsite: { sheet = .add(id) }, advanced: { sheet = .advanced(id) },
                                     edit: { edit in changeRule(id, edit: edit) },
                                     remove: { sheet = nil; change { $0.groups.removeAll { $0.id == id } } })
                }
            case .advanced(let id):
                if let group = config.groups.first(where: { $0.id == id }) {
                    EgressGroupEditor(group: group, config: config) { group, done in
                        changeRule(id, edit: { $0 = group }, completion: done)
                    }
                }
            case .unknownWeb:
                EgressUnknownWebView(config: stored, status: status, refresh: refresh)
            }
        }
        .sheet(item: $editingMethod) { method in
            EgressMethodEditor(method: method) { value, done in
                change({ current in
                    current.methods.removeAll { $0.id == value.id }
                    current.methods.append(value)
                }, completion: done)
            }
        }
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
            } catch { message = "无法读取出口保护配置。请选择有效的 JSON 文件。" }
        }
        .fileExporter(isPresented: $exporting, document: EgressConfigFile(config: stored),
                      contentType: .json, defaultFilename: "AlwaysConnect-egress") { result in
            if case .failure = result { message = "配置未导出。请检查保存位置。" }
        }
        .alert("打开断线保护？", isPresented: $confirmDropProtection) {
            Button("取消", role: .cancel) {}
            Button("打开") {
                var settings = ProfileStore.loadAppSettings()
                settings.dropProtection = true
                ProfileStore.saveAppSettings(settings)
                manager.dropProtectionChanged()
            }
        } message: { Text("VPN 断开时会暂时拦截网络，直到重新连接或你手动断开。") }
    }

    private var summary: String {
        let active = config.groups.filter(\.enabled)
        guard !active.isEmpty else { return "出口保护已关闭" }
        let count = Set(active.flatMap(\.websiteNames)).count
        let state = status?.panelCaption(checkingFor: 0, expectedRules: Set(active.map(\.id))) ?? "尚未核实出口"
        return "正在保护 \(count) 个网站 · " + state
    }

    @ViewBuilder private var advanced: some View {
        if config.isActive {
            Button("认不出网站的连接") { sheet = .unknownWeb }
        }
        ForEach(config.availableMethods) { method in
            HStack {
                Button(method.name) { editingMethod = method }
                Text(method.scopeCaption).font(.caption).foregroundStyle(.secondary)
                Spacer()
                if config.methods.contains(where: { $0.id == method.id }) {
                    Button("删除", role: .destructive) { change { $0.methods.removeAll { $0.id == method.id } } }
                }
            }
        }
        Button("新增检查方式") {
            editingMethod = .init(id: UUID().uuidString, name: "", url: "https://{host}/",
                                  extract: .init(kind: .json, key: "country"))
        }
        HStack {
            Button("导入配置…") { importing = true }
            Button("导出配置…") { exporting = true }
        }
        Button("新建高级规则") {
            var group = EgressProtection.newGroup(in: config, name: "网站规则")
            group.enabled = false
            change { $0.groups.append(group) }
        }
    }

    private func ruleRow(_ group: EgressProtection.Group) -> some View {
        let state = status?.groups.first { $0.id == group.id }
        let canEnable = !config.directMembers(in: group).isEmpty && !group.expect.isEmpty
        let reason = state?.blockReason
        let description = state?.blockCaption ?? (group.enabled && !canEnable
            ? "无法核实网站本身的出口，连接后将拦截这条规则的新连接"
            : group.enabled ? (state?.displayLevel == .ok ? "正常" : "尚未核实出口") : "已停用")
        return VStack(alignment: .leading, spacing: 5) {
            HStack {
                Button { sheet = .details(group.id) } label: {
                    VStack(alignment: .leading, spacing: 3) {
                        Text(group.name)
                        if !group.expect.isEmpty {
                            Text("只允许 " + group.expect.map(egressCountryName).joined(separator: "、"))
                                .font(.caption).foregroundStyle(.secondary)
                        }
                        Text(description).font(.caption)
                            .foregroundStyle(reason != nil ? Color.red : (state?.displayLevel ?? .unknown).color)
                    }.frame(maxWidth: .infinity, alignment: .leading).contentShape(Rectangle())
                }.buttonStyle(.plain)
                Toggle("启用 \(group.name)", isOn: Binding(get: { group.enabled }, set: { on in
                    if on && !canEnable { sheet = .details(group.id); return }
                    changeRule(group.id) { $0.enabled = on }
                })).labelsHidden().disabled(!canEnable && !group.enabled)
            }
            if group.enabled && (reason != nil || !canEnable) {
                HStack {
                    Button("编辑检查方式") { sheet = .advanced(group.id) }
                    Button("停用这条规则", role: .destructive) { changeRule(group.id) { $0.enabled = false } }
                }.buttonStyle(.borderless)
            }
        }
    }

    private func openRequestedRule() {
        guard visible else { return }
        if window.unknownEgressRequested {
            window.unknownEgressRequested = false
            if config.isActive && available { sheet = .unknownWeb }
            return
        }
        guard let id = window.egressRuleToOpen else { return }
        window.egressRuleToOpen = nil
        if config.groups.contains(where: { $0.id == id }) { sheet = .details(id) }
    }

    private func changeRule(_ id: UInt32, edit: (inout EgressProtection.Group) -> Void, completion: ((Bool) -> Void)? = nil) {
        change({ config in
            if let index = config.groups.firstIndex(where: { $0.id == id }) { edit(&config.groups[index]) }
        }, completion: completion)
    }

    private func change(_ edit: (inout EgressProtection) -> Void, completion: ((Bool) -> Void)? = nil) {
        let previous = ProfileStore.loadAppSettings().egressProtection ?? EgressProtection()
        let change = EgressRuleChange(config: previous, edit: edit)
        guard change.after.permitsActivation(comparedTo: previous) else {
            message = "先添加一个能直接检查出口的网站。"
            completion?(false)
            return
        }
        if change.needsReconnect(connected: manager.showsConnected) {
            if completion != nil { sheet = nil }
            confirm = change
        } else { apply(change, completion: completion) }
    }

    private func apply(_ change: EgressRuleChange, completion: ((Bool) -> Void)? = nil) {
        busy = true
        manager.saveEgress(change.after, replacing: change.before) { ok in
            busy = false
            message = ok ? nil : "规则未保存。请重新打开设置后再试。"
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
        stored = ProfileStore.loadAppSettings().egressProtection ?? EgressProtection()
        guard visible, config.isActive, manager.showsConnected else { status = nil; return }
        manager.fetchEgressJSON { json in
            guard visible, config.isActive, manager.showsConnected else { return }
            status = json.flatMap { try? JSONDecoder().decode(EgressProtection.Status.self, from: Data($0.utf8)) }
        }
    }
}

private struct EgressConfigFile: FileDocument {
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

struct EgressGroupEditor: View {
    @Environment(\.dismiss) private var dismiss
    @State var group: EgressProtection.Group
    let config: EgressProtection
    var pendingSite: String? = nil
    let save: (EgressProtection.Group, @escaping (Bool) -> Void) -> Void
    @State private var input = ""
    @State private var country = ""
    @State private var member: EgressProtection.Member?
    @State private var newMember = false
    @State private var pendingSiteAdded = false
    @State private var note: String?
    @State private var busy = false

    private var probeable: [EgressProtection.Member] {
        group.members.filter { config.method($0.method) != nil && $0.concreteHost != nil }
    }

    private var directMembers: [EgressProtection.Member] { config.directMembers(in: group) }

    var body: some View {
        Form {
            Section("组") {
                TextField("名称", text: $group.name)
                if !group.expect.isEmpty {
                    ForEach(group.expect, id: \.self) { expected in
                        HStack {
                            Text(countryName(expected))
                            Spacer()
                            Button("移除") { group.expect.removeAll { $0 == expected } }
                                .buttonStyle(.borderless)
                        }
                    }
                }
                HStack {
                    TextField("预期出口国家代码", text: $country)
                    Button("添加") {
                        let code = country.uppercased()
                        if !group.expect.contains(code) { group.expect.append(code) }
                        country = ""
                    }.disabled(country.utf8.count != 2 || !country.utf8.allSatisfy { (65...90).contains($0 & 0xDF) })
                }
            }
            Section("成员") {
                ForEach(group.members) { item in
                    HStack {
                        Text(item.pattern)
                        Spacer()
                        let method = config.method(item.method)
                        Button(method?.isDirect == true ? method?.name ?? "跟随本组"
                               : method != nil ? "跟随本组 · 第三方查询点仅供参考" : "跟随本组") {
                            newMember = false
                            member = item
                        }
                            .buttonStyle(.borderless)
                        erase { group.members.removeAll { $0.id == item.id } }
                    }
                }
                ForEach(group.cidrs, id: \.self) { range in
                    HStack { Text(range); Spacer(); erase { group.cidrs.removeAll { $0 == range } } }
                }
                HStack {
                    TextField("域名、*.通配、geosite:清单、网段", text: $input).onSubmit(add)
                    Button("添加", action: add).disabled(input.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                }
            }
            if directMembers.isEmpty {
                Text("至少需要一个直接检查网站的成员才能开启该组。")
                    .font(.caption).foregroundStyle(.red)
            }
            if let note { Text(note).font(.caption).foregroundStyle(.orange) }
            HStack {
                Button("取消") { dismiss() }
                Spacer()
                Button("立即检测", action: check).disabled(probeable.isEmpty)
                Button("保存") { commit() }.keyboardShortcut(.defaultAction).disabled(group.name.isEmpty)
            }
        }
        .formStyle(.grouped).frame(width: 540, height: 450)
        .disabled(busy)
        .onAppear {
            if let pendingSite, !pendingSiteAdded {
                pendingSiteAdded = true
                input = pendingSite
                add()
            }
        }
        .sheet(item: $member) { item in
            EgressMemberEditor(member: item, methods: config.availableMethods, chooseDefault: newMember) { value in
                group.members.removeAll { $0.id == value.id }
                group.members.append(value)
            }
        }
    }

    private func erase(_ action: @escaping () -> Void) -> some View {
        Button(role: .destructive, action: action) { Image(systemName: "minus.circle.fill").foregroundStyle(.red) }
            .buttonStyle(.borderless)
    }

    private func add() {
        let line = input.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if line.contains(":"), let parts = line.split(separator: "/").first,
           IPv6Address(String(parts)) != nil, let length = line.split(separator: "/").dropFirst().first.flatMap({ Int($0) }) ?? (line.contains("/") ? nil : 128),
           (0...128).contains(length) {
            let range = "\(parts)/\(length)"
            if !group.cidrs.contains(range) { group.cidrs.append(range) }
        } else if let rule = ListRule.parse(line.hasPrefix("*.") ? String(line.dropFirst(2)) : line) {
            switch rule {
            case .network(let range):
                if !group.cidrs.contains(range) { group.cidrs.append(range) }
            case .domain, .geosite:
                let pattern = line.hasPrefix("*.") ? "*." + rule.text : rule.text
                let existing = group.members.first { $0.pattern == pattern }
                newMember = existing == nil
                member = existing ?? .init(pattern: pattern)
            case .geoip:
                note = "请填写具体网段。"
                return
            }
        } else {
            note = "无法识别这条成员规则。"
            return
        }
        input = ""
        note = nil
    }

    private func commit() {
        guard !group.enabled || (!directMembers.isEmpty && !group.expect.isEmpty) else {
            note = "已开启的组需要至少一个直接检查网站的成员和一个预期国家。"
            return
        }
        busy = true
        save(group) { ok in
            busy = false
            if ok { dismiss() }
            else { note = "配置未保存。请检查成员和检测方式。" }
        }
    }

    private func check() {
        let members = probeable
        guard !members.isEmpty else { return }
        busy = true
        func next(_ index: Int, _ rows: [String]) {
            guard index < members.count else {
                busy = false
                note = rows.joined(separator: "\n")
                return
            }
            let member = members[index]
            guard let host = member.concreteHost else { busy = false; return }
            probe(host) { observations in
                let observed = observations.first(where: { $0.method == member.method })
                let method = config.method(member.method)
                let label = observed?.country.map(countryName) ?? observed?.error ?? "未查到"
                let scope = method.map { " · " + $0.scopeCaption } ?? ""
                next(index + 1, rows + ["\(host)：\(label)" + scope])
            }
        }
        next(0, [])
    }
}

struct EgressMemberEditor: View {
    @Environment(\.dismiss) private var dismiss
    @State var member: EgressProtection.Member
    let methods: [EgressProtection.Method]
    let chooseDefault: Bool
    let save: (EgressProtection.Member) -> Void
    @State private var host = ""
    @State private var observations: [EgressProtection.Observation] = []
    @State private var busy = false
    @State private var generation = 0

    var body: some View {
        Form {
            Section(member.pattern) {
                if member.pattern.hasPrefix("*.") {
                    TextField("填写一个具体的子域名", text: Binding(get: { host }, set: { value in
                        generation += 1
                        host = value
                        busy = false
                        observations = []
                    }))
                }
                if !member.pattern.hasPrefix("geosite:") {
                    Button(busy ? "正在探测…" : "重新探测") { refresh() }
                        .disabled(busy || host.isEmpty)
                    Picker("检测方式", selection: $member.method) {
                        ForEach(methods) { method in
                            let result = observations.first { $0.method == method.id }
                            Text(method.name + " · " + resultLabel(result) + " · " + method.scopeCaption)
                                .tag(Optional(method.id))
                        }
                        Text("不检测，跟随本组").tag(String?.none)
                    }
                }
                if member.method == nil {
                    Text("同组别的网站查出问题时一起拦。").font(.caption).foregroundStyle(.secondary)
                } else if methods.first(where: { $0.id == member.method })?.isDirect == false {
                    Text(EgressProtection.Method.thirdPartyCaption + "。此成员跟随本组。")
                        .font(.caption).foregroundStyle(.secondary)
                }
                if !busy, observations.isEmpty, !host.isEmpty {
                    Text("连接自建 VPN 后可以探测出口。").font(.caption).foregroundStyle(.secondary)
                }
            }
            HStack {
                Button("取消") { dismiss() }
                Spacer()
                Button("确定") {
                    if member.pattern.hasPrefix("*.") { member.probeHost = host }
                    save(member)
                    dismiss()
                }.keyboardShortcut(.defaultAction).disabled(busy || !validSelection)
            }
        }
        .formStyle(.grouped).frame(width: 510)
        .onAppear {
            host = member.concreteHost ?? ""
            if !host.isEmpty { refresh() }
        }
    }

    private var validSelection: Bool {
        guard member.method != nil, let suffix = member.pattern.split(separator: "*", maxSplits: 1).last,
              member.pattern.hasPrefix("*.") else { return true }
        return host.lowercased().hasSuffix(String(suffix)) && host.count > suffix.count
    }

    private func resultLabel(_ result: EgressProtection.Observation?) -> String {
        if let code = result?.country { return countryName(code) + (result?.ip.map { "（\($0)）" } ?? "") }
        return result?.error ?? "待探测"
    }

    private func refresh() {
        busy = true
        generation += 1
        let token = generation
        probe(host) { result in
            guard token == generation else { return }
            observations = result
            busy = false
            if chooseDefault && member.method == nil {
                member.method = EgressProtection.Method.preferredDirectMethod(methods, observations: result)
            }
        }
    }
}

private struct EgressMethodEditor: View {
    @Environment(\.dismiss) private var dismiss
    @State var method: EgressProtection.Method
    let save: (EgressProtection.Method, @escaping (Bool) -> Void) -> Void
    @State private var error = false

    var body: some View {
        Form {
            TextField("名称", text: $method.name)
            TextField("HTTPS 地址模板", text: $method.url)
            Text(method.scopeCaption + "。地址中的 {host} 代表成员网站。")
                .font(.caption).foregroundStyle(.secondary)
            Picker("请求", selection: $method.head) { Text("GET").tag(false); Text("HEAD").tag(true) }
            Picker("从哪里取值", selection: $method.extract.kind) {
                Text("正文 key=value").tag(EgressProtection.Extract.Kind.kv)
                Text("JSON 字段").tag(EgressProtection.Extract.Kind.json)
                Text("应答头").tag(EgressProtection.Extract.Kind.header)
            }
            TextField("字段名", text: $method.extract.key)
            TextField("正则（选填，取第 1 组）", text: Binding(
                get: { method.extract.regex ?? "" },
                set: { method.extract.regex = $0.isEmpty ? nil : $0 }))
            if error { Text("检测方式未保存。请检查 HTTPS 地址和字段。").foregroundStyle(.orange) }
            HStack {
                Button("取消") { dismiss() }
                Spacer()
                Button("保存") { save(method) { if $0 { dismiss() } else { error = true } } }
                    .keyboardShortcut(.defaultAction)
                    .disabled(method.name.isEmpty || method.extract.key.isEmpty || !method.url.hasPrefix("https://"))
            }
        }.formStyle(.grouped).frame(width: 500)
    }
}

private func probe(_ host: String, completion: @escaping ([EgressProtection.Observation]) -> Void) {
    HelperClient.shared.probeEgressJSON(host) { json in
        let observations = json.flatMap {
            try? JSONDecoder().decode([EgressProtection.Observation].self, from: Data($0.utf8))
        }
        completion(observations ?? [])
    }
}

private func countryName(_ code: String) -> String {
    Locale(identifier: "zh_Hans").localizedString(forRegionCode: code) ?? code
}
