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
    @State private var config = ProfileStore.loadAppSettings().egressProtection ?? EgressProtection()
    @State private var status: EgressProtection.Status?
    @State private var confirm: Bool?
    @State private var editing: EgressProtection.Group?
    @State private var editingMethod: EgressProtection.Method?
    @State private var methodsOpen = false
    @State private var busy = false
    @State private var message: String?
    @State private var importing = false
    @State private var exporting = false
    private let timer = Timer.publish(every: 5, tolerance: 1, on: .main, in: .common).autoconnect()

    private var unavailable: String? {
        if manager.usesCisco {
            return "经 Cisco 连接时出口由公司名单决定，这里不做检测。"
        }
        if !ProfileStore.loadAppSettings().isDropProtectionOn {
            return "出口保护需要断线保护开着，否则断线时受保护网站会回落本地。"
        }
        return nil
    }

    private var canEnableProtection: Bool {
        var candidate = config
        candidate.enabled = true
        return config.enabled || candidate.permitsActivation(comparedTo: config)
    }

    var body: some View {
        Section {
            Group {
                Toggle(isOn: Binding(get: { config.enabled }, set: { on in
                    guard !on || canEnableProtection else { return }
                    if manager.switchIsOn { confirm = on }
                    else { change { $0.enabled = on } }
                })) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("出口保护")
                        Text(summary).font(.caption).foregroundStyle(.secondary)
                    }
                }
                .disabled(!canEnableProtection)
                if let on = confirm {
                    HStack {
                        Text("需要重新连接一次才能生效").font(.callout)
                        Spacer()
                        Button("稍后") { confirm = nil }
                        Button("重新连接") {
                            confirm = nil
                            change { $0.enabled = on }
                        }
                    }
                }
                if config.groups.isEmpty {
                    Text("还没有组。点「新建组」，或从「连接」页加入网站。")
                        .font(.caption).foregroundStyle(.secondary)
                }
                ForEach(config.groups) { group in groupRow(group) }
                if let records = status?.records, !records.isEmpty {
                    DisclosureGroup("拦截记录") {
                        ForEach(records.indices, id: \.self) { index in
                            let record = records[index]
                            VStack(alignment: .leading, spacing: 4) {
                                Text(record.name + (record.ended == nil ? " · 有未恢复的拦截" : " · 已恢复"))
                                ForEach(record.observed.indices, id: \.self) { observation in
                                    Text(record.observed[observation].observationCaption)
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                }
                            }
                        }
                    }
                }
                HStack {
                    Button("新建组") { editing = EgressProtection.newGroup(in: config) }
                    Spacer()
                    Menu("管理配置") {
                        Button("导入 JSON…") { importing = true }
                        Button("导出 JSON…") { exporting = true }
                    }.fixedSize()
                }
                DisclosureGroup("检测方式", isExpanded: $methodsOpen) {
                    ForEach(config.availableMethods) { method in
                        HStack {
                            Button { editingMethod = method } label: {
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(method.name)
                                    Text(method.scopeCaption).font(.caption).foregroundStyle(.secondary)
                                }
                            }.buttonStyle(.plain)
                            Spacer()
                            if config.methods.contains(where: { $0.id == method.id }) {
                                Button(role: .destructive) {
                                    change { $0.methods.removeAll { $0.id == method.id } }
                                } label: { Image(systemName: "minus.circle.fill").foregroundStyle(.red) }
                                .buttonStyle(.borderless)
                                .help("删除自定义方式或恢复预设")
                            }
                        }
                    }
                    Button("新增检测方式") {
                        editingMethod = .init(id: UUID().uuidString, name: "", url: "https://{host}/",
                                              extract: .init(kind: .json, key: "country"))
                    }
                }
            }
            .disabled(unavailable != nil || busy)
            if let message { Text(message).font(.caption).foregroundStyle(.orange) }
        } footer: {
            Text(unavailable ?? "开启后，走 VPN 的网站会改用 TCP 连接。受保护网站的新连接先等出口检查，1 秒内可共用结果。")
                .font(.caption).foregroundStyle(.secondary)
        }
        .onAppear { config = ProfileStore.loadAppSettings().egressProtection ?? EgressProtection(); refresh() }
        .onChange(of: manager.egressLine) { _ in refresh() }
        .onChange(of: manager.showsConnected) { _ in refresh() }
        .onReceive(timer) { _ in if config.isActive { refresh() } }
        .sheet(item: $editing) { group in
            EgressGroupEditor(group: group, config: config) { candidate, done in
                change({ current in
                    if let index = current.groups.firstIndex(where: { $0.id == candidate.id }) {
                        current.groups[index] = candidate
                    } else { current.groups.append(candidate) }
                }, completion: done)
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
                change { $0 = imported }
            } catch { message = "无法读取出口保护配置。请选择有效的 JSON 文件。" }
        }
        .fileExporter(isPresented: $exporting, document: EgressConfigFile(config: config),
                      contentType: .json, defaultFilename: "AlwaysConnect-egress") { result in
            if case .failure = result { message = "配置未导出。请检查保存位置。" }
        }
    }

    private var summary: String {
        guard config.enabled else { return "每次连组里的网站前先查出口，国家不对就拦住。" }
        let total = config.groups.filter(\.enabled).count
        let blocked = status?.groups.filter(\.blocked).count ?? 0
        if blocked != 0 { return "\(total) 组 · \(blocked) 组有拦截" }
        let checked = status?.groups.filter { $0.state == "ok" }.count ?? 0
        return "\(total) 组 · " + (total > 0 && checked == total ? "全部正常" : "等待检查")
    }

    private func groupRow(_ group: EgressProtection.Group) -> some View {
        let current = status?.groups.first { $0.id == group.id }
        let canProbe = !config.directMembers(in: group).isEmpty
        let needsAttention = group.enabled && !canProbe
        let reason = current?.blocked == true ? current?.blockReason : nil
        let description: String
        if let caption = current?.blockCaption {
            description = caption
        } else if needsAttention && config.enabled {
            description = "无法核实网站本身的出口。启用后将拦截这组新连接。"
        } else if !canProbe {
            description = "至少需要一个直接检查网站的成员才能开启"
        } else {
            description = "\(group.members.count) 个网站 · " + group.expect.map(countryName).joined(separator: "、")
        }
        return VStack(alignment: .leading, spacing: 6) {
            HStack {
                Button { editing = group } label: {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(group.name)
                        Text(description).font(.caption)
                            .foregroundStyle(current?.blocked == true || !canProbe ? Color.red : Color.secondary)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .contentShape(Rectangle())
                }.buttonStyle(.plain)
                Toggle(group.name, isOn: Binding(get: { group.enabled }, set: { on in
                    if on && canProbe { editing = group }
                    else if !on { disableGroup(group.id) }
                })).labelsHidden().disabled(!canProbe && !group.enabled)
                Button(role: .destructive) { change { $0.groups.removeAll { $0.id == group.id } } } label: {
                    Image(systemName: "minus.circle.fill").foregroundStyle(.red)
                }.buttonStyle(.borderless).help("删除这一组")
                }
            if needsAttention || reason != nil {
                HStack {
                    Button("编辑检测方式") { editing = group }
                    Button("停用这组", role: .destructive) { disableGroup(group.id) }
                }
                .buttonStyle(.borderless)
            }
        }
    }

    private func disableGroup(_ id: UInt32) {
        change { $0.disableGroup(id) }
    }

    private func change(_ edit: (inout EgressProtection) -> Void, completion: ((Bool) -> Void)? = nil) {
        let previous = ProfileStore.loadAppSettings().egressProtection ?? EgressProtection()
        var next = previous
        edit(&next)
        guard next.permitsActivation(comparedTo: previous) else {
            message = "至少需要一个直接检查网站的成员才能开启该组。"
            completion?(false)
            return
        }
        busy = true
        manager.saveEgress(next) { ok in
            busy = false
            if ok { config = next; message = nil; refresh() }
            else { message = "后台服务未接受配置。请检查配置和后台服务版本。" }
            completion?(ok)
        }
    }

    private func refresh() {
        config = ProfileStore.loadAppSettings().egressProtection ?? EgressProtection()
        guard config.isActive, manager.showsConnected else { status = nil; return }
        manager.fetchEgressJSON { json in
            guard config.isActive, manager.showsConnected else { status = nil; return }
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
                Button("立即检测") { check(enable: false) }.disabled(probeable.isEmpty)
                if !group.enabled {
                    Button("检测并开启") { check(enable: true) }.disabled(directMembers.isEmpty || group.name.isEmpty)
                }
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

    private func check(enable: Bool) {
        let members = enable ? directMembers : probeable
        guard !members.isEmpty else { return }
        busy = true
        func next(_ index: Int, _ countries: [String], _ rows: [String]) {
            guard index < members.count else {
                busy = false
                let actual = Array(Set(countries)).sorted()
                note = enable ? "当前出口：" + actual.map(countryName).joined(separator: "、") : rows.joined(separator: "\n")
                if enable {
                    group.expect = actual
                    group.enabled = true
                    commit()
                }
                return
            }
            let member = members[index]
            guard let host = member.concreteHost else { busy = false; return }
            probe(host) { observations in
                let observed = observations.first(where: { $0.method == member.method })
                if enable && observed?.country == nil {
                    busy = false
                    note = "\(host) 未查到出口。请检查自建连接和检测方式。"
                    return
                }
                let method = config.method(member.method)
                let label = observed?.country.map(countryName) ?? observed?.error ?? "未查到"
                let scope = method.map { " · " + $0.scopeCaption } ?? ""
                next(index + 1, countries + (observed?.country.map { [$0] } ?? []),
                     rows + ["\(host)：\(label)" + scope])
            }
        }
        next(0, [], [])
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
