import AppKit
import ServiceManagement
import SwiftUI

// Settings window. Every page is a grouped Form in the style of macOS
// System Settings (2026-11-03, after the owner called the first version
// crude): rounded cards, label left / control right, one short footer per
// card. Since 2026-11-26 the pages share one design language
// (SettingsDesign.swift; UI-DESIGN.md 设置, DESIGN.md §69.14): seven tabs
// in the see-through title bar, a status card at the top of each page,
// coloured icons by meaning.

struct SettingsView: View {
    @AppStorage("settingsTab") private var tab = "general"
    @AppStorage("splitSection") private var splitSection = "direct"
    var connectionPreview: [ConnectionRow]? = nil
    var splitPreview: SplitPagePreview? = nil

    var body: some View {
        let current = SettingsPages.all.firstIndex { $0.tag == SettingsPages.resolve(tab) } ?? 0
        VStack(spacing: 0) {
            SettingsTabBar(tab: $tab)
            Divider()
            SettingsPageContainer(selection: current, pages: SettingsPages.all.map { page in
                AnyView(content(for: page.tag)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                    .toggleStyle(.always)
                    // The tab row above already keeps the title bar clear.
                    .ignoresSafeArea(.container, edges: .top))
            })
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        // The tab row goes up into the see-through title bar.
        .ignoresSafeArea(.container, edges: .top)
        .frame(minWidth: SettingsWindow.minimumSize.width, maxWidth: .infinity,
               minHeight: SettingsWindow.minimumSize.height, maxHeight: .infinity)
        .onAppear(perform: openLegacyTab)
        .onChange(of: tab) { _ in openLegacyTab() }
    }

    @ViewBuilder private func content(for tag: String) -> some View {
        switch tag {
        case "credentials": CredentialsPage(preview: splitPreview != nil)
        case "connect": ConnectPage()
        case "split": SplitPage(preview: splitPreview, section: $splitSection)
        case "egress": EgressProtectionPage()
        case "traffic": ConnectionsPage(preview: connectionPreview)
        case "diagnostics": DiagnosticsPage()
        default: GeneralPage()
        }
    }

    /// "proxy" opens 分流代理 inside 分流; "connections" is now 流量.
    private func openLegacyTab() {
        if tab == "proxy" { splitSection = "proxy" }
        let resolved = SettingsPages.resolve(tab)
        if resolved != tab { tab = resolved }
    }
}

/// AppKit displays only the selected page and keeps its view state while
/// the window is open, including unsaved edits when switching tabs.
private struct SettingsPageContainer: NSViewControllerRepresentable {
    let selection: Int
    let pages: [AnyView]

    func makeNSViewController(context: Context) -> NSTabViewController {
        let controller = NSTabViewController()
        controller.tabStyle = .unspecified
        controller.tabView.tabViewType = .noTabsNoBorder
        controller.transitionOptions = []
        for page in pages {
            controller.addChild(NSHostingController(rootView: page))
        }
        controller.selectedTabViewItemIndex = selection
        return controller
    }

    func updateNSViewController(_ controller: NSTabViewController, context: Context) {
        for (child, page) in zip(controller.children, pages) {
            (child as? NSHostingController<AnyView>)?.rootView = page
        }
        if controller.selectedTabViewItemIndex != selection {
            controller.selectedTabViewItemIndex = selection
        }
    }
}

/// A card footer: one or two short lines, secondary.
struct Footnote: View {
    var text: String
    init(_ text: String) { self.text = text }
    var body: some View {
        Text(text)
            .font(.caption)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
    }
}

/// A question-mark button whose help shows the moment the pointer is on
/// it. `.help` is the system tooltip, which waits about a second
/// (user, 2026-11-05: show it immediately, §26.18). The popover sits
/// beside the icon, never under the pointer, so it cannot flicker by
/// stealing the hover. Clicking still runs `action`.
struct HoverHelp<Content: View>: View {
    var action: () -> Void
    @ViewBuilder var content: () -> Content
    @State private var showing = false

    var body: some View {
        Button {
            showing = false
            action()
        } label: {
            Image(systemName: "questionmark.circle")
        }
        .buttonStyle(.borderless)
        .onHover { showing = $0 }
        .popover(isPresented: $showing, arrowEdge: .trailing) {
            content()
                .padding(12)
                .fixedSize()
        }
    }
}

// MARK: - General

/// 通用 (§69.14): starting up and notifications, the shortcut, and one
/// card about the App itself (version and update, notices, uninstall).
/// Connecting and drop protection moved to 连接.
struct GeneralPage: View {
    @ObservedObject private var updates = UpdateChecker.shared
    @State private var settings = ProfileStore.loadAppSettings()
    @State private var loginItemOn = SMAppService.mainApp.status == .enabled
    @State private var loginError: String?
    @State private var recording = false

    var body: some View {
        Form {
            Section {
                Toggle(isOn: Binding(
                    get: { loginItemOn },
                    set: { on in
                        do {
                            if on {
                                try SMAppService.mainApp.register()
                            } else {
                                try SMAppService.mainApp.unregister()
                            }
                            loginItemOn = on
                            loginError = nil
                        } catch {
                            loginError = "设置失败：\(error.localizedDescription)"
                        }
                    })) {
                    IconLabel(title: "开机时自动打开", symbol: "power", color: SettingsTone.neutral)
                }
                Toggle(isOn: $settings.notificationAggregation) {
                    IconLabel(title: "掉线和恢复时发通知", symbol: "bell.fill", color: .red)
                }
                .onChange(of: settings.notificationAggregation) { _ in
                    ProfileStore.saveAppSettings(settings)
                }
                Toggle(isOn: Binding(
                    get: { settings.isApprovalCardOn },
                    set: { on in
                        settings.approvalCard = on
                        ProfileStore.saveAppSettings(settings)
                        ApprovalPrompt.shared.settingsChanged()
                    })) {
                    IconLabel(title: "等手机批准时在菜单栏下提醒", symbol: "iphone", color: SettingsTone.account)
                }
                if let loginError {
                    Text(loginError).foregroundStyle(.red)
                }
            } header: {
                PageHeader(symbol: "gearshape.fill", color: SettingsTone.neutral, title: "通用",
                         status: versionLine, dot: updates.available == nil ? nil : .accentColor)
            }

            Section {
                Toggle(isOn: $settings.globalHotkeyEnabled) {
                    IconLabel(title: "全局快捷键", symbol: "command", color: .indigo)
                }
                .onChange(of: settings.globalHotkeyEnabled) { _ in
                    ProfileStore.saveAppSettings(settings)
                    HotkeyManager.shared.apply(settings)
                }
                LabeledContent {
                    HStack(spacing: 8) {
                        Text(HotkeyManager.describe(settings: settings))
                            .foregroundStyle(.secondary)
                        Button(recording ? "请按下组合键…" : "录制") { toggleRecording() }
                    }
                } label: {
                    IconLabel(title: "连接 / 断开", symbol: "keyboard", color: .indigo)
                }
                .disabled(!settings.globalHotkeyEnabled)
            } header: {
                Text("快捷键")
            } footer: {
                Footnote("需在「系统设置 → 隐私与安全性 → 辅助功能」里允许 AlwaysConnect；只接受带 ⌘/⌥/⌃ 的组合。")
            }

            AboutSection()
        }
        .formStyle(.grouped)
        .onDisappear { HotkeyManager.shared.stopRecording() }
    }

    private var versionLine: String {
        if let update = updates.available { return "AlwaysConnect \(UpdateChecker.currentVersion) · 有新版本 \(update.version)，在下面更新" }
        return "AlwaysConnect \(UpdateChecker.currentVersion)"
    }

    private func toggleRecording() {
        if recording {
            HotkeyManager.shared.stopRecording()
            recording = false
            return
        }
        recording = true
        HotkeyManager.shared.startRecording { code, mods, chars in
            settings.hotkeyKeyCode = code
            settings.hotkeyModifiers = mods
            settings.hotkeyCharacters = chars
            ProfileStore.saveAppSettings(settings)
            HotkeyManager.shared.apply(settings)
            HotkeyManager.shared.stopRecording()
            recording = false
        }
    }
}

/// One card about the App (§69.14, was three: 版本, 关于, 卸载): the
/// version and its update (UpdateRows), the notices that travel with the
/// App (DESIGN.md §34; files in Resources, opened in the default viewer),
/// and the clean uninstall (§31).
struct AboutSection: View {
    var body: some View {
        Section {
            UpdateRows()
            LabeledContent {
                HStack(spacing: 8) {
                    Button("使用须知") { open("RESPONSIBLE-USE", "md") }
                    Button("许可证与第三方声明") { open("THIRD_PARTY_NOTICES", "md") }
                }
            } label: {
                IconLabel(title: "说明", symbol: "doc.text.fill", color: SettingsTone.neutral)
            }
            UninstallRows()
        } header: {
            Text("关于 AlwaysConnect")
        } footer: {
            Footnote("只用于连接你所在单位授权你使用的 VPN。Cisco、Cisco Secure Client、AnyConnect 是 Cisco Systems, Inc. 的商标；AlwaysConnect 是独立的个人项目，与 Cisco 没有关联，也未获其认可。")
        }
    }

    private func open(_ name: String, _ ext: String) {
        guard let url = Bundle.main.url(forResource: name, withExtension: ext) else { return }
        NSWorkspace.shared.open(url)
    }
}

/// Clean uninstall (DESIGN.md §31): a row that opens an inline
/// confirmation with two "keep" choices, both off — the default leaves
/// nothing behind.
struct UninstallRows: View {
    @State private var confirming = false
    @State private var keepPassword = false
    @State private var keepSettings = false
    @State private var running = false
    @State private var message: String?

    var body: some View {
        if confirming {
            Text("会断开 Cisco、恢复直连，然后删除后台服务、随附的 openconnect、日志、桌面上的恢复网络脚本和 App 本身。需要输入一次这台电脑的开机密码。Cisco Secure Client 不受影响。默认什么都不留；勾了保留的，以后重新安装会自动带回来。")
                .fixedSize(horizontal: false, vertical: true)
            Toggle("保留账号密码（钥匙串里）", isOn: $keepPassword)
            Toggle("保留设置（服务器、分流名单等）", isOn: $keepSettings)
            HStack {
                Spacer()
                Button("取消") {
                    confirming = false
                    message = nil
                }
                .disabled(running)
                Button(running ? "正在卸载…" : "卸载") { uninstall() }
                    .buttonStyle(.borderedProminent)
                    .tint(.red)
                    .disabled(running)
            }
        } else {
            LabeledContent {
                Button("卸载…") {
                    keepPassword = false
                    keepSettings = false
                    message = nil
                    confirming = true
                }
            } label: {
                IconLabel(title: "从这台 Mac 上移除 AlwaysConnect", symbol: "trash.fill", color: .red)
            }
        }
        if let message {
            Text(message)
                .foregroundStyle(.red)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    private func uninstall() {
        running = true
        message = nil
        Uninstaller.start(keepPassword: keepPassword, keepSettings: keepSettings) { outcome in
            switch outcome {
            case .started:
                message = nil  // the App quits now; the script finishes after it
            case .cancelled:
                running = false
            case .failed(let text):
                running = false
                message = "卸载没有开始：\(text)"
            }
        }
    }
}

// MARK: - Account

/// The server list (DESIGN.md §21.13): pick the one to use, add, edit,
/// remove. Kept in step with the Mac's Cisco profiles each time it is
/// shown, and on "从 Cisco 重新导入" (§三十八).
struct ServerListSection: View {
    @Binding var selected: String
    @State private var servers = ProfileStore.loadServers()
    @State private var importNote: String?
    @State private var editingID: UUID?
    @State private var adding = false
    @State private var draftName = ""
    @State private var draftAddress = ""

    var body: some View {
        Section {
            ForEach(servers) { entry in
                if editingID == entry.id {
                    editor(save: { update(entry) })
                } else {
                    row(entry)
                }
            }
            if adding {
                editor(save: add)
            } else {
                HStack {
                    Button {
                        startEditing(nil)
                        adding = true
                    } label: {
                        Label("添加服务器", systemImage: "plus.circle.fill")
                    }
                    .buttonStyle(.borderless)
                    Spacer()
                    if CiscoProfiles.isPresent {
                        Button {
                            sync(force: true)
                        } label: {
                            Label("从 Cisco 重新导入", systemImage: "arrow.down.circle")
                        }
                        .buttonStyle(.borderless)
                        .help("重新读取本机 Cisco 里保存的服务器，删掉过的也会加回来")
                    }
                }
            }
            if let importNote {
                Text(importNote)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        } header: {
            Text("服务器")
        } footer: {
            Text(footer)
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .onAppear { sync(force: false) }
    }

    private var footer: String {
        if servers.isEmpty {
            return CiscoProfiles.isPresent
                ? "本机 Cisco 里没有保存的服务器，请点「添加服务器」填网关地址。"
                : "没有找到 Cisco，请点「添加服务器」填网关地址。"
        }
        let pick = servers.contains { $0.ciscoName != nil }
            ? "点圆圈选用；标着 Cisco 的条目从本机 Cisco 自动导入，并随 Cisco 的改动更新。"
            : "点圆圈选用。"
        if !CiscoEngine.isAvailable { return pick }
        return HelperClient.shared.usesCisco
            ? pick + "经 Cisco 连接时按名称连接，证书由 Cisco 自动出示。"
            : pick + "自建连接时自动换成它的网关地址。"
    }

    /// Bring the list in step with Cisco (DESIGN.md §三十八). Shown
    /// quietly on appear when something changed; the button always says
    /// what happened.
    private func sync(force: Bool) {
        let report = ProfileStore.syncWithCisco(force: force)
        servers = ProfileStore.loadProfile().servers
        selected = ProfileStore.loadProfile().server
        importNote = Self.note(report, asked: force)
    }

    static func note(_ report: ProfileStore.CiscoSync?, asked: Bool) -> String? {
        guard let report else { return asked ? "读取 Cisco 配置失败" : nil }
        var parts: [String] = []
        if !report.added.isEmpty { parts.append("新增 \(report.added.joined(separator: "、"))") }
        if !report.updated.isEmpty { parts.append("更新 \(report.updated.joined(separator: "、"))") }
        if !report.detached.isEmpty {
            parts.append("\(report.detached.joined(separator: "、")) 已不在 Cisco 里，保留为普通服务器")
        }
        if parts.isEmpty {
            guard asked else { return nil }
            return report.found == 0 ? "本机 Cisco 里没有找到保存的服务器" : "已和 Cisco 一致（\(report.found) 台）"
        }
        return "已从 Cisco 同步：" + parts.joined(separator: "；")
    }

    private func row(_ entry: ServerEntry) -> some View {
        let isSelected = entry.target == selected
        return HStack(spacing: 10) {
            Button {
                selected = entry.target
                ProfileStore.saveServers(servers, selected: entry.target)
            } label: {
                Image(systemName: isSelected ? "checkmark.circle.fill" : "circle")
                    .font(.title3)
                    .foregroundStyle(isSelected ? Color.accentColor : Color.secondary)
            }
            .buttonStyle(.borderless)
            .help("选用这台服务器")
            VStack(alignment: .leading, spacing: 1) {
                HStack(spacing: 6) {
                    Text(entry.name).fontWeight(isSelected ? .semibold : .regular)
                    if entry.ciscoName != nil {
                        Text("Cisco")
                            .font(.caption2)
                            .padding(.horizontal, 5)
                            .padding(.vertical, 1)
                            .background(Capsule().fill(Color.secondary.opacity(0.2)))
                            .foregroundStyle(.secondary)
                    }
                }
                Text(entry.address)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
            Spacer()
            Button { startEditing(entry) } label: { Image(systemName: "pencil") }
                .buttonStyle(.borderless)
                .help("修改")
            Button { remove(entry) } label: {
                Image(systemName: "minus.circle.fill").foregroundStyle(.red)
            }
            .buttonStyle(.borderless)
            .disabled(servers.count <= 1)
            .help("删除")
        }
    }

    private func editor(save: @escaping () -> Void) -> some View {
        VStack(spacing: 8) {
            TextField("名称", text: $draftName, prompt: Text("例如 深圳"))
            TextField("地址", text: $draftAddress, prompt: Text("例如 vpn.example.com:443"))
            HStack {
                Spacer()
                Button("取消") { editingID = nil; adding = false }
                Button("保存", action: save)
                    .buttonStyle(.borderedProminent)
                    .disabled(draftAddress.trimmingCharacters(in: .whitespaces).isEmpty)
            }
        }
        .padding(.vertical, 4)
    }

    private func startEditing(_ entry: ServerEntry?) {
        adding = false
        editingID = entry?.id
        draftName = entry?.name ?? ""
        draftAddress = entry?.address ?? ""
    }

    private func cleaned() -> (name: String, address: String) {
        let address = draftAddress.trimmingCharacters(in: .whitespaces)
        let name = draftName.trimmingCharacters(in: .whitespaces)
        return (name.isEmpty ? address : name, address)
    }

    private func add() {
        let (name, address) = cleaned()
        let entry = ServerEntry(name: name, address: address)
        servers.append(entry)
        adding = false
        if servers.count == 1 { selected = entry.target }
        ProfileStore.saveServers(servers, selected: selected)
    }

    private func update(_ entry: ServerEntry) {
        guard let index = servers.firstIndex(where: { $0.id == entry.id }) else { return }
        let (name, address) = cleaned()
        let wasSelected = entry.target == selected
        servers[index].name = name
        if address != entry.address {
            // A hand-edited address is ours, no longer Cisco's entry; the
            // sync must not add Cisco's entry back beside it.
            if let ciscoName = entry.ciscoName { ProfileStore.dismissCisco([ciscoName]) }
            servers[index].address = address
            servers[index].ciscoName = nil
        }
        if wasSelected { selected = servers[index].target }
        editingID = nil
        ProfileStore.saveServers(servers, selected: selected)
    }

    private func remove(_ entry: ServerEntry) {
        // Removed stays removed: the sync with Cisco skips it (§三十八).
        ProfileStore.dismissCisco([entry.ciscoName ?? entry.address])
        servers.removeAll { $0.id == entry.id }
        if entry.target == selected { selected = servers.first?.target ?? "" }
        ProfileStore.saveServers(servers, selected: selected)
    }
}

/// Server list + login, shared by the Account page and the first-run
/// wizard. The password belongs to the account (any server) and is
/// write-only: never read back into the field, no show-password switch.
struct CredentialForm: View {
    var onSaved: (() -> Void)?
    var showsStatus = false
    var certificatePreview = false

    @ObservedObject private var manager = HelperClient.shared
    @State private var server = ProfileStore.loadProfile().server
    // Before the first save, what Cisco last logged in with (§三十八).
    @State private var group = ProfileStore.loadUsername() == nil && ProfileStore.loadProfile().group.isEmpty
        ? CiscoProfiles.lastGroup() : ProfileStore.loadProfile().group
    @State private var username = ProfileStore.loadUsername() ?? CiscoProfiles.lastUser()
    @State private var password = ""
    @State private var message: String?
    @State private var messageIsError = false

    var body: some View {
        Form {
            if showsStatus {
                // Settings → 账号 (§69.14): who logs in first, then where,
                // then the certificate it shows.
                loginSection(hero: true)
                ServerListSection(selected: $server)
                LoginCertificateSection(preview: certificatePreview)
            } else {
                ServerListSection(selected: $server)
                loginSection(hero: false)
            }

            Section {
                HStack {
                    if let message {
                        Label(message, systemImage: messageIsError ? "exclamationmark.circle.fill" : "checkmark.circle.fill")
                            .foregroundStyle(messageIsError ? Color.red : Color.green)
                    }
                    Spacer()
                    if showsStatus {
                        Button("保存并连接") {
                            if save() { _ = HelperClient.shared.connectWithStoredCredentials(manual: true) }
                        }
                    }
                    Button("保存") { _ = save() }
                        .buttonStyle(.borderedProminent)
                        .keyboardShortcut(.defaultAction)
                }
                if showsStatus {
                    LabeledContent("当前状态") {
                        Text(manager.stateLine).foregroundStyle(manager.gatewayTrustFailed ? Color.red : Color.secondary)
                    }
                }
            }
        }
        .formStyle(.grouped)
    }

    private func loginSection(hero: Bool) -> some View {
        Section {
            TextField("用户名", text: $username)
            SecureField("密码", text: $password, prompt: Text(passwordPrompt))
            TextField("Group", text: $group, prompt: Text("一般留空"))
        } header: {
            if hero {
                let name = username.trimmingCharacters(in: .whitespaces)
                PageHeader(symbol: "person.fill", color: SettingsTone.account,
                         title: name.isEmpty ? "还没有填账号" : name,
                         status: accountLine,
                         dot: manager.hasCredentials ? .green : .orange,
                         letter: name.first.map { String($0).uppercased() } ?? "?")
            } else {
                Text("登录")
            }
        } footer: {
            Text("密码存在钥匙串里，所有服务器共用，只能改不能看。登录时如果公司要求，请在手机上确认。"
                 + "Group 是网关上的登录组，留空就用网关默认的组；只有单位让你选别的组时才填。经 Cisco 连接时用的是 Cisco 自己的设置。")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }

    /// The server in use and whether the password is kept.
    private var accountLine: String {
        let servers = ProfileStore.loadProfile().servers
        let name = servers.first { $0.target == server }?.name ?? (server.isEmpty ? "还没选服务器" : server)
        return name + " · " + (manager.hasCredentials ? "密码已存在钥匙串里" : "还没保存密码")
    }

    private var passwordPrompt: String {
        manager.hasCredentials ? "已保存，留空则不改" : "必填"
    }

    @discardableResult
    private func save() -> Bool {
        var profile = ProfileStore.loadProfile()
        profile.server = server
        profile.group = group
        ProfileStore.saveProfile(profile)
        ProfileStore.saveUsername(username)
        if password.isEmpty {
            let has = HelperClient.shared.hasCredentials
            message = has ? "已保存" : "请填写密码"
            messageIsError = !has
            if !has { return false }
        } else {
            guard KeychainStore.save(server: KeychainStore.accountKey, username: username,
                                     password: password) else {
                message = "保存失败，请重试"
                messageIsError = true
                return false
            }
            message = "已保存"
            messageIsError = false
            password = ""
        }
        HelperClient.shared.credentialsChanged()
        onSaved?()
        return true
    }
}

/// The login certificate (DESIGN.md §23.10), in 账号 since 2026-11-26
/// (user: "证书那个挪走"; it was on 分流 because only the own connection
/// uses it). One line, automatic by default; the choice is only offered
/// on demand, login certificates only.
struct LoginCertificateSection: View {
    var preview = false
    @ObservedObject private var manager = HelperClient.shared
    @State private var settings = ProfileStore.loadAppSettings()
    @State private var certificates: [CertificateRelay.ClientIdentity] = []
    private var own: Bool { preview || manager.ownConnection }

    var body: some View {
        Section {
            LabeledContent {
                HStack(spacing: 8) {
                    Text(preview ? "自动：示例证书（到期 2027-06-30）"
                         : LoginCertificate.summary(settings.clientCertificate, certificates))
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                    Menu("更改") {
                        Button("自动选择") { set(nil) }
                        Divider()
                        ForEach(certificates, id: \.digest) { item in
                            Button(LoginCertificate.label(item)) { set(item.digest) }
                        }
                        Divider()
                        Button("不使用证书") { set("none") }
                    }
                    .menuStyle(.borderlessButton)
                    .fixedSize()
                }
            } label: {
                Text("登录证书")
            }
        } footer: {
            VStack(alignment: .leading, spacing: 4) {
                Footnote(own
                    ? "按网站分流开着时，AlwaysConnect 自己连 Cisco，登录时出示这张证书；私钥不离开钥匙串。"
                    : "只在按网站分流开着时用；现在经 Cisco 连接，证书由 Cisco 出示。")
                if own, !preview, let problem = LoginCertificate.problem(settings.clientCertificate, certificates) {
                    Text(problem).font(.caption).foregroundStyle(.red)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
        .onAppear {
            guard !preview else { return }
            settings = ProfileStore.loadAppSettings()
            certificates = CertificateRelay.loginCandidates()
        }
    }

    private func set(_ value: String?) {
        guard !preview else { return }
        var stored = ProfileStore.loadAppSettings()
        stored.clientCertificate = value
        ProfileStore.saveAppSettings(stored)
        settings = stored
    }
}

/// What the account and 分流 pages say about the login certificate.
enum LoginCertificate {
    /// The automatic pick, the manual one, or that none is used.
    static func summary(_ choice: String?, _ certificates: [CertificateRelay.ClientIdentity]) -> String {
        switch choice {
        case nil:
            guard let pick = certificates.first else { return "自动（未找到）" }
            return "自动：" + label(pick, short: true)
        case "none":
            return "不使用"
        case let digest?:
            guard let pick = certificates.first(where: { $0.digest == digest }) else {
                return "所选证书已不在钥匙串"
            }
            return "手动：" + label(pick, short: true)
        }
    }

    /// Renewed certificates share a name: tell them apart by expiry and
    /// the start of their fingerprint.
    static func label(_ item: CertificateRelay.ClientIdentity, short: Bool = false) -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd"
        let expiry = item.expires.map { "到期 " + formatter.string(from: $0) } ?? ""
        if short { return "\(item.name)（\(expiry)）" }
        return "\(item.name)（\(expiry)，\(item.digest.prefix(4))…）"
    }

    /// What the own connection still needs on this Mac, if anything.
    static func problem(_ choice: String?, _ certificates: [CertificateRelay.ClientIdentity]) -> String? {
        if #unavailable(macOS 15.0), choice != "none" {
            return "证书转接需要 macOS 15 或更新。"
        }
        // The App ships openconnect (§27.3); the installer puts it next
        // to the background service. Homebrew's is a developer fallback.
        let paths = ["/Library/PrivilegedHelperTools/AlwaysConnect-openconnect/bin/openconnect",
                     "/opt/homebrew/bin/openconnect", "/usr/local/bin/openconnect"]
        if !paths.contains(where: { FileManager.default.isExecutableFile(atPath: $0) }) {
            return "后台服务还没装上自带的连接组件：点面板上的「更新」或「安装后台服务」。"
        }
        if choice == nil, certificates.isEmpty {
            return "钥匙串里没有找到公司发的证书。用 Cisco 能连上的话，证书一般就在钥匙串里；也可以在「账号」页手动选择。"
        }
        if let digest = choice, digest != "none", !certificates.contains(where: { $0.digest == digest }) {
            return "设置里选的证书已经不在钥匙串里，请在「账号」页改回自动选择。"
        }
        return nil
    }
}

struct CredentialsPage: View {
    /// Sample data only (offscreen pictures): no keychain certificates.
    var preview = false
    var body: some View {
        CredentialForm(showsStatus: true, certificatePreview: preview)
    }
}

// MARK: - Network

/// Home LAN access while connected (DESIGN.md §21.7, §21.9): with the
/// Cisco engine it is Cisco's own "Allow local (LAN) access" option,
/// read here and switched once in Cisco's window.
struct LocalLanStatus: View {
    @State private var enabled = CiscoProfiles.localLanAccessEnabled()

    var body: some View {
        if HelperClient.shared.usesCisco {
            HStack(alignment: .top, spacing: 10) {
                Image(systemName: enabled == true ? "checkmark.circle.fill" : "exclamationmark.triangle.fill")
                    .font(.title2)
                    .foregroundStyle(enabled == true ? Color.green : Color.orange)
                VStack(alignment: .leading, spacing: 4) {
                    Text(enabled == true ? "已允许访问家里的设备" : "未允许访问家里的设备")
                        .font(.body.weight(.medium))
                    Text(enabled == true
                         ? "连着 Cisco 也能打开家里的路由器、NAS、打印机等设备。"
                         : "在 Cisco 的设置里勾选 “Allow local (LAN) access when using VPN”，然后退出 Cisco。只需做一次。")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                    if enabled != true {
                        HStack {
                            Button("打开 Cisco") {
                                NSWorkspace.shared.open(URL(fileURLWithPath: "/Applications/Cisco/Cisco Secure Client.app"))
                            }
                            Button("重新检查") { enabled = CiscoProfiles.localLanAccessEnabled() }
                        }
                        .padding(.top, 2)
                    }
                }
                Spacer(minLength: 0)
            }
            .padding(.vertical, 2)
            .onReceive(NotificationCenter.default.publisher(
                for: NSApplication.didBecomeActiveNotification)) { _ in
                enabled = CiscoProfiles.localLanAccessEnabled()
            }
        } else {
            Label("本地局域网由上面的开关决定", systemImage: "checkmark.circle.fill")
        }
    }
}

// MARK: - Split

/// 按网站分流 (DESIGN.md §26.12, UI-DESIGN.md): one switch that also
/// picks the connection (on = AlwaysConnect connects itself with the
/// keychain certificate, off = through Cisco), the certificate, and the
/// user's own list of sites that skip the VPN.
/// Saving the "不走 VPN" list and making it take effect, for the 分流
/// page and the 连接 page alike (DESIGN.md §26.12, §四十四): stored,
/// networks to the drop-protection allowlist in either mode, names to
/// the split forwarder unless Cisco carries the traffic.
enum DirectList {
    /// Networks (and the local one) to the drop-protection allowlist.
    static func pushNetworks() {
        HelperClient.shared.updateAllowNetworks(ProfileStore.loadAppSettings().effectiveAllowNetworks) { _ in }
    }

    /// Stores `sites`, pushes them, and returns the stored settings.
    /// `note` gets a line for the user when the background service is
    /// too old to take the names (nil when it took them).
    @discardableResult
    static func save(_ sites: [DirectSite], note: ((String?) -> Void)? = nil) -> AppSettings {
        var stored = ProfileStore.loadAppSettings()
        stored.directSites = sites
        stored.directGroups = nil
        stored.directCustom = nil
        ProfileStore.saveAppSettings(stored)
        pushNetworks()
        if !HelperClient.shared.usesCisco {
            HelperClient.shared.pushDirectDomains { taken in
                note?(taken == nil ? "已保存；后台服务版本过旧，更新后生效。" : nil)
            }
        }
        return stored
    }
}

/// Fixed data instead of the live state (offscreen screenshots).
struct SplitPagePreview {
    var ownConnection = true
    var sites: [DirectSite] = []
    var routes: [ProxyRoute] = []
}

struct SplitPage: View {
    var preview: SplitPagePreview? = nil
    /// 分流直连, 分流代理 or 局域网 (§69.9).
    @Binding var section: String
    @ObservedObject private var manager = HelperClient.shared
    @ObservedObject private var window = SettingsWindow.shared
    @State private var settings = ProfileStore.loadAppSettings()
    @State private var sites = DirectSites.sites(ProfileStore.loadAppSettings())
    @State private var certificates: [CertificateRelay.ClientIdentity] = []
    @State private var newSite = ""
    @State private var siteNote: String?
    @State private var confirmSwitch: Bool?
    @State private var localNetworks: [String] = []
    private var own: Bool { preview?.ownConnection ?? manager.ownConnection }
    private var proxyCount: Int { preview.map { $0.routes.count } ?? (settings.proxyRoutes ?? []).count }

    var body: some View {
        Form {
            // The master switch in the page's status card (§69.14): what on
            // and off mean, in the card itself.
            Section {
                if let on = confirmSwitch {
                    HStack {
                        Text(on ? "要用证书重新连接一次，手机需要再批准。" : "要改回经 Cisco 重新连接一次。")
                            .font(.callout)
                        Spacer()
                        Button("取消") { confirmSwitch = nil }
                        Button("重新连接") {
                            confirmSwitch = nil
                            manager.setSplit(on: on)
                        }
                    }
                }
                if own, preview == nil,
                   let problem = LoginCertificate.problem(settings.clientCertificate, certificates) {
                    EgressCallout(icon: "exclamationmark.triangle.fill", tint: .red, text: problem) {
                        Button("去「账号」") { UserDefaults.standard.set("credentials", forKey: "settingsTab") }
                    }
                }
                SettingsSegments(items: [("direct", "分流直连 · \(sites.count) 条"),
                                         ("proxy", "分流代理 · \(proxyCount) 个"),
                                         ("lan", "局域网")], selection: $section)
            } header: {
                PageHeader(symbol: "arrow.triangle.branch", color: SettingsTone.direct, title: "按网站分流",
                         status: own
                            ? "开 · \(sites.count) 条直连，\(proxyCount) 个代理，其余走 Cisco"
                            : "关 · 经 Cisco 连接，按公司的规则分流",
                         dot: own ? .green : nil) {
                    AlwaysSwitchTrack(isOn: Binding(
                        get: { own },
                        set: { on in
                            guard preview == nil else { return }
                            if manager.switchIsOn { confirmSwitch = on } else { manager.setSplit(on: on) }
                        }))
                        .disabled(manager.splitSwitchPending)
                        .accessibilityLabel("按网站分流")
                }
            } footer: {
                SplitOrderStrip()
            }

            switch section {
            case "proxy":
                ProxySections(splitOn: own, previewRoutes: preview?.routes) { settings = $0 }
            case "lan":
                Section {
                Toggle(isOn: Binding(
                    get: { settings.isAutoLANOn },
                    set: { on in
                        var stored = ProfileStore.loadAppSettings()
                        stored.autoLAN = on
                        ProfileStore.saveAppSettings(stored)
                        settings = stored
                        pushNetworks()
                    })) {
                    IconLabel(title: "本地局域网直连",
                              subtitle: localNetworks.isEmpty ? "自动识别你当前连着的网段（现在没有）"
                                : "自动识别，现在是 " + localNetworks.joined(separator: "、"),
                              symbol: "house.fill", color: SettingsTone.direct)
                }
                } footer: {
                    Footnote("你现在连着的局域网（家里的 NAS、打印机）不走 Cisco；Cisco 掉线时也照常可用。")
                }
                if manager.usesCisco {
                    Section("Cisco 的局域网访问") {
                        LocalLanStatus()
                    }
                }
            default:
                if !settings.directOn {
                    Section {
                        EgressCallout(icon: "pause.circle.fill", tint: .orange,
                                      text: "分流直连已在菜单栏面板上关闭。",
                                      caption: "关闭期间这些网站走 Cisco。") {
                            Button("打开") { setDirect(on: true) }
                        }
                    }
                }
                Section {
                if sites.isEmpty {
                    EmptyGuide(symbol: "arrow.uturn.right", color: SettingsTone.direct, title: "还没有不走 Cisco 的网站",
                               text: "在下面输入一个网站、网段或清单名，例如 example.com、10.1.0.0/16、geosite:apple。") {
                        EmptyView()
                    }
                }
                ForEach(sites) { site in
                    HStack(spacing: 10) {
                        IconTile(symbol: icon(site), color: SettingsTone.direct)
                        VStack(alignment: .leading, spacing: 1) {
                            Text(site.name)
                            Text(caption(site))
                                .font(.caption)
                                .foregroundStyle(.secondary)
                                .lineLimit(1)
                                .truncationMode(.tail)
                        }
                        Spacer()
                        Button {
                            sites.removeAll { $0 == site }
                            saveSites()
                        } label: {
                            Image(systemName: "minus.circle.fill").foregroundStyle(.red)
                        }
                        .buttonStyle(.borderless)
                        .help("从名单删除")
                    }
                }
                HStack(spacing: 8) {
                    AlwaysTextField("例如 example.com、geosite:apple、10.1.0.0/16", text: $newSite, onSubmit: addSite)
                    Button("添加", action: addSite)
                        .disabled(ListRule.parse(newSite) == nil)
                    // Examples the moment the pointer is on the question
                    // mark, the list names one click away (§26.16, §26.18).
                    HoverHelp(action: { NSWorkspace.shared.open(Self.referenceURL) }) {
                        RuleExamples()
                    }
                }
                if let problem = ListRule.problem(newSite) {
                    Text(problem).font(.caption).foregroundStyle(.orange)
                }
            } header: {
                Text("不走 Cisco 的网站")
            } footer: {
                Footnote(siteNote ?? (own
                    ? "改动立即生效，不用重新连接。写法示例：鼠标停在输入框旁的问号上；点问号打开全部清单名。"
                    : "分流关闭（经 Cisco）时，只有网段和本地局域网起作用：断线保护期间照常可用。网址和清单在分流开启后生效。"))
            }


                SiteListsSection()
            }
        }
        .formStyle(.grouped)
        .onAppear {
            if let preview { sites = preview.sites; return }
            certificates = CertificateRelay.loginCandidates()
            localNetworks = LocalNetwork.current()
            // The 连接 page may have changed the list meanwhile (§四十四).
            settings = ProfileStore.loadAppSettings()
            sites = DirectSites.sites(settings)
            if settings.directSites == nil { saveSites() }  // migrate once
        }
    }

    /// Neutral, work-flavoured samples (DESIGN.md §34.3): the list is for
    /// traffic that need not cross the employer's network, so the card
    /// shows no region or streaming examples. geoip:cn still parses.
    static let examples: [(rule: String, meaning: String)] = [
        ("example.com", "这个网站和它所有子域名"),
        ("full:www.example.com", "只这一个域名"),
        ("keyword:example", "域名里含这个词"),
        ("10.0.0.5", "单个地址"),
        ("192.168.50.0/24", "一个网段"),
        ("geosite:apple", "苹果相关域名（系统更新、App Store 等）"),
        ("geosite:microsoft", "微软相关域名"),
        ("geosite:github", "GitHub 相关域名"),
        ("geosite:apple@cn", "只取清单里标了 @cn 的条目"),
    ]

    /// The full list of geosite names (domain-list-community's data).
    static let referenceURL = URL(string: "https://github.com/v2fly/domain-list-community/tree/master/data")!


    private func icon(_ site: DirectSite) -> String {
        guard site.domains.count == 1, let rule = ListRule.parse(site.domains[0]) else { return "globe" }
        switch rule {
        case .domain, .full: return "globe"
        case .keyword, .regexp: return "text.magnifyingglass"
        case .geosite: return "list.bullet"
        case .geoip: return "flag.fill"
        case .network: return "point.3.connected.trianglepath.dotted"
        }
    }

    private func caption(_ site: DirectSite) -> String {
        if site.domains.count == 1, let rule = ListRule.parse(site.domains[0]) { return rule.kind }
        return site.domains.joined(separator: "、")
    }

    private func addSite() {
        guard let rule = ListRule.parse(newSite) else { return }
        if !sites.contains(where: { $0.domains == [rule.text] || (rule.isNetwork == false && $0.domains.contains(rule.text)) }) {
            sites.append(DirectSite(name: rule.text, domains: [rule.text]))
        }
        newSite = ""
        saveSites()
    }

    private func pushNetworks() { DirectList.pushNetworks() }

    /// The 分流直连 switch (also on the panel): the list rests or applies,
    /// live, without reconnecting (§69.9).
    private func setDirect(on: Bool) {
        var stored = ProfileStore.loadAppSettings()
        stored.directPaused = on ? nil : true
        ProfileStore.saveAppSettings(stored)
        settings = stored
        DirectList.pushNetworks()
        if !manager.usesCisco { manager.pushDirectDomains() }
    }

    private func saveSites() {
        settings = DirectList.save(sites) { note in siteNote = note }
    }

}

/// The site lists' version and updates (DESIGN.md §66.30), shared by the
/// split list and exit protection.
struct SiteListsSection: View {
    @ObservedObject private var updater = GeoUpdater.shared
    @State private var autoUpdate = ProfileStore.loadAppSettings().isSiteListsAutoUpdateOn
    @State private var result: String?

    var body: some View {
        Section {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text(updater.version == nil ? "还没下载" : "现用 \(updater.versionText)")
                    if updater.checking {
                        Text(updater.version == nil ? "正在下载…" : "正在检查…").font(.caption).foregroundStyle(.secondary)
                    } else if let error = updater.lastError {
                        Text((updater.version == nil ? "还没下载成功：" : "上次更新没成功：") + error
                             + (error == GeoUpdater.unreachable ? "（Cisco 连上后会自动再试）" : ""))
                            .font(.caption).foregroundStyle(.orange)
                    } else if let result {
                        Text(result).font(.caption).foregroundStyle(.secondary)
                    } else if let when = updater.lastSuccess {
                        Text("上次检查 \(when.formatted(date: .abbreviated, time: .shortened))")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }
                Spacer()
                Button(updater.version == nil ? "立即下载" : "立即更新") {
                    let before = updater.version
                    result = nil
                    updater.check { error in
                        guard error == nil else { return }
                        result = updater.version == before ? "已经是最新" : "已更新，规则已按新清单生效"
                    }
                }
                .disabled(updater.checking)
            }
            Toggle("每天自动更新", isOn: $autoUpdate)
                .onChange(of: autoUpdate) { on in
                    var settings = ProfileStore.loadAppSettings()
                    settings.siteListsAutoUpdate = on
                    ProfileStore.saveAppSettings(settings)
                }
        } header: {
            Text("网站清单（geosite）")
        } footer: {
            Footnote("分流名单和出口保护里的 geosite: 都按这份清单展开。清单来自 v2fly/domain-list-community，第一次启动时自动下载、存在本机；开着自动更新时每天看一次有没有新版，内容变了才下载，校验通过才换上。")
        }
        .onAppear { updater.reload() }
    }
}

/// The hover card on the split page: the rules in one column, what they
/// mean in the other (§26.16, §26.18).
struct RuleExamples: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("写法示例（每次添加一条）").font(.headline)
            Grid(alignment: .leading, horizontalSpacing: 14, verticalSpacing: 4) {
                ForEach(SplitPage.examples, id: \.rule) { example in
                    GridRow {
                        Text(example.rule).font(.system(.body, design: .monospaced))
                        Text(example.meaning).foregroundStyle(.secondary)
                    }
                }
            }
            Text("geosite 后面填清单名，来自开源的 v2fly/domain-list-community（现用 \(GeoUpdater.shared.versionText)）。出口保护用同一种写法。\n点这个问号打开全部清单名：github.com/v2fly/domain-list-community")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }
}

// MARK: - Diagnostics (with the former Statistics page)

struct DiagnosticsPage: View {
    @ObservedObject private var manager = HelperClient.shared
    @State private var stats: (bytesIn: Int64, bytesOut: Int64, tunnelIf: String)?
    @State private var statsMessage: String?
    @State private var statsRunning = false
    @State private var statsRequest = UUID()
    @State private var leakItems: [LeakCheckItem]?
    @State private var leakMessage: String?
    @State private var lanResult: String?
    @State private var lanRunning = false
    @State private var confirmClearDrops = false
    @State private var neighbors: [NeighborNotice]?
    @State private var leakRunning = false
    /// "一键体检" was pressed while this page was open.
    @State private var checkupRan = false

    private func checkNeighbors() {
        let manager = HelperClient.shared
        let active = manager.state != .disconnected
        let cisco = manager.usesCisco
        let split = manager.ownConnection
        DispatchQueue.global(qos: .userInitiated).async {
            let found = NetworkNeighbors.notices(NetworkNeighbors.observe(
                oursActive: active && !cisco, ciscoTunnel: active && cisco, splitOn: split))
            DispatchQueue.main.async { neighbors = found }
        }
    }

    var body: some View {
        Form {
            // One click checks everything that can be checked here (§69.14,
            // was three buttons in three places).
            Section {
                checkRow("其他 VPN 与代理", symbol: "rectangle.connected.to.line.below", color: .purple,
                         state: neighbors == nil ? .running : (neighbors!.contains { $0.level == .warning } ? .warning : .passed)) {
                    if let neighbors {
                        if neighbors.isEmpty {
                            Text("没有发现").font(.caption).foregroundStyle(.secondary)
                        }
                        ForEach(neighbors, id: \.text) { notice in
                            Text(notice.text).font(.caption)
                                .foregroundStyle(notice.level == .warning ? Color.orange : Color.secondary)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    }
                }
                checkRow("泄漏自检", symbol: "drop.fill", color: .blue, state: leakState) {
                    if let leakMessage {
                        Text(leakMessage).font(.caption).foregroundStyle(manager.showsConnected ? Color.red : Color.secondary)
                    }
                    ForEach(leakItems ?? [], id: \.item) { item in
                        Label {
                            Text("\(item.item)：\(item.detail)").font(.caption)
                        } icon: {
                            Image(systemName: item.informational ? "info.circle"
                                  : (item.passed ? "checkmark.circle.fill" : "xmark.circle.fill"))
                                .foregroundStyle(item.informational ? Color.secondary
                                                 : (item.passed ? Color.green : Color.red))
                        }
                    }
                }
                checkRow("访问本地路由器", symbol: "wifi.router.fill", color: SettingsTone.direct,
                         state: lanRunning ? .running : (lanResult == nil ? .idle : .done)) {
                    if let lanResult {
                        Text(lanResult).font(.caption).textSelection(.enabled)
                    }
                }
            } header: {
                PageHeader(symbol: "stethoscope", color: SettingsTone.diagnostics, title: "诊断",
                         status: dropLine, dot: lastDropColor) {
                    Button(checking ? "正在体检…" : "一键体检") { runCheckup() }
                        .buttonStyle(.borderedProminent)
                        .disabled(checking)
                }
            } footer: {
                Footnote("Clash、sing-box 等只开系统代理时可以和 Cisco 共存，开 TUN/增强模式会抢网络。连着 Cisco 却打不开家里的设备时，把体检结果截图发给维护者。")
            }
            .onAppear { checkNeighbors() }
            // Our own tunnel and DNS forwarder must never read as someone
            // else's: look again when the session's state changes.
            .onChange(of: HelperClient.shared.state) { _ in checkNeighbors() }

            Section("本次连接") {
                LabeledContent("状态") { Text(manager.stateLine).foregroundStyle(manager.gatewayTrustFailed ? Color.red : Color.secondary) }
                LabeledContent("连接时长") {
                    if manager.showsConnected, let since = manager.connectedSince {
                        TimelineView(.periodic(from: .now, by: 1)) { _ in
                            Text(durationText(Date().timeIntervalSince(since))).monospacedDigit()
                        }
                        .foregroundStyle(.secondary)
                    } else {
                        Text("—").foregroundStyle(.secondary)
                    }
                }
                LabeledContent("流量") {
                    HStack(spacing: 10) {
                        if let stats, !stats.tunnelIf.isEmpty {
                            Text("↓ \(bytes(stats.bytesIn))  ↑ \(bytes(stats.bytesOut))")
                                .monospacedDigit()
                                .foregroundStyle(.secondary)
                        } else {
                            Text(statsRunning ? "读取中…" : (statsMessage ?? "未连接"))
                                .foregroundStyle(.secondary)
                        }
                        Button {
                            refreshStats()
                        } label: {
                            Image(systemName: "arrow.clockwise")
                        }
                        .buttonStyle(.borderless)
                        .help("刷新本次 Cisco 流量")
                        .disabled(statsRunning || !manager.showsConnected)
                    }
                }
            }

            Section {
                if manager.dropHistory.isEmpty {
                    Text("暂无掉线").foregroundStyle(.secondary)
                } else {
                    ForEach(manager.dropHistory.reversed()) { drop in
                        HStack(alignment: .center, spacing: 8) {
                            VStack(alignment: .leading, spacing: 2) {
                                HStack(spacing: 6) {
                                    Text(dropTimeText(drop))
                                    if drop.isSleepRecord {
                                        Text("睡眠中").font(.caption).foregroundStyle(.secondary)
                                    }
                                    if let engine = drop.engineLabel {
                                        Text(engine).font(.caption).foregroundStyle(.secondary)
                                    }
                                }
                                Text(drop.summary)
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                                    .fixedSize(horizontal: false, vertical: true)
                            }
                            Spacer()
                            Text(drop.outcomeLabel)
                                .font(.callout)
                                .foregroundStyle(dropOutcomeColor(drop.resolvedOutcome))
                            Button {
                                manager.deleteDrop(drop.id)
                            } label: {
                                Image(systemName: "minus.circle.fill").foregroundStyle(.red)
                            }
                            .buttonStyle(.borderless)
                            .help("删除这条记录")
                        }
                    }
                }
            } header: {
                HStack {
                    Text("掉线记录（\(manager.dropHistory.count) 次，最多存 \(ProfileStore.dropHistoryLimit) 次）")
                    Spacer()
                    Button("清空") { confirmClearDrops = true }
                        .buttonStyle(.borderless)
                        .disabled(manager.dropHistory.isEmpty)
                        .confirmationDialog("清空全部掉线记录？", isPresented: $confirmClearDrops) {
                            Button("清空", role: .destructive) { manager.clearDropHistory() }
                        } message: {
                            Text("只删除这里的记录，不影响连接。")
                        }
                }
            } footer: {
                Footnote("每条写明断了多久、重新登录了几次、最后恢复没有；一次睡眠中的断线合成一条。")
            }

            Section {
                LabeledContent {
                    Button("导出…") {
                        DiagnosticsExporter.export(manager: manager, profile: ProfileStore.loadProfile())
                    }
                } label: {
                    IconLabel(title: "诊断包", subtitle: "日志与状态，不含密码与账号", symbol: "archivebox.fill", color: SettingsTone.neutral)
                }
            }
        }
        .formStyle(.grouped)
        .onAppear(perform: refreshStats)
        .onChange(of: manager.showsConnected) { _ in
            refreshStats()
            leakItems = nil
            leakMessage = nil
        }
    }

    private enum CheckState { case idle, running, passed, warning, failed, done }

    /// Only while a check the user started still runs (the automatic look
    /// for other VPNs on opening the page is not one).
    private var checking: Bool { lanRunning || leakRunning || (checkupRan && neighbors == nil) }

    private var leakState: CheckState {
        if leakRunning { return .running }
        if let items = leakItems {
            return items.contains { !$0.passed && !$0.informational } ? .failed : .passed
        }
        if leakMessage != nil { return checkupRan && !manager.showsConnected ? .idle : .failed }
        return .idle
    }

    /// One check: its name and result on the first line, details under it.
    private func checkRow<Details: View>(_ title: String, symbol: String, color: Color, state: CheckState,
                                         @ViewBuilder details: () -> Details) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 10) {
                IconTile(symbol: symbol, color: color)
                Text(title)
                Spacer()
                switch state {
                case .running: ProgressView().controlSize(.small)
                case .passed: Label("正常", systemImage: "checkmark.circle.fill").foregroundStyle(.green).font(.callout)
                case .warning: Label("留意", systemImage: "exclamationmark.triangle.fill").foregroundStyle(.orange).font(.callout)
                case .failed: Label("有问题", systemImage: "xmark.circle.fill").foregroundStyle(.red).font(.callout)
                case .done: Label("已完成", systemImage: "checkmark.circle").foregroundStyle(.secondary).font(.callout)
                case .idle: Text("未检查").foregroundStyle(.tertiary).font(.callout)
                }
            }
            VStack(alignment: .leading, spacing: 3) { details() }
                .padding(.leading, 32)
        }
    }

    /// The newest drop, or that there was none.
    private var dropLine: String {
        guard let drop = manager.dropHistory.last else { return "还没有掉线记录" }
        return "上次掉线 \(ConnectPage.when(drop.droppedAt)) · \(drop.outcomeLabel)"
    }

    private var lastDropColor: Color? {
        manager.dropHistory.last.map { dropOutcomeColor($0.resolvedOutcome) }
    }

    private func runCheckup() {
        checkupRan = true
        neighbors = nil
        checkNeighbors()
        runLanCheck()
        if manager.showsConnected {
            runLeakCheck()
        } else {
            leakItems = nil
            leakMessage = "没连 Cisco，连上后再查"
        }
    }

    private func dropOutcomeColor(_ outcome: DropRecord.Outcome) -> Color {
        switch outcome {
        case .recovered: return .green
        case .failed: return .red
        case .stoppedByUser, .quit: return .secondary
        }
    }

    private func refreshStats() {
        let request = UUID()
        statsRequest = request
        stats = nil
        statsMessage = nil
        statsRunning = manager.showsConnected
        guard statsRunning else { return }
        HelperClient.shared.fetchStats { result in
            guard statsRequest == request else { return }
            statsRunning = false
            if let (bytesIn, bytesOut, tunnelIf) = result, !tunnelIf.isEmpty {
                stats = (bytesIn: bytesIn, bytesOut: bytesOut, tunnelIf: tunnelIf)
            } else {
                statsMessage = manager.usesCisco ? "未读到 Cisco 流量，请刷新重试"
                    : "未读到隧道流量，请检查后台服务"
            }
        }
    }

    private func runLeakCheck() {
        leakMessage = nil
        leakItems = nil
        leakRunning = true
        HelperClient.shared.runLeakCheck { items in
            leakRunning = false
            if let items {
                leakItems = items
            } else {
                leakMessage = "后台服务未回应（版本过旧或未运行）"
            }
        }
    }

    private func runLanCheck() {
        lanRunning = true
        lanResult = nil
        DispatchQueue.global().async {
            let text = HomeLanCheck.describe(HomeLanCheck.run())
            DispatchQueue.main.async {
                lanResult = text
                lanRunning = false
            }
        }
    }

    private func bytes(_ count: Int64) -> String {
        let formatter = ByteCountFormatter()
        formatter.countStyle = .file
        formatter.allowsNonnumericFormatting = false
        return formatter.string(fromByteCount: count)
    }

    /// A sleep record spans its first to its newest drop (DESIGN.md §41).
    private func dropTimeText(_ drop: DropRecord) -> String {
        guard drop.sleepDropCount > 1 else { return formatDate(drop.droppedAt) }
        let formatter = DateFormatter()
        formatter.dateFormat = Calendar.current.isDate(drop.droppedAt, inSameDayAs: drop.latestDropAt) ? "HH:mm" : "M月d日 HH:mm"
        return "\(formatDate(drop.droppedAt)) – \(formatter.string(from: drop.latestDropAt))"
    }

    private func formatDate(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "M月d日 HH:mm"
        return formatter.string(from: date)
    }

    private func durationText(_ seconds: TimeInterval) -> String {
        let total = Int(seconds)
        let hours = total / 3600, minutes = total % 3600 / 60, secs = total % 60
        if hours > 0 { return "\(hours) 小时 \(minutes) 分" }
        if minutes > 0 { return "\(minutes) 分 \(secs) 秒" }
        return "\(secs) 秒"
    }
}

