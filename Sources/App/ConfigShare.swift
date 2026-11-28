import Foundation

@_silgen_name("ac_share_export")
private func ac_share_export(_ request: UnsafePointer<CChar>) -> UnsafeMutablePointer<CChar>?
@_silgen_name("ac_share_preview")
private func ac_share_preview(_ request: UnsafePointer<CChar>) -> UnsafeMutablePointer<CChar>?
@_silgen_name("ac_share_apply")
private func ac_share_apply(_ request: UnsafePointer<CChar>) -> UnsafeMutablePointer<CChar>?

/// Sharing settings as one commented file (DESIGN §七十五). The file text,
/// its reading and what an import adds are the Rust core's
/// (core/src/config_share.rs); this side hands over this Mac's settings,
/// parses pasted proxy links with the proxy editor's own parser, writes
/// the result and tells the background service, as the pages do.
enum ConfigShare {
    // MARK: This Mac's settings, as the core reads them

    struct WireProxy: Encodable {
        var id: String
        var name: String
        var kind: String
        var host: String
        var port: Int
        var username: String?
        var password: String?
        var ports: String?
        var sni: String?
        var pin_sha256: String?
        var obfs: String?
        var obfs_password: String?
        var ech: String?
        var up_mbps: Int?
        var down_mbps: Int?
        var hop_seconds: Int?
        var sites: [String]
        var exceptions: [String]
    }

    struct WireServer: Codable {
        var id: String?
        var name: String
        var address: String
        var cisco_name: String?
    }

    struct WireCisco: Encodable {
        var servers: [WireServer]
        var selected: String
        var group: String
    }

    struct WireGeneral: Encodable {
        var drop_protection: Bool
        var auto_lan: Bool
        var auto_connect_on_launch: Bool
        var approval_card: Bool
        var site_lists_auto_update: Bool
    }

    struct Local: Encodable {
        var direct_sites: [DirectSite]
        var direct_exceptions: [String]
        var proxies: [WireProxy]
        var egress: [EgressProtection.Group]
        var cisco: WireCisco
        var general: WireGeneral
    }

    /// `secrets`: the proxies' passwords, read from the keychain (only for
    /// full links on export; at most one keychain question per run).
    static func local(secrets: Bool = false) -> Local {
        let settings = ProfileStore.loadAppSettings()
        let profile = ProfileStore.loadProfile()
        let proxies = (settings.proxyRoutes ?? []).map { r in
            WireProxy(id: r.id.uuidString, name: r.name, kind: r.kind.rawValue, host: r.host, port: r.port,
                      username: r.username, password: secrets ? ProxyPasswords.password(for: r) : nil,
                      ports: r.hysteriaPorts, sni: r.sni, pin_sha256: r.pinSHA256, obfs: r.obfs,
                      obfs_password: secrets ? ProxyPasswords.obfsPassword(for: r) : nil, ech: r.ech,
                      up_mbps: r.upMbps, down_mbps: r.downMbps, hop_seconds: r.hopSeconds,
                      sites: r.sites, exceptions: r.exceptions ?? [])
        }
        let egress = (settings.egressProtection ?? EgressProtection()).withoutExpandedMatches.groups
        return Local(
            direct_sites: DirectSites.sites(settings),
            direct_exceptions: settings.directExceptions ?? [],
            proxies: proxies,
            egress: egress,
            cisco: WireCisco(servers: profile.servers.map {
                WireServer(id: $0.id.uuidString, name: $0.name, address: $0.address, cisco_name: $0.ciscoName)
            }, selected: profile.server, group: profile.group),
            general: WireGeneral(drop_protection: settings.isDropProtectionOn, auto_lan: settings.isAutoLANOn,
                                 auto_connect_on_launch: profile.autoConnectOnLaunch,
                                 approval_card: settings.isApprovalCardOn,
                                 site_lists_auto_update: settings.isSiteListsAutoUpdateOn))
    }

    // MARK: Export

    struct ExportRequest: Encodable {
        var local: Local
        var direct: Bool
        var proxies: [String]
        var egress: [UInt32]
        var cisco: Bool
        var general: Bool
        var full_links: Bool
        var app_version: String
        var date: String
    }

    struct Exported: Decodable, Equatable {
        var text: String
        var to_fill: Int
        var contains_secrets: Bool
        var renamed: [String]
    }

    static func export(_ request: ExportRequest) -> Exported? {
        GeoData.prepare()
        return CiscoProfiles.callJSON(ac_share_export, request)
    }

    static var today: String {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.dateFormat = "yyyy-MM-dd"
        return f.string(from: Date())
    }

    // MARK: Import

    struct Item: Decodable, Hashable {
        var text: String
        var new: Bool
    }

    struct Preview: Decodable {
        struct Direct: Decodable {
            var rules: [Item]
            var exceptions: [Item]
            var groups: [Group]
            var added_rules: Int
            var added_exceptions: Int
        }
        struct Group: Decodable, Hashable {
            var name: String
            var rules: [Item]
        }
        struct Proxy: Decodable, Identifiable {
            var index: Int
            var name: String
            var import_name: String
            var kind: String
            var link: String
            var complete: Bool
            var hint: String
            var rules: [String]
            var exceptions: [String]
            var id: Int { index }
        }
        struct Egress: Decodable, Hashable {
            var name: String
            var import_name: String
            var rules: [String]
            var exceptions: [String]
            var countries: [String]
            var unverified: String
        }
        struct Server: Decodable, Hashable {
            var name: String
            var cisco_entry: String?
            var address: String?
            var new: Bool
        }
        struct Cisco: Decodable {
            var servers: [Server]
            var added: Int
            var group: String?
            var selected: String?
        }
        var ok: Bool
        var error: String?
        var legacy_egress: Bool
        var app_version: String
        var exported: String
        var contains_secrets: Bool
        var direct: Direct?
        var proxies: [Proxy]
        var egress: [Egress]
        var cisco: Cisco?
        var general: [GeneralChange]
        var skipped: [String]
    }

    struct GeneralChange: Decodable, Hashable {
        var key: String
        var local: Bool
        var file: Bool

        var label: String {
            switch key {
            case "drop_protection": return "断线保护"
            case "auto_lan": return "本地局域网直连"
            case "auto_connect_on_launch": return "打开 App 时自动连接"
            case "approval_card": return "等手机批准时在菜单栏下提醒"
            default: return "网站清单每天自动更新"
            }
        }
    }

    private struct PreviewRequest: Encodable {
        var text: String
        var local: Local
    }

    static func preview(_ text: String) -> Preview? {
        GeoData.prepare()
        return CiscoProfiles.callJSON(ac_share_preview, PreviewRequest(text: text, local: local()))
    }

    private struct ApplyRequest: Encodable {
        var text: String
        var local: Local
        var direct: Bool
        var egress: Bool
        var cisco: Bool
        var general: Bool
        var proxies: [Int]
    }

    private struct NewProxy: Decodable {
        var index: Int
        var name: String
        var kind: String
        var sites: [String]
        var exceptions: [String]
    }

    private struct Applied: Decodable {
        var ok: Bool
        var error: String?
        var direct_sites: [DirectSite]?
        var direct_exceptions: [String]?
        var proxies: [NewProxy]
        var egress_groups: [EgressProtection.Group]
        var cisco_servers: [WireServer]?
        var selected: String?
        var group: String?
        var general: [GeneralChange]
        var added_rules: Int
        var added_exceptions: Int
        var added_servers: Int
    }

    /// What the user picked on the import sheet.
    struct Choices {
        var direct = true
        var proxies = true
        var egress = true
        var cisco = true
        var general = false
        /// The link pasted for each proxy (file index), maybe empty.
        var links: [Int: String] = [:]
    }

    /// A pasted link as the proxy editor reads it; links still carrying
    /// the file's `{…}` placeholders are refused.
    static func parseLink(_ text: String) -> ProxyLink.Parsed? {
        let link = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !link.isEmpty else { return nil }
        if link.contains("{") || link.contains("}") { return .problem("链接里还有没填的 {…}，请换成你自己的完整链接") }
        return ProxyLink.parse(link)
    }

    /// Everything the import changed, to put back.
    struct Undo {
        var profile: Profile
        var settings: AppSettings
        var egress: EgressProtection
        var newProxies: [ProxyRoute]
    }

    struct Outcome {
        var line: String
        var undo: Undo?
    }

    /// Writes what the core computed. Only adds: nothing this Mac had is
    /// removed or changed, except the general switches the user ticked.
    static func importNow(_ text: String, choices: Choices, completion: @escaping (Outcome) -> Void) {
        GeoData.prepare()
        let before = local()
        let request = ApplyRequest(text: text, local: before, direct: choices.direct, egress: choices.egress,
                                   cisco: choices.cisco, general: choices.general,
                                   proxies: choices.proxies ? Array(choices.links.keys).sorted() : [])
        guard let applied: Applied = CiscoProfiles.callJSON(ac_share_apply, request), applied.ok else {
            completion(Outcome(line: "没有导入：这个文件读不出来了，请重新选一次。", undo: nil))
            return
        }
        let oldProfile = ProfileStore.loadProfile()
        var settings = ProfileStore.loadAppSettings()
        let oldSettings = settings
        let oldEgress = settings.egressProtection ?? EgressProtection()

        // Proxies: a pasted link makes a working proxy, as the editor saves one.
        var newRoutes: [ProxyRoute] = []
        var linked = 0
        for np in applied.proxies {
            var route = ProxyRoute(name: np.name, kind: ProxyRoute.Kind(rawValue: np.kind) ?? .socks5,
                                   host: "", port: 0, sites: np.sites, enabled: false)
            route.exceptions = np.exceptions.isEmpty ? nil : np.exceptions
            if let parsed = choices.links[np.index].flatMap(parseLink), let l = parsed.link {
                route.kind = l.kind
                route.host = l.host
                route.port = l.port
                route.username = l.username
                if l.kind == .hysteria2 {
                    route.hysteriaPorts = l.ports
                    route.sni = l.sni
                    route.pinSHA256 = l.pinSHA256
                    route.obfs = l.obfs
                    route.ech = l.ech
                    route.upMbps = l.upMbps
                    route.downMbps = l.downMbps
                    route.hopSeconds = l.hopSeconds
                    if let obfsPassword = l.obfsPassword, l.obfs != nil {
                        route.obfsPasswordStamp = ProxyPasswords.saveObfs(obfsPassword, for: route) ? UUID().uuidString : nil
                    }
                }
                if let password = l.password, l.kind == .hysteria2 || l.username != nil {
                    route.passwordStamp = ProxyPasswords.save(password, for: route) ? UUID().uuidString : nil
                }
                route.enabled = true
                linked += 1
            }
            newRoutes.append(route)
        }

        if let sites = applied.direct_sites {
            settings.directSites = sites
            settings.directGroups = nil
            settings.directCustom = nil
        }
        if let exceptions = applied.direct_exceptions { settings.directExceptions = exceptions.isEmpty ? nil : exceptions }
        if !newRoutes.isEmpty { settings.proxyRoutes = (settings.proxyRoutes ?? []) + newRoutes }
        var profile = oldProfile
        var dropChanged = false
        var egressOffWithDrop = false
        for change in applied.general {
            switch change.key {
            case "drop_protection":
                settings.dropProtection = change.file
                dropChanged = true
                if !change.file, settings.egressProtection?.enabled == true {
                    settings.egressProtection?.enabled = false
                    egressOffWithDrop = true
                }
            case "auto_lan": settings.autoLAN = change.file
            case "auto_connect_on_launch": profile.autoConnectOnLaunch = change.file
            case "approval_card": settings.approvalCard = change.file
            case "site_lists_auto_update": settings.siteListsAutoUpdate = change.file
            default: break
            }
        }
        ProfileStore.saveAppSettings(settings, updatingEgress: egressOffWithDrop)

        if let servers = applied.cisco_servers {
            profile.servers = servers.map {
                ServerEntry(id: $0.id.flatMap(UUID.init(uuidString:)) ?? UUID(), name: $0.name,
                            address: $0.address, ciscoName: $0.cisco_name)
            }
        }
        if let selected = applied.selected { profile.server = selected }
        if let group = applied.group { profile.group = group }
        if profile != oldProfile { ProfileStore.saveProfile(profile) }

        notify(dropChanged: dropChanged, approvalChanged: applied.general.contains { $0.key == "approval_card" })

        var parts: [String] = []
        if applied.added_rules > 0 { parts.append("\(applied.added_rules) 条直连规则") }
        if applied.added_exceptions > 0 { parts.append("\(applied.added_exceptions) 条直连例外") }
        if !newRoutes.isEmpty {
            parts.append("\(newRoutes.count) 个代理" + (linked < newRoutes.count ? "（\(newRoutes.count - linked) 个待填链接）" : ""))
        }
        if applied.added_servers > 0 { parts.append("\(applied.added_servers) 台 Cisco 服务器") }
        if !applied.general.isEmpty { parts.append("\(applied.general.count) 项通用开关") }
        let undo = Undo(profile: oldProfile, settings: oldSettings, egress: oldEgress, newProxies: newRoutes)

        func finish(_ egressNote: String?) {
            var line = parts.isEmpty && egressNote == nil ? "没有可以加的：文件里的内容你都有了。" : "已导入：" + parts.joined(separator: "、")
            if let egressNote { line += parts.isEmpty ? egressNote : "；" + egressNote }
            if !newRoutes.isEmpty || !applied.egress_groups.isEmpty, let hint = hiddenHint(settings) { line += "。" + hint }
            completion(Outcome(line: line, undo: undo))
        }
        guard !applied.egress_groups.isEmpty else { finish(nil); return }
        var egress = ProfileStore.loadAppSettings().egressProtection ?? EgressProtection()
        let previous = egress
        egress.groups += applied.egress_groups
        HelperClient.shared.saveEgress(egress, replacing: previous) { ok in
            DispatchQueue.main.async {
                finish(ok ? "\(applied.egress_groups.count) 条出口保护（已暂停）"
                          : "出口保护没有导入（现在不能改出口保护，断开 Cisco 后再导入一次即可）")
            }
        }
    }

    /// Puts the settings back as they were before the import.
    static func undo(_ undo: Undo, completion: @escaping (Bool) -> Void) {
        let current = ProfileStore.loadAppSettings()
        let dropChanged = current.isDropProtectionOn != undo.settings.isDropProtectionOn
        let approvalChanged = current.isApprovalCardOn != undo.settings.isApprovalCardOn
        ProfileStore.saveAppSettings(undo.settings)
        ProfileStore.saveProfile(undo.profile)
        for route in undo.newProxies { ProxyPasswords.delete(for: route) }
        notify(dropChanged: dropChanged, approvalChanged: approvalChanged)
        let egressNow = ProfileStore.loadAppSettings().egressProtection ?? EgressProtection()
        guard egressNow != undo.egress else { completion(true); return }
        HelperClient.shared.saveEgress(undo.egress, replacing: egressNow) { ok in
            DispatchQueue.main.async { completion(ok) }
        }
    }

    /// The same pushes the split, proxy and connection pages make after saving.
    private static func notify(dropChanged: Bool, approvalChanged: Bool) {
        DirectList.pushNetworks()
        if !HelperClient.shared.usesCisco {
            HelperClient.shared.pushDirectDomains()
        } else if HelperClient.shared.state == .disconnected {
            HelperClient.shared.syncProxyOnly()
        }
        if dropChanged { HelperClient.shared.dropProtectionChanged() }
        if approvalChanged { ApprovalPrompt.shared.settingsChanged() }
    }

    /// Why the imported proxies or protections will not work yet, if so.
    private static func hiddenHint(_ settings: AppSettings) -> String? {
        if HelperClient.shared.usesCisco && HelperClient.shared.state != .disconnected {
            return "连着 Cisco 时分流代理和出口保护不起作用，在「分流」里打开按网站分流后才起作用"
        }
        if !settings.isDropProtectionOn { return "出口保护要先打开断线保护" }
        return nil
    }
}
