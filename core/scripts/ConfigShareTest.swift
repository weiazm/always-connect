// Configuration sharing end to end (DESIGN.md §七十五): the App's own
// export, import, write and undo code (Sources/App/ConfigShare.swift) with
// the Rust core, in a settings suite of its own and an in-memory keychain.
// The background service is a stand-in that records what it was told.
// Built and run by scripts/config-share-test.sh; sample data only.
import Foundation

// MARK: - Stand-ins for the App pieces that talk to the service

final class HelperClient {
    enum State { case disconnected, connected }
    static let shared = HelperClient()
    var usesCisco = false
    var state = State.disconnected
    var refuseEgress = false
    var calls: [String] = []

    func pushDirectDomains(completion: ((Bool?) -> Void)? = nil) { calls.append("pushDirectDomains"); completion?(true) }
    func syncProxyOnly() { calls.append("syncProxyOnly") }
    func dropProtectionChanged() { calls.append("dropProtectionChanged") }
    func updateAllowNetworks(_ networks: [String], completion: @escaping (Bool?) -> Void) {
        calls.append("updateAllowNetworks")
        completion(true)
    }
    /// As the real one: refused while a save is not allowed, otherwise stored.
    func saveEgress(_ config: EgressProtection, replacing previous: EgressProtection? = nil,
                    completion: @escaping (Bool) -> Void) {
        calls.append("saveEgress")
        let stored = ProfileStore.loadAppSettings().egressProtection ?? EgressProtection()
        guard !refuseEgress, previous == nil || previous == stored else { completion(false); return }
        var settings = ProfileStore.loadAppSettings()
        settings.egressProtection = config
        ProfileStore.saveAppSettings(settings, updatingEgress: true)
        completion(true)
    }
}

enum DirectList {
    static func pushNetworks() { HelperClient.shared.calls.append("pushNetworks") }
}

final class ApprovalPrompt {
    static let shared = ApprovalPrompt()
    func settingsChanged() { HelperClient.shared.calls.append("approvalChanged") }
}

@main
struct ConfigShareTest {
    static var fails = 0
    static func check(_ name: String, _ ok: Bool) {
        print("\(ok ? "PASS" : "FAIL") \(name)")
        if !ok { fails += 1 }
    }

    static var vault: [String: String] = [:]

    static func wipe() {
        UserDefaults(suiteName: AppGroups.suiteName)!.removePersistentDomain(forName: AppGroups.suiteName)
    }

    /// Runs the asynchronous import (or undo) to its end.
    static func wait<T>(_ start: (@escaping (T) -> Void) -> Void) -> T {
        var result: T?
        start { result = $0 }
        while result == nil { RunLoop.main.run(until: Date().addingTimeInterval(0.01)) }
        return result!
    }

    static func main() {
        precondition(AppGroups.suiteName.hasPrefix("com.example."), "the test must not use the App's own settings")
        SecretVault.load = { vaultReadCount += 1; return vault.isEmpty ? .missing : .found(vault) }
        SecretVault.save = { all, _ in vault = all; return true }
        SecretVault.names = { Array(vault.keys) }
        SecretVault.readLegacy = { _, _ in nil }
        SecretVault.hasLegacy = { _, _ in false }

        // MARK: The sharer
        wipe()
        var profile = Profile()
        profile.servers = [ServerEntry(name: "VPN-A", address: "vpn-a.example.com", ciscoName: "VPN-A"),
                           ServerEntry(name: "VPN-B", address: "vpn-b.example.com")]
        profile.server = "VPN-A"
        profile.group = "Staff"
        ProfileStore.saveProfile(profile)
        var socks = ProxyRoute(name: "示例 SOCKS5", kind: .socks5, host: "198.51.100.9", port: 1080,
                               sites: ["full:api.example.net", "geosite:github"], username: "alice")
        socks.passwordStamp = ProxyPasswords.save("p@ss word", for: socks) ? "s1" : nil
        var hy = ProxyRoute(name: "示例 Hysteria2", kind: .hysteria2, host: "proxy.example.net", port: 443,
                            sites: ["198.51.100.0/24"], hysteriaPorts: "443,20000-30000", sni: "proxy.example.net",
                            obfs: "salamander", upMbps: 50, downMbps: 200, hopSeconds: 30)
        hy.exceptions = ["full:static.example.org"]
        hy.passwordStamp = ProxyPasswords.save("s3cret/+", for: hy) ? "s2" : nil
        hy.obfsPasswordStamp = ProxyPasswords.saveObfs("ob fs", for: hy) ? "s3" : nil
        var settings = AppSettings()
        settings.directSites = [DirectSite(name: "example.com", domains: ["example.com"]),
                                DirectSite(name: "203.0.113.0/24", domains: ["203.0.113.0/24"])]
        settings.directExceptions = ["full:login.example.com"]
        settings.proxyRoutes = [socks, hy]
        ProfileStore.saveAppSettings(settings)
        var egress = EgressProtection()
        egress.enabled = true
        egress.groups = [EgressProtection.Group(id: 3, name: "示例：只从美国出口", enabled: true, sites: ["shop.example.com"],
                                                exceptions: ["full:cdn.shop.example.com"], expect: ["US"], unverified: .whenWrong)]
        settings = ProfileStore.loadAppSettings()
        settings.egressProtection = egress
        ProfileStore.saveAppSettings(settings, updatingEgress: true)
        check("the sharer's passwords are in the stand-in keychain", vault.count == 3)

        let local = ConfigShare.local()
        func request(_ l: ConfigShare.Local, full: Bool) -> ConfigShare.ExportRequest {
            ConfigShare.ExportRequest(local: l, direct: true, proxies: l.proxies.map(\.id), egress: l.egress.map(\.id),
                                      cisco: true, general: true, full_links: full, app_version: "0.6.0", date: "2026-11-28")
        }
        let vaultReadsBefore = vaultReads
        guard let hidden = ConfigShare.export(request(local, full: false)) else { check("export answers", false); exit(1) }
        check("export without full links reads no keychain", vaultReads == vaultReadsBefore)
        check("hidden export has no address, account or password",
              !["198.51.100.9", "alice", "p@ss", "s3cret", "ob fs", "\"proxy.example.net"].contains { hidden.text.contains($0) })
        check("hidden export keeps every rule and exception",
              ["example.com", "203.0.113.0/24", "full:login.example.com", "full:api.example.net", "geosite:github",
               "198.51.100.0/24", "full:static.example.org", "shop.example.com", "full:cdn.shop.example.com"]
                .allSatisfy { hidden.text.contains("\"\($0)\"") })
        check("hidden export has placeholders and says so", hidden.to_fill == 2 && !hidden.contains_secrets
              && hidden.text.contains("{host}") && hidden.text.contains("contains_secrets = false"))
        check("Cisco servers and group are exported as they are",
              hidden.text.contains("vpn-a.example.com") && hidden.text.contains("group = \"Staff\""))

        let full = ConfigShare.export(request(ConfigShare.local(secrets: true), full: true))!
        check("full export carries the links and says so", full.contains_secrets
              && full.text.contains("socks5://alice:p%40ss%20word@198.51.100.9:1080")
              && full.text.contains("hysteria2://s3cret%2F%2B@proxy.example.net:443,20000-30000/")
              && full.text.contains("obfs-password=ob%20fs") && full.text.contains("本文件含代理的完整链接"))
        if case .link(let l) = ProxyLink.parse("socks5://alice:p%40ss%20word@198.51.100.9:1080") {
            check("the exported SOCKS5 link reads back in the proxy editor", l.username == "alice" && l.password == "p@ss word")
        } else { check("the exported SOCKS5 link reads back in the proxy editor", false) }
        let fullHy = full.text.split(separator: "\n").first { $0.contains("hysteria2://") }
            .map { String($0.dropFirst("link = \"".count).dropLast()) } ?? ""
        if case .link(let l) = ProxyLink.parse(fullHy) {
            check("the exported Hysteria2 link reads back in the proxy editor",
                  l.password == "s3cret/+" && l.obfsPassword == "ob fs" && l.ports == "443,20000-30000" && l.sni == "proxy.example.net")
        } else { check("the exported Hysteria2 link reads back in the proxy editor", false) }

        // MARK: The recipient: some rules of their own, a proxy with the same name, protection off
        wipe()
        vault = [:]
        var mine = Profile()
        mine.servers = [ServerEntry(name: "VPN-A", address: "vpn-a.example.com", ciscoName: "VPN-A")]
        mine.server = "VPN-A"
        ProfileStore.saveProfile(mine)
        var own = AppSettings()
        own.directSites = [DirectSite(name: "example.com", domains: ["example.com"]),
                           DirectSite(name: "own.example.org", domains: ["own.example.org"])]
        own.proxyRoutes = [ProxyRoute(name: "示例 SOCKS5", kind: .http, host: "198.51.100.77", port: 8080, sites: ["own.example.net"])]
        own.autoLAN = false
        ProfileStore.saveAppSettings(own)
        let ownEgress = EgressProtection()
        let beforeSettings = ProfileStore.loadAppSettings()
        let beforeProfile = ProfileStore.loadProfile()

        guard let preview = ConfigShare.preview(hidden.text), preview.ok else { check("preview reads the file", false); exit(1) }
        check("preview: rules this Mac has are marked", preview.direct?.rules.first { $0.text == "example.com" }?.new == false
              && preview.direct?.added_rules == 1 && preview.direct?.added_exceptions == 1)
        check("preview: the same-named proxy is renamed", preview.proxies.first?.import_name == "示例 SOCKS5（导入）")
        check("preview: the link box hint is in words", preview.proxies.first?.hint == "socks5://用户名:密码@地址:1080")
        check("preview: only differing switches are offered", preview.general.map(\.key) == ["auto_lan"])
        check("preview: a link with placeholders is refused",
              ConfigShare.parseLink("socks5://{host}:1080")?.problem != nil && ConfigShare.parseLink("  ") == nil)

        HelperClient.shared.calls = []
        var choices = ConfigShare.Choices(direct: true, proxies: true, egress: true, cisco: true, general: true)
        choices.links = [0: "socks5://bob:pw@198.51.100.30:1080", 1: ""]
        let outcome = wait { done in ConfigShare.importNow(hidden.text, choices: choices, completion: done) }
        let after = ProfileStore.loadAppSettings()
        let afterProfile = ProfileStore.loadProfile()
        check("import keeps every rule this Mac had, then adds", (after.directSites ?? []).prefix(2).map(\.name) == ["example.com", "own.example.org"]
              && (after.directSites ?? []).map(\.name).contains("203.0.113.0/24") && after.directExceptions == ["full:login.example.com"])
        let routes = after.proxyRoutes ?? []
        check("import keeps this Mac's proxy first and untouched", routes.first == own.proxyRoutes?.first)
        let linked = routes.first { $0.name == "示例 SOCKS5（导入）" }
        check("a pasted link makes a working proxy with its rules", linked?.enabled == true && linked?.host == "198.51.100.30"
              && linked?.username == "bob" && linked?.sites == ["full:api.example.net", "geosite:github"])
        check("its password went to the keychain, not the settings", linked.map { vault["proxy@\($0.keychainServer)"] } == "pw"
              && !String(decoding: try! JSONEncoder().encode(after), as: UTF8.self).contains("\"pw\""))
        let empty = routes.first { $0.name == "示例 Hysteria2" }
        check("a proxy left empty stays off with its rules", empty?.enabled == false && empty?.host == ""
              && empty?.kind == .hysteria2 && empty?.exceptions == ["full:static.example.org"])
        check("an empty proxy shows that its link is missing", empty?.rowSubtitle.contains("还没填链接") == true)
        let groups = after.egressProtection?.groups ?? []
        check("exit protection is added switched off", groups.count == 1 && groups[0].enabled == false
              && groups[0].sites == ["shop.example.com"] && groups[0].expect == ["US"])
        check("Cisco: the missing server is added, the selection kept, the group filled",
              afterProfile.servers.map(\.name) == ["VPN-A", "VPN-B"] && afterProfile.server == "VPN-A" && afterProfile.group == "Staff"
              && afterProfile.servers[0].id == mine.servers[0].id)
        check("the ticked switch changed", after.autoLAN == true)
        let calls = HelperClient.shared.calls
        check("the service was told as the pages tell it", calls.contains("pushNetworks") && calls.contains("pushDirectDomains")
              && calls.contains("saveEgress") && !calls.contains("dropProtectionChanged"))
        check("the result line counts what was added", outcome.line.contains("已导入") && outcome.line.contains("1 条直连规则")
              && outcome.line.contains("2 个代理（1 个待填链接）") && outcome.line.contains("1 条出口保护（已暂停）"))

        // Importing the same file again adds no rules.
        let again = wait { done in
            ConfigShare.importNow(hidden.text, choices: ConfigShare.Choices(direct: true, proxies: false, egress: false, cisco: true),
                                  completion: done)
        }
        check("a second import adds no rule or server", ProfileStore.loadAppSettings().directSites == after.directSites
              && ProfileStore.loadProfile().servers == afterProfile.servers && again.line.contains("没有可以加的"))

        // MARK: Undo
        let undone = wait { done in ConfigShare.undo(outcome.undo!, completion: done) }
        let back = ProfileStore.loadAppSettings()
        check("undo puts the settings back", undone && back.directSites == beforeSettings.directSites
              && back.directExceptions == beforeSettings.directExceptions && back.proxyRoutes == beforeSettings.proxyRoutes
              && back.autoLAN == false && (back.egressProtection ?? EgressProtection()) == ownEgress)
        check("undo puts the Cisco servers back", ProfileStore.loadProfile() == beforeProfile)
        check("undo removes the passwords it wrote", vault.isEmpty)

        // MARK: The service refuses the exit protection save
        HelperClient.shared.refuseEgress = true
        let refused = wait { done in ConfigShare.importNow(hidden.text, choices: choices, completion: done) }
        check("a refused exit protection is reported, the rest imported",
              refused.line.contains("出口保护没有导入") && (ProfileStore.loadAppSettings().proxyRoutes ?? []).count == 3
              && (ProfileStore.loadAppSettings().egressProtection?.groups ?? []).isEmpty)
        HelperClient.shared.refuseEgress = false

        // MARK: Turning drop protection off with the switches also turns exit protection off
        wipe()
        var guarded = AppSettings()
        guarded.dropProtection = true
        ProfileStore.saveAppSettings(guarded)
        var on = EgressProtection()
        on.enabled = true
        guarded = ProfileStore.loadAppSettings()
        guarded.egressProtection = on
        ProfileStore.saveAppSettings(guarded, updatingEgress: true)
        let offFile = hidden.text.replacingOccurrences(of: "drop_protection = true", with: "drop_protection = false")
        HelperClient.shared.calls = []
        _ = wait { done in
            ConfigShare.importNow(offFile, choices: ConfigShare.Choices(direct: false, proxies: false, egress: false, cisco: false,
                                                                        general: true), completion: done)
        }
        let dropped = ProfileStore.loadAppSettings()
        check("drop protection off also turns exit protection off, and the service is told",
              dropped.dropProtection == false && dropped.egressProtection?.enabled == false
              && HelperClient.shared.calls.contains("dropProtectionChanged"))

        // MARK: The old exit protection backup
        let backup = String(decoding: try! JSONEncoder().encode(egress), as: UTF8.self)
        let old = ConfigShare.preview(backup)
        check("the old exit protection backup is read", old?.ok == true && old?.legacy_egress == true && old?.egress.count == 1)

        wipe()
        print(fails == 0 ? "config-share: all passed" : "config-share: \(fails) failed")
        exit(fails == 0 ? 0 : 1)
    }

    static var vaultReads: Int { vaultReadCount }
}

/// Counts keychain reads through the stand-in (set up in main).
var vaultReadCount = 0
