import AppKit
import SwiftUI

private final class Fixture: ObservableObject {
    @Published var rows = (1...180).map(Fixture.row)

    static func row(_ index: Int) -> ConnectionRow {
        ConnectionRow(process: "Example Browser", pid: 1, proto: "udp",
                      remote: "192.0.2.\(index)", port: index.isMultiple(of: 2) ? 443 : 3478,
                      host: "site-\(index).example.com", via: "vpn", interface: "utun0", reason: "VPN")
    }
}

private struct FixtureSettings: View {
    @ObservedObject var fixture: Fixture
    let defaults: UserDefaults

    var body: some View {
        SettingsView(connectionPreview: fixture.rows)
            .defaultAppStorage(defaults)
    }
}

@main
struct ConnectionsUITest {
    @MainActor static func main() {
        _ = NSApplication.shared
        if let marker = ProcessInfo.processInfo.environment["AC_PROXY_HEALTH_MARKER"] {
            checkProxyProcesses(marker: URL(fileURLWithPath: marker))
            return
        }
        let first = ProxyRoute(name: "A", kind: .hysteria2, host: "192.0.2.1", port: 443, sites: [])
        let second = ProxyRoute(name: "B", kind: .socks5, host: "192.0.2.2", port: 1080, sites: [])
        let health = ProxyHealth()
        health.preview([first.id: ProxyCheck(level: .ok, text: "OK", millis: 80, at: Date()),
                        second.id: ProxyCheck(level: .fail, text: "timeout", at: Date())])
        let mixed = health.summary([first, second])
        check(mixed.text == "1 个正常 · 1 个连不上" && mixed.level == .warn, "mixed proxy availability shows both outcomes")
        check(health.summary([first]).text == "正常 · 80 ms", "single proxy retains its latency")
        checkEgressEditing()
        checkTextTrim()
        if let output = ProcessInfo.processInfo.environment["AC_EGRESS_RENDER_DIR"] { renderEgress(to: output) }
        // Use the real settings process' snapshot entry. A late engine state
        // can still say connected while the menu App reports a trust failure.
        let manager = HelperClient.shared
        manager.applyRemoteSnapshot(#"{"state":0,"preparingEngine":true,"ownConnection":true}"#)
        check(manager.panelConnectionState == .connecting && manager.switchIsOn && !manager.showsConnected,
              "accepted login shows preparation before the engine pushes state")
        manager.applyRemoteSnapshot(#"{"state":5,"detail":"tunnel negotiation accepted","ownConnection":true}"#)
        let progressing = PanelStatusHeader(client: manager, subtitle: "重试")
        check(progressing.look.headline == "正在连接…" && progressing.subtitle.contains("隧道协商完成"),
              "negotiated reconnect shows setup progress before confirmed connection")
        manager.applyRemoteSnapshot(#"{"state":4,"gatewayTrustFailed":true,"rejectedLoginHeld":true,"ownConnection":true}"#)
        let failed = PanelStatusHeader(client: manager, subtitle: "已连接")
        let menu = NSButton()
        StatusLook.updateMenuButton(menu, client: manager)
        check(!manager.showsConnected && manager.stateLine == "Cisco 网关证书校验失败", "settings copy replaces the old success state")
        check(failed.look.headline == manager.stateLine && failed.badge == .alert
              && !failed.subtitle.contains("已连接") && menu.toolTip?.contains(manager.stateLine) == true,
              "menu, tooltip, panel and settings agree on certificate rejection")
        manager.applyRemoteSnapshot(#"{"state":4,"gatewayTrustFailed":false,"ownConnection":true}"#)
        check(manager.showsConnected && PanelStatusHeader(client: manager, subtitle: "").badge == .lock, "healthy settings snapshot restores the lock")
        manager.applyRemoteSnapshot(#"{"state":0}"#)
        CiscoEngine.cliPath = "/nonexistent/connections-ui-test/vpn"
        let defaults = UserDefaults(suiteName: AppGroups.suiteName)!
        defaults.set("connections", forKey: "settingsTab")
        defer { defaults.removeObject(forKey: "settingsTab") }
        let fixture = Fixture()
        let controller = NSHostingController(rootView: FixtureSettings(fixture: fixture, defaults: defaults))
        let window = NSWindow(contentRect: NSRect(origin: .zero, size: SettingsWindow.size),
                              styleMask: [.titled, .resizable], backing: .buffered, defer: false)
        window.isReleasedWhenClosed = false
        window.contentViewController = controller
        window.setContentSize(SettingsWindow.size)
        let root = controller.view

        func settle() {
            root.layoutSubtreeIfNeeded()
            RunLoop.main.run(until: Date(timeIntervalSinceNow: 0.07))
            root.layoutSubtreeIfNeeded()
        }

        settle()
        guard let table = findTable(in: root), let scroll = table.enclosingScrollView else {
            fail("the connection tab did not create a native scrollable table")
        }
        // The list was the 连接 tab before it became 流量 (§69.14).
        check(defaults.string(forKey: "settingsTab") == "traffic", "an old link to the connection list opens 流量")
        check(SettingsPages.all.map(\.title) == ["通用", "账号", "连接", "分流", "出口保护", "流量", "诊断"]
              && SettingsPages.resolve("proxy") == "split" && SettingsPages.resolve("nonsense") == "general",
              "seven pages in order; 分流代理 opens 分流; an unknown name opens 通用")
        check(table.numberOfRows == 180, "180 sample connections reach the table")
        table.selectRowIndexes(IndexSet([0, 1]), byExtendingSelection: false)
        check(table.allowsMultipleSelection && table.selectedRowIndexes == IndexSet([0, 1]), "connection table selects multiple rows")
        check(table.tableColumns.count == 6, "all six columns exist")
        let protocolFont = NSFont.systemFont(ofSize: NSFont.systemFontSize)
        for port in [443, 3478] {
            let label = ConnectionsPage.protocolName("udp", port)
            let width = (label as NSString).size(withAttributes: [.font: protocolFont]).width
            check(table.tableColumns[2].width >= width, "the protocol column fits \(label)")
        }

        func visible(_ row: Int) -> Bool {
            let rowBounds = table.rect(ofRow: row)
            let viewport = scroll.documentVisibleRect
            return rowBounds.minY >= viewport.minY && rowBounds.maxY <= viewport.maxY
        }

        func wheel(_ lines: Int32) {
            let clip = scroll.contentView
            let point = clip.convert(NSPoint(x: clip.bounds.midX, y: clip.bounds.midY), to: root)
            guard let hit = root.hitTest(root.convert(point, to: root.superview)),
                  hit === scroll || hit.isDescendant(of: scroll),
                  let raw = CGEvent(scrollWheelEvent2Source: nil, units: .line,
                                    wheelCount: 1, wheel1: lines, wheel2: 0, wheel3: 0),
                  let event = NSEvent(cgEvent: raw) else {
                fail("wheel hit testing did not reach the table")
            }
            hit.scrollWheel(with: event)
            settle()
        }

        let defaultViewport = scroll.contentView.bounds.size
        let scopes = DirectSites.choices(host: "a.edge.example.com", address: "192.0.2.9").map(\.rule)
        check(scopes == ["example.com", "edge.example.com", "full:a.edge.example.com", "192.0.2.9/32"],
              "both lists offer the site, its subdomains, the name alone and the address")
        check(table.rect(ofColumn: 5).maxX <= scroll.documentVisibleRect.maxX,
              "all columns fit at the default window size")
        for size in [SettingsWindow.size, SettingsWindow.minimumSize] {
            window.setContentSize(size)
            settle()
            check(visible(0) && !visible(table.numberOfRows - 1), "the list starts at the top and overflows")
            wheel(-16)
            check(!visible(0), "scrolling down moves the table, not the settings page")
            let offset = scroll.contentView.bounds.minY
            for _ in 0..<3 {
                let count = fixture.rows.count
                fixture.rows.append(Fixture.row(count + 1))
                let deadline = Date(timeIntervalSinceNow: 2)
                repeat { settle() } while table.numberOfRows != count + 1 && Date() < deadline
                check(table.numberOfRows == count + 1, "a new sample reaches the same table")
                check(abs(scroll.contentView.bounds.minY - offset) <= 1, "refresh keeps the scroll position")
            }
            for _ in 0..<40 where !visible(table.numberOfRows - 1) { wheel(-32) }
            check(visible(table.numberOfRows - 1), "scrolling reaches the final row")
            for _ in 0..<40 where !visible(0) { wheel(32) }
            check(visible(0), "scrolling back up reaches the first row")
        }
        check(scroll.contentView.bounds.width < defaultViewport.width &&
              scroll.contentView.bounds.height < defaultViewport.height, "the table resizes with the settings window")
        check(scroll.enclosingScrollView == nil, "no enclosing form scrolls around the table")
        var direct = Fixture.row(1)
        direct.via = "direct"
        fixture.rows = [direct, Fixture.row(2)]
        settle()
        check(table.numberOfRows == 2, "ordinary Connections entry shows all routes")
        SettingsWindow.shared.vpnConnectionsRequested = true
        settle()
        check(table.numberOfRows == 1 && !SettingsWindow.shared.vpnConnectionsRequested,
              "the empty-state shortcut shows VPN connections and is consumed once")
        defaults.set("general", forKey: "settingsTab")
        settle()
        check(findTable(in: root) == nil, "a hidden page leaves the settings window")
        defaults.set("traffic", forKey: "settingsTab")
        settle()
        check(findTable(in: root) === table && table.numberOfRows == 1,
              "returning to a tab retains its view and current filter")
        // Proxied connections (§69.12): their own way, by proxy, before VPN.
        var proxied = Fixture.row(3)
        proxied.via = "proxy"; proxied.reason = "分流代理"; proxied.proxy = 0
        let grouped = ConnectionsPage.group([Fixture.row(2), proxied, proxied])
        check(grouped.first?.via == "proxy" && grouped.first?.proxy == 0 && grouped.first?.count == 2
              && ConnectionsPage.wayName("proxy") == "代理" && ConnectionsPage.Filter.allCases.map(\.rawValue).contains("走代理"),
              "proxied connections group by proxy and show as 代理")
        print("PASS connection table scrolls both ways, tracks resizing and keeps position across row updates")
        print("PASS tab navigation hides detached pages and keeps their view state")
    }

    private static func checkEgressEditing() {
        let initial = EgressProtection(enabled: false, groups: [
            .init(id: 1, name: "Retained", enabled: true, sites: ["retained.example.com"], expect: ["ZZ"])
        ])
        let bytes = try! JSONEncoder().encode(initial)
        check(!initial.rulesForEditing.groups[0].enabled
              && (try! JSONDecoder().decode(EgressProtection.self, from: bytes)).groups[0].enabled,
              "old disabled master switch remains disabled and viewing doesn't mutate stored bytes")
        // One parser for both lists (§66.30): the split list's syntax, no Clash lines.
        let input = EgressRuleInput("""
        example.org
        full:exact.test
        keyword:fixture
        domain:example.org
        DOMAIN-SUFFIX,example.org,Office
        PROCESS-NAME,example
        regexp:(
        geosite:nosuchlist
        """.replacingOccurrences(of: "\n", with: "\r\n"))
        check(input.sites == ["example.org", "full:exact.test", "keyword:fixture"]
              && input.issues.map(\.id) == [6, 7, 8] && input.issues[1].message == "正则表达式写得不对"
              && input.issues[2].message == "没有叫这个名字的网站清单",
              "rule lines parse like the split list, pasted Clash lines normalize, CRLF line numbers and reasons")
        check(EgressRuleInput(input.sites.joined(separator: "\n")).sites == input.sites
              && EgressRuleInput("regexp:^node[0-9]{1,3}[.]example$").sites == ["regexp:^node[0-9]{1,3}[.]example$"],
              "stored rules read back unchanged")
        func add(_ text: String, _ countries: [String], _ policy: EgressProtection.Unverified,
                 to config: EgressProtection) -> EgressRuleChange? {
            EgressRuleChange.adding(EgressRuleInput(text), countries: countries, unverified: policy, config: config)
        }
        guard let first = add(input.sites.joined(separator: "\n"), ["ZZ"], .block, to: initial),
              let second = add("192.0.2.0/24\ngeoip:cn", ["ZZ"], .block, to: first.after),
              let third = add("geosite:test\n198.51.100.2", ["ZZ"], .block, to: second.after) else {
            fail("create rules")
        }
        let added = EgressRuleChange(before: initial, after: third.after)
        check(added.after.enabled && !added.after.groups[0].enabled && added.after.groups.count == 4
              && added.after.groups[1].name == "example.org" && added.after.groups[1].expect == ["ZZ"]
              && added.after.groups[1].unverified == .block, "a new rule arms with the selected policy")
        check(added.needsReconnect(connected: true) && !added.needsReconnect(connected: false)
              && added.undo.after == initial, "first rule requires a live reconnect and undo restores the original snapshot")
        check(EgressRuleChange.adding(EgressRuleInput(""), countries: ["ZZ"], unverified: .allow, config: initial) == nil
              && EgressRuleChange.adding(input, countries: [], unverified: .allow, config: initial) == nil,
              "a new rule needs a site and a country")
        let network = EgressProtection.Target(host: nil, address: "192.0.2.10")
        let name = EgressProtection.Target(host: "chat.example.org", address: "192.0.2.10")
        let mismatch = EgressProtection.Target(host: "badexample.org", address: "198.51.100.9")
        let listed = EgressProtection.Target(host: "test.example.com", address: "198.51.100.9")
        let matched = added.after.rules(covering: [network, name, mismatch, listed])
        check(matched[network] == added.after.groups[2].id && matched[name] == added.after.groups[1].id
              && matched[mismatch] == nil && matched[listed] == added.after.groups[3].id,
              "the connections page uses the Rust matcher, with names before ranges")
        check(added.after.groups.allSatisfy { $0.matches == nil }
              && added.after.forBackgroundService.groups[2].matches?.contains(where: { $0.hasPrefix("ipcidr:") }) == true,
              "expansion stays out of the settings model")
        let copied = EgressRuleInput.text(of: added.after)
        check(copied.hasPrefix("# Retained\nretained.example.com\n\n# example.org\nexample.org\n")
              && EgressRuleInput(copied).issues.isEmpty,
              "copied rules are one block per protection and read back without errors")
        // The detail's whole-list edit (§66.29) in the shared syntax (§66.30).
        let old = Data(#"{"enabled":true,"groups":[{"id":7,"name":"Fixture","enabled":true,"expect":["ZZ"],"members":[{"pattern":"*.legacy.example"},{"pattern":"archive.example"}]}]}"#.utf8)
        let legacy = try! JSONDecoder().decode(EgressProtection.self, from: old)
        let original = legacy.groups[0].sites
        check(original.joined(separator: "\n") == "legacy.example\narchive.example",
              "opening an older rule prefills the original entries in order")
        let changed = EgressRuleInput("""
        DOMAIN,EXACT.EXAMPLE.,Ignored group
        192.0.2.4
        domain:legacy.example
        full:exact.example
        """)
        let expected = ["full:exact.example", "192.0.2.4/32", "legacy.example"]
        let originalRules = EgressRuleChange.Rules(legacy.groups[0])
        let excluded = EgressRuleInput(TextTrim.ruleLines("  full:login.legacy.example \n  geosite:test@!cn  "))
        guard let sites = changed.replacementSites,
              let replacement = EgressRuleChange.replacingRules(.init(sites: sites, exceptions: excluded.sites),
                                                                expected: originalRules, group: 7, in: legacy)
        else { fail("make a complete rule replacement") }
        var expectedSettings = legacy
        expectedSettings.groups[0].sites = expected
        expectedSettings.groups[0].exceptions = ["full:login.legacy.example", "geosite:test@!cn"]
        check(replacement.before == legacy && replacement.after == expectedSettings && !replacement.needsReconnect(connected: true),
              "completion deletes omitted entries, normalizes edits and preserves all other settings")
        let update = EgressConfigUpdate(config: replacement.after, previous: replacement.before)
        let reopened = try! JSONDecoder().decode(EgressConfigUpdate.self, from: JSONEncoder().encode(update)).config
        check(EgressRuleInput(reopened.groups[0].sites.joined(separator: "\n")).replacementSites == expected,
              "reopening shows the saved normalized list")
        let invalid = EgressRuleInput("full:valid.example\nPROCESS-NAME,Fixture\n192.0.2.0/33")
        let tooMany = EgressRuleInput((0...EgressRuleInput.siteLimit).map { "example-\($0).test" }.joined(separator: "\n"))
        check(invalid.issues.map(\.id) == [2, 3] && invalid.replacementSites == nil
              && EgressRuleInput("# comment only").replacementSites == nil && tooMany.replacementSites == nil,
              "invalid, empty or oversized drafts do not produce a save payload")
        check(EgressRuleChange.Rules(reopened.groups[0]).exceptions == expectedSettings.groups[0].exceptions
              && originalRules.exceptions.isEmpty, "old rules decode and edited exceptions survive JSON")
        check(EgressRuleChange.replacingRules(.init(sites: sites), expected: originalRules, group: 7, in: reopened) == nil,
              "a stale editor cannot overwrite a rule already changed elsewhere")
        let mixed = ["legacy.example", "full:exact.example", "keyword:fixture", "regexp:^node[0-9]{1,3}[.]example$",
                     "geosite:test", "geoip:cn", "192.0.2.0/24"]
        check(EgressRuleInput(mixed.joined(separator: "\n")).replacementSites == mixed,
              "all existing rule types retain their meaning when reopened")
        print("PASS exit rule detail normalizes a complete edit and rejects an invalid or stale draft")
        print("PASS rule lines parse, expand and copy like the split list")
    }

    private static func checkTextTrim() {
        check(TextTrim.singleLine("  socks5://127.0.0.1:1080 \n") == "socks5://127.0.0.1:1080",
              "singleLine trims outer spaces and trailing newline")
        check(TextTrim.singleLine("  foo\r\nbar  ") == "foo bar",
              "singleLine collapses embedded CRLF")
        check(TextTrim.liveSingleLine(old: "", new: "   ") == "",
              "liveSingleLine strips accidental leading whitespace on empty field")
        check(TextTrim.liveSingleLine(old: "my", new: "my ") == "my ",
              "liveSingleLine keeps a single space while typing")
        check(TextTrim.liveSingleLine(old: "", new: "  socks5://198.51.100.1:1080  ") == "socks5://198.51.100.1:1080",
              "liveSingleLine trims pasted proxy address immediately")
        check(TextTrim.liveSingleLine(old: "a", new: "a\nb") == "a b",
              "liveSingleLine flattens pasted newline")
        check(TextTrim.ruleLines("\n  example.com  \r\n\tfull:exact.example  \n\n") == "example.com\nfull:exact.example",
              "ruleLines trims each line and outer blank lines")
        check(TextTrim.liveRuleLines(old: "example.com", new: "example.com\n") == "example.com\n",
              "liveRuleLines keeps a single Enter key while typing")
        check(TextTrim.liveRuleLines(old: "", new: "  example.com \n  example.org  \n") == "example.com\nexample.org",
              "liveRuleLines cleans pasted multi-line rules immediately")
        print("PASS input auto-trim cleans paste and blur without fighting normal typing")
    }

    @MainActor private static func renderEgress(to output: String) {
        let sample = [Fixture.row(1), Fixture.row(2)]
        let now = Date().timeIntervalSince1970
        let proxyRoutes = [
            ProxyRoute(name: "示例节点 A", kind: .hysteria2, host: "198.51.100.10", port: 443,
                       sites: ["example.test", "full:exact.test"]),
            ProxyRoute(name: "备用代理", kind: .socks5, host: "198.51.100.20", port: 1080,
                       sites: ["work.example.org"]),
        ]
        let group1 = EgressProtection.Group(id: 7, name: "示例保护", enabled: true,
            sites: ["example.test", "full:exact.test", "192.0.2.0/24"], expect: ["ZZ"], unverified: .block)
        let group2 = EgressProtection.Group(id: 8, name: "第二条保护", enabled: true,
            sites: ["work.example.org", "geosite:test"], expect: ["ZZ"], unverified: .whenWrong)
        let group3 = EgressProtection.Group(id: 9, name: "本地出口核查", enabled: true,
            sites: ["direct-check.example"], expect: ["YY"], unverified: .whenWrong)
        let config = EgressProtection(enabled: true, groups: [group1, group2, group3])
        let obs1 = EgressProtection.Observation(host: "example.test", country: "ZZ", ip: "198.51.100.50",
            error: nil, peerAddress: nil, path: "proxy:0")
        let obs2 = EgressProtection.Observation(host: "work.example.org", country: "YY", ip: "203.0.113.44",
            error: nil, peerAddress: nil, path: "proxy:1")
        let obs3 = EgressProtection.Observation(host: "direct-check.example", country: "YY", ip: "203.0.113.12",
            error: nil, peerAddress: "203.0.113.99", path: "local")
        let gs1 = EgressProtection.GroupState(
            id: 7, name: group1.name, state: "ok", lastCheck: now - 45, observed: [obs1],
            blockedCount: 0, lastBlockedHost: nil, lastBlockedCountry: nil, path: "proxy:0",
            paths: [
                EgressProtection.PathState(path: "proxy:0", state: "ok", lastCheck: now - 45,
                                           country: "ZZ", ip: "198.51.100.50", error: nil, blockedCount: 0),
                EgressProtection.PathState(path: "cisco", state: "ok", lastCheck: now - 300,
                                           country: "ZZ", ip: "198.51.100.51", error: nil, blockedCount: 0),
            ])
        let gs2 = EgressProtection.GroupState(
            id: 8, name: group2.name, state: "blocked", lastCheck: now - 15, observed: [obs2],
            blockedCount: 3, lastBlockedHost: "work.example.org", lastBlockedCountry: "YY", path: "proxy:1",
            paths: [
                EgressProtection.PathState(path: "proxy:1", state: "blocked", lastCheck: now - 15,
                                           country: "YY", ip: "203.0.113.44", error: nil, blockedCount: 3),
            ])
        let gs3 = EgressProtection.GroupState(
            id: 9, name: group3.name, state: "ok", lastCheck: now - 80, observed: [obs3],
            blockedCount: 0, lastBlockedHost: nil, lastBlockedCountry: nil, path: "local",
            paths: [
                EgressProtection.PathState(path: "local", state: "ok", lastCheck: now - 80,
                                           country: "YY", ip: "203.0.113.12", error: nil, blockedCount: 0),
            ])
        let rec1 = EgressProtection.BlockRecord(
            started: now - 15, ended: nil, group: 8, name: group2.name, host: "work.example.org",
            observed: [obs2], expected: ["ZZ"], path: "proxy:1")
        let status = EgressProtection.Status(running: true, checking: [], groups: [gs1, gs2, gs3], records: [rec1])
        let render: (String, CGFloat, CGFloat, AnyView) -> Void = { name, width, height, view in
            let bounds = NSRect(x: 0, y: 0, width: width, height: height)
            let host = NSHostingView(rootView: view.background(Color(nsColor: .windowBackgroundColor)))
            let window = NSWindow(contentRect: bounds, styleMask: [.titled], backing: .buffered, defer: false)
            window.isReleasedWhenClosed = false
            window.appearance = NSAppearance(named: .aqua)
            window.contentView = host
            host.frame = bounds
            host.layoutSubtreeIfNeeded()
            RunLoop.main.run(until: Date(timeIntervalSinceNow: 0.15))
            host.layoutSubtreeIfNeeded()
            host.displayIfNeeded()
            guard let image = host.bitmapImageRepForCachingDisplay(in: bounds) else { fail("prepare offscreen view") }
            host.cacheDisplay(in: bounds, to: image)
            guard let png = image.representation(using: .png, properties: [:]) else { fail("encode offscreen view") }
            window.close()
            let path = URL(fileURLWithPath: output).appendingPathComponent(name + ".png")
            do { try png.write(to: path) } catch { fail("write offscreen view") }
        }
        render("egress-add", 600, 660, AnyView(EgressSiteSheet(sites: group1.sites, countries: ["ZZ"], preview: sample) { _, _, _, _, _ in }))
        render("egress-detail", 600, 560, AnyView(EgressRuleDetail(rule: group1, config: config, status: status, connected: true,
            refresh: {}, edit: { _ in }, remove: {}, saveRules: { _, _, done in done(nil) })))
        render("egress-page", 760, 860, AnyView(EgressProtectionPage(preview: EgressPagePreview(
            config: config, status: status, connected: true, available: true, proxyRoutes: proxyRoutes))))
        render("proxy-editor", 520, 552, AnyView(ProxyEditor(
            route: proxyRoutes[0], isNew: false, previewSavesFirst: false,
            previewProtectedSites: ["example.test", "full:exact.test"],
            cancel: {}, done: { _ in })))
        render("split-direct", 760, 730, AnyView(SplitPage(preview: SplitPagePreview(
            sites: [DirectSite(name: "example.test", domains: ["example.test"])],
            directExceptions: ["full:login.example.test"]), section: .constant("direct"))))
        render("rule-exceptions-expanded", 520, 240, AnyView(Form {
            Section {
                EgressRuleExceptions(input: .constant("full:login.example.test"),
                    parsed: EgressRuleInput("full:login.example.test"),
                    explanation: "命中例外的网站跳过这个代理，继续匹配后面的规则。",
                    footer: { EmptyView() }, expanded: true)
            }
        }.formStyle(.grouped)))
        // Panel A (proxy-only, Cisco off, exit protection active)
        let previewClient = HelperClient.shared
        previewClient.applyRemoteSnapshot(#"{"state":0,"proxyOnlyRunning":true,"egressLine":"正常","egressLevel":"ok"}"#)
        let oldSettings = ProfileStore.loadAppSettings()
        var panelSettings = oldSettings
        panelSettings.connectionMode = "own"
        panelSettings.dropProtection = true
        panelSettings.proxyRoutes = proxyRoutes
        panelSettings.egressProtection = config
        ProfileStore.saveAppSettings(panelSettings, updatingEgress: true)
        var previewProfile = Profile()
        previewProfile.server = "VPN-A"
        let totals = PanelSpeed.Totals(ready: true, total: [160_400, 17_800], vpn: [0, 0],
                                       direct: [18_400, 2_200], proxy: [142_000, 15_600])
        render("panel-proxy-only", 340, 470, AnyView(PanelView(
            manager: previewClient, profile: previewProfile, onStart: {}, onStop: {},
            preview: PanelPreview(speed: totals, link: .unknown))))
        ProfileStore.saveAppSettings(oldSettings, updatingEgress: true)
        previewClient.applyRemoteSnapshot(#"{"state":0}"#)
        print("PASS offscreen add, detail, page, proxy editor, split direct, expanded exceptions and panel views")
    }

    private static func findTable(in view: NSView) -> NSTableView? {
        if let table = view as? NSTableView { return table }
        return view.subviews.lazy.compactMap(findTable).first
    }

    // Run the production SettingsLink on both ends of its inherited socket.
    // The harness's suite is isolated and the test server is loopback only.
    @MainActor private static func checkProxyProcesses(marker: URL) {
        let health = ProxyHealth.shared
        let link = SettingsLink.shared
        let until = Date().addingTimeInterval(12)
        let progress = marker.appendingPathExtension("stage")
        func stage(_ text: String) { try? Data(text.utf8).write(to: progress, options: .atomic) }
        if AppRole.isSettings {
            stage("child started")
            guard let route = ProfileStore.loadAppSettings().activeProxyRoutes.first else { exit(2) }
            stage("read saved route")
            var requested = false
            link.startSettingsSide { stage("connected"); link.send("watchProxyHealth", "1") }
            while Date() < until {
                RunLoop.current.run(until: Date().addingTimeInterval(0.02))
                if !requested, health.checks[route.id]?.millis == 17 {
                    requested = true
                    stage("received initial status")
                    health.check([route], force: true)
                } else if requested, health.checks[route.id]?.level == .fail {
                    try! Data("mirrored".utf8).write(to: marker, options: .atomic)
                    exit(0)
                }
            }
            exit(3)
        }
        var settings = AppSettings()
        let route = ProxyRoute(name: "Loopback", kind: .socks5, host: "127.0.0.1", port: 0, sites: ["example.test"])
        settings.proxyRoutes = [route]
        ProfileStore.saveAppSettings(settings)
        UserDefaults(suiteName: AppGroups.suiteName)?.synchronize()
        defer { UserDefaults.standard.removePersistentDomain(forName: AppGroups.suiteName) }
        HelperClient.shared.applyRemoteSnapshot(#"{"state":4,"ownConnection":true}"#)
        health.configure([route])
        link.startAppSide()
        link.show(tab: nil)
        var seeded = false
        while Date() < until && !FileManager.default.fileExists(atPath: marker.path) {
            if !seeded, (try? String(contentsOf: progress)) == "connected" {
                seeded = true
                health.preview([route.id: ProxyCheck(level: .ok, text: "fixture", millis: 17, at: Date())])
            }
            RunLoop.current.run(until: Date().addingTimeInterval(0.02))
        }
        let step = (try? String(contentsOf: progress)) ?? "launch"
        check(FileManager.default.fileExists(atPath: marker.path) && health.checks[route.id]?.level == .fail,
              "settings receives the menu result, requests a saved proxy check there and receives the failure (\(step))")
    }

    private static func check(_ condition: @autoclosure () -> Bool, _ message: String) {
        if !condition() { fail(message) }
    }

    private static func fail(_ message: String) -> Never {
        fputs("FAIL: \(message)\n", stderr)
        exit(1)
    }
}
