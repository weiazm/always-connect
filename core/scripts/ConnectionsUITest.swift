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

    var body: some View {
        SettingsView(connectionPreview: fixture.rows)
    }
}

@main
struct ConnectionsUITest {
    @MainActor static func main() {
        _ = NSApplication.shared
        checkEgressEditing()
        if let output = ProcessInfo.processInfo.environment["AC_EGRESS_RENDER_DIR"] { renderEgress(to: output) }
        // Use the real settings process' snapshot entry. A late engine state
        // can still say connected while the menu App reports a trust failure.
        let manager = HelperClient.shared
        manager.applyRemoteSnapshot(#"{"state":4,"gatewayTrustFailed":true,"rejectedLoginHeld":true,"ownConnection":true}"#)
        let failed = PanelStatusHeader(client: manager, subtitle: "已连接")
        let menu = NSButton()
        StatusLook.updateMenuButton(menu, client: manager)
        check(!manager.showsConnected && manager.stateLine == "VPN 网关证书校验失败", "settings copy replaces the old success state")
        check(failed.look.headline == manager.stateLine && failed.badge == .alert
              && !failed.subtitle.contains("已连接") && menu.toolTip?.contains(manager.stateLine) == true,
              "menu, tooltip, panel and settings agree on certificate rejection")
        manager.applyRemoteSnapshot(#"{"state":4,"gatewayTrustFailed":false,"ownConnection":true}"#)
        check(manager.showsConnected && PanelStatusHeader(client: manager, subtitle: "").badge == .lock, "healthy settings snapshot restores the lock")
        manager.applyRemoteSnapshot(#"{"state":0}"#)
        CiscoEngine.cliPath = "/nonexistent/connections-ui-test/vpn"
        let fixture = Fixture()
        let controller = NSHostingController(rootView: FixtureSettings(fixture: fixture))
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
        print("PASS connection table scrolls both ways, tracks resizing and keeps position across row updates")
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
        guard let sites = changed.replacementSites,
              let replacement = EgressRuleChange.replacingSites(sites, expected: original, group: 7, in: legacy)
        else { fail("make a complete rule replacement") }
        var expectedSettings = legacy
        expectedSettings.groups[0].sites = expected
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
        check(EgressRuleChange.replacingSites(sites, expected: original, group: 7, in: reopened) == nil,
              "a stale editor cannot overwrite a rule already changed elsewhere")
        let mixed = ["legacy.example", "full:exact.example", "keyword:fixture", "regexp:^node[0-9]{1,3}[.]example$",
                     "geosite:test", "geoip:cn", "192.0.2.0/24"]
        check(EgressRuleInput(mixed.joined(separator: "\n")).replacementSites == mixed,
              "all existing rule types retain their meaning when reopened")
        print("PASS exit rule detail normalizes a complete edit and rejects an invalid or stale draft")
        print("PASS rule lines parse, expand and copy like the split list")
    }

    @MainActor private static func renderEgress(to output: String) {
        let sample = [Fixture.row(1), Fixture.row(2)]
        let group = EgressProtection.Group(id: 7, name: "示例保护", enabled: true,
            sites: ["example.test", "full:exact.test", "192.0.2.0/24"], expect: ["ZZ"], unverified: .block)
        let config = EgressProtection(enabled: true, groups: [group])
        let render: (String, CGFloat, AnyView) -> Void = { name, height, view in
            let bounds = NSRect(x: 0, y: 0, width: 600, height: height)
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
        render("egress-add", 600, AnyView(EgressSiteSheet(sites: group.sites, countries: ["ZZ"], preview: sample) { _, _, _, _ in }))
        render("egress-detail", 560, AnyView(EgressRuleDetail(rule: group, config: config, status: nil, connected: true,
            refresh: {}, edit: { _ in }, remove: {}, saveSites: { _, _, done in done(nil) })))
        print("PASS offscreen add and detail views")
    }

    private static func findTable(in view: NSView) -> NSTableView? {
        if let table = view as? NSTableView { return table }
        return view.subviews.lazy.compactMap(findTable).first
    }

    private static func check(_ condition: @autoclosure () -> Bool, _ message: String) {
        if !condition() { fail(message) }
    }

    private static func fail(_ message: String) -> Never {
        fputs("FAIL: \(message)\n", stderr)
        exit(1)
    }
}
