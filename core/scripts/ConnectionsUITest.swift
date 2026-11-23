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
            .init(id: 1, name: "Retained", enabled: true,
                  members: [.init(pattern: "retained.example.com", method: "trace")], expect: ["ZZ"])
        ])
        let bytes = try! JSONEncoder().encode(initial)
        check(!initial.rulesForEditing.groups[0].enabled
              && (try! JSONDecoder().decode(EgressProtection.self, from: bytes)).groups[0].enabled,
              "old disabled master switch remains disabled and viewing doesn't mutate stored bytes")
        guard let site = EgressWebsiteScope("https://chat.example.com:8443/path?x=1", includesSubdomains: true),
              let another = EgressWebsiteScope("auth.example.com", includesSubdomains: true) else { fail("normalize a named website") }
        check(site.host == "chat.example.com" && site.website == "example.com",
              "the input shows the normalized whole-site scope")
        check(EgressWebsiteScope("https://198.51.100.7", includesSubdomains: true) == nil
              && EgressWebsiteScope.unique([site, another]).count == 1, "selection rejects IP-only rows and deduplicates websites")

        let data = Data(#"{"host":"chat.example.com","method":"trace","status":"ok","resolvedAddressCount":5,"probedAddressCount":5,"truncated":false,"coverageIncomplete":false,"results":[{"address":"198.51.100.1","method":"trace","status":"ok","country":"ZZ"},{"address":"198.51.100.2","method":"trace","status":"ok","country":"ZZ"},{"address":"198.51.100.3","method":"trace","status":"ok","country":"ZZ"},{"address":"198.51.100.4","method":"trace","status":"ok","country":"ZZ"},{"address":"198.51.100.5","method":"trace","status":"ok","country":"YY"}]}"#.utf8)
        let summary = try! JSONDecoder().decode(EgressProtection.SetupProbe.self, from: data)
        check(summary.suggestedCountry == "ZZ" && summary.caption.contains("4 个") && summary.caption.contains("1 个")
              && EgressProtection.SetupProbe.unavailable(site.host).suggestedCountry == nil, "only a uniquely supported country is suggested")
        let probes = [site.host: summary]
        let methods = verifiedMethods(probes, config: initial)
        guard let added = EgressWebsiteScope.adding([site], to: initial, rule: nil, newRuleID: 2,
            methods: methods, countries: [summary.suggestedCountry!]) else { fail("create a verified rule") }
        check(added.after.enabled && !added.after.groups[0].enabled && added.after.groups[1].expect == ["ZZ"]
              && added.after.groups[1].members.map(\.pattern) == ["example.com", "*.example.com"], "new rule arms only its confirmed scope")
        check(added.needsReconnect(connected: true) && !added.needsReconnect(connected: false)
              && added.undo.after == initial, "first rule requires a live reconnect and undo restores the original snapshot")
        let second = EgressWebsiteScope("static.fixture.example", includesSubdomains: true)!
        guard let batch = EgressWebsiteScope.adding([second], to: added.after, rule: 2, newRuleID: 3,
            methods: [:], countries: ["YY"], activateExisting: false) else { fail("add following websites to a verified rule") }
        check(!batch.needsReconnect(connected: true) && batch.after.groups[1].expect == ["ZZ"],
              "adding to an existing rule cannot silently widen countries or reconnect")
        let moved = EgressRuleChange.move(host: site.host, source: 2, target: 1, config: batch.after)
        check(moved?.patterns == ["example.com", "*.example.com"] && moved?.change.after.groups[0].enabled == false
              && moved?.change.undo.after == batch.after, "moving shows and transfers the scope while preserving destination settings")

        let history = EgressRecentVisits()
        let start = Date(timeIntervalSince1970: 100)
        func row(_ host: String?, _ process: String = "Example Browser", _ via: String = "vpn") -> ConnectionRow {
            .init(process: process, pid: 1, proto: "tcp", remote: "198.51.100.9", port: 443,
                  host: host, via: via, interface: "utun0", reason: "VPN")
        }
        history.record([row(site.host)], at: start)
        let source = history.visits
        history.record([row(site.host), row("related.test"), row("other.test", "Other App"),
                        row("direct.test", "Example Browser", "direct"), row(nil), row("listed.test")], at: start + 5)
        history.record([row("expired.test")], at: start + 20)
        let direct = [DirectSite(name: "Fixture", domains: ["listed.test"])]
        check(history.recommendations(for: source, config: added.after, direct: direct) == ["related.test"],
              "recommendations use the same process and time window with no protected, direct or unnamed rows")
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
