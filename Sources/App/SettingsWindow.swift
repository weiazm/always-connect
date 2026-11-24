import AppKit
import SwiftUI

/// Owns the Settings window (UI-DESIGN.md §二主窗口).
///
/// Deliberately AppKit-managed, not a SwiftUI Settings scene: the
/// scene's programmatic openers (SettingsLink, openSettings) need
/// macOS 14, while this app targets macOS 13. The menu-bar panel is
/// the entry point (LSUIElement apps have no app menu), so the panel
/// entries call show() directly. The window and its SwiftUI pages are
/// released when it closes (§28.6: kept forever they held the App's
/// memory up all day); the next open builds them again.
///
/// In the menu-bar App, show() starts the settings process instead
/// (§32.15); the window itself only ever lives in that process, which
/// exits when it closes.
final class SettingsWindow: NSObject, NSWindowDelegate, ObservableObject {
    static let shared = SettingsWindow()
    static let size = NSSize(width: 1040, height: 640)
    static let minimumSize = NSSize(width: 900, height: 560)

    private var window: NSWindow?
    @Published var egressRuleToOpen: UInt32?
    @Published var vpnConnectionsRequested = false
    @Published var unknownEgressRequested = false

    func showVPNConnections() {
        vpnConnectionsRequested = true
        show(tab: "connections")
    }

    private override init() {}

    func windowWillClose(_ notification: Notification) {
        guard let closing = notification.object as? NSWindow, closing === window else { return }
        closing.delegate = nil
        // Let the close finish first, then drop the pages and the window.
        DispatchQueue.main.async { [weak self] in
            closing.contentViewController = nil
            if self?.window === closing { self?.window = nil }
            // The settings process has done its job: everything it used
            // goes back to the system with it. Never the quit path, which
            // would end the VPN.
            if AppRole.isSettings { exit(0) }
        }
    }

    /// A menu-bar (LSUIElement) app is not active when its status item
    /// is clicked, so a plain makeKeyAndOrderFront left the window
    /// behind whatever app was in front (user report, 2026-11-03):
    /// activate first, then bring the window up.
    func show(tab: String? = nil, egressRule: UInt32? = nil) {
        guard AppRole.isSettings else {
            SettingsLink.shared.show(tab: tab, egressRule: egressRule)
            return
        }
        let arguments = CommandLine.arguments
        let initialRule = window == nil
            ? arguments.firstIndex(of: "--egress-rule").flatMap { arguments.dropFirst($0 + 1).first }.flatMap(UInt32.init)
            : nil
        let focusUnknown = tab == "unknown-egress" || (window == nil && arguments.contains("--focus-unknown-egress"))
        if focusUnknown {
            egressRuleToOpen = nil
            unknownEgressRequested = true
        } else if let rule = egressRule ?? initialRule {
            unknownEgressRequested = false
            egressRuleToOpen = rule
        }
        let focusEgress = focusUnknown || tab == "egress" || egressRule != nil || initialRule != nil
            || (window == nil && arguments.contains("--focus-egress"))
        if focusEgress {
            UserDefaults.standard.set("egress", forKey: "settingsTab")
        } else if let tab {
            UserDefaults.standard.set(tab, forKey: "settingsTab")
        }
        NSApp.activate(ignoringOtherApps: true)
        if let window {
            window.makeKeyAndOrderFront(nil)
            window.orderFrontRegardless()
            return
        }
        let window = NSWindow(
            contentRect: NSRect(origin: .zero, size: Self.size),
            styleMask: [.titled, .closable, .resizable],
            backing: .buffered,
            defer: false)
        window.isReleasedWhenClosed = false
        window.delegate = self
        window.contentViewController = NSHostingController(rootView: SettingsView())
        window.contentMinSize = Self.minimumSize
        window.title = "AlwaysConnect 设置"
        window.center()
        window.makeKeyAndOrderFront(nil)
        window.orderFrontRegardless()
        self.window = window
    }
}
