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
    /// Where the window's size and place are kept between openings.
    static let frameName = "AlwaysConnectSettings"

    private var window: NSWindow?
    @Published private(set) var contentVisible = true

    func windowDidChangeOcclusionState(_ notification: Notification) {
        guard let window = notification.object as? NSWindow, window === self.window else { return }
        let visible = window.occlusionState.contains(.visible)
        if visible != contentVisible { contentVisible = visible }
    }
    @Published var egressRuleToOpen: UInt32?
    @Published var vpnConnectionsRequested = false

    func showVPNConnections() {
        vpnConnectionsRequested = true
        show(tab: "traffic")
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
        if let rule = egressRule ?? initialRule {
            egressRuleToOpen = rule
        }
        let focusEgress = tab == "egress" || egressRule != nil || initialRule != nil
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
        let window = Self.makeWindow(SettingsView())
        window.delegate = self
        // Same size and place as last time (user, 2026-11-26).
        if !window.setFrameUsingName(Self.frameName) { window.center() }
        window.setFrameAutosaveName(Self.frameName)
        window.makeKeyAndOrderFront(nil)
        window.orderFrontRegardless()
        self.window = window
    }

    /// The window without its title line (user, 2026-11-26: "设置页的页面顶部
    /// 的窗口能隐藏吗？美观一些啊"): the title bar is see-through and the
    /// page's tab row sits in it, beside the window's buttons. The title
    /// stays for the Window menu and VoiceOver.
    static func makeWindow<Content: View>(_ content: Content) -> NSWindow {
        let window = NSWindow(
            contentRect: NSRect(origin: .zero, size: size),
            styleMask: [.titled, .closable, .miniaturizable, .resizable, .fullSizeContentView],
            backing: .buffered,
            defer: false)
        window.isReleasedWhenClosed = false
        window.title = "AlwaysConnect 设置"
        window.titleVisibility = .hidden
        window.titlebarAppearsTransparent = true
        window.titlebarSeparatorStyle = .none
        // An empty toolbar only makes the title bar as tall as the tab
        // row, with the window's buttons centred on it (§69.14).
        let toolbar = NSToolbar(identifier: frameName)
        toolbar.delegate = EmptyToolbar.shared
        toolbar.allowsUserCustomization = false
        window.toolbar = toolbar
        window.toolbarStyle = .unified
        window.contentViewController = NSHostingController(rootView: content)
        window.contentMinSize = minimumSize
        window.setContentSize(size)
        return window
    }
}

/// No items: the toolbar is there for its height only.
private final class EmptyToolbar: NSObject, NSToolbarDelegate {
    static let shared = EmptyToolbar()
    func toolbarDefaultItemIdentifiers(_ toolbar: NSToolbar) -> [NSToolbarItem.Identifier] { [] }
    func toolbarAllowedItemIdentifiers(_ toolbar: NSToolbar) -> [NSToolbarItem.Identifier] { [] }
}
