import AppKit
import SwiftUI

/// Headline and colour per situation for the panel header (UI-DESIGN.md
/// §三). The icon itself is GlobeIcon (globe + state badge, as the
/// user asked); `symbol` remains an SF Symbol fallback.
struct StatusLook {
    var symbol: String
    var color: NSColor
    var headline: String

    static let certificateHeadline = "VPN 网关证书校验失败"

    static func of(_ state: HelperClient.State, held: Bool, hasCredentials: Bool, onDemand: Bool = false,
                   certificateRejected: Bool = false, pendingLogin: Bool = false) -> StatusLook {
        if certificateRejected {
            return StatusLook(symbol: "exclamationmark.shield.fill", color: .systemRed, headline: certificateHeadline)
        }
        if pendingLogin && state == .disconnected {
            return StatusLook(symbol: "shield.lefthalf.fill", color: .systemYellow, headline: "VPN 尚未连接")
        }
        switch state {
        case .connected:
            return StatusLook(symbol: "checkmark.shield.fill", color: .systemGreen, headline: "VPN 已连接")
        case .connecting, .authenticating:
            return StatusLook(symbol: "shield.lefthalf.fill", color: .systemYellow, headline: "正在连接…")
        case .awaitingApproval:
            return StatusLook(symbol: "iphone.radiowaves.left.and.right", color: .systemYellow,
                              headline: "请在手机上确认登录")
        case .reconnecting:
            return StatusLook(symbol: "exclamationmark.shield.fill", color: .systemRed,
                              headline: "VPN 断了，正在重连")
        case .disconnected where held:
            return StatusLook(symbol: "exclamationmark.shield.fill", color: .systemRed,
                              headline: "未连接，网络仍处暂停")
        case .disconnected:
            return StatusLook(symbol: "shield.slash", color: .secondaryLabelColor,
                              headline: onDemand ? "已断开 · 按需连接" : (hasCredentials ? "未连接（直连网络）" : "还没填账号"))
        }
    }

    static func updateMenuButton(_ button: NSButton, client: HelperClient) {
        var badge = GlobeIcon.badge(for: client.state, held: client.networkHeld, certificateRejected: client.gatewayTrustFailed)
        if badge == .none, client.proxyOnlyRunning { badge = .proxy }
        button.image = GlobeIcon.image(badge)
        button.contentTintColor = nil
        button.toolTip = "AlwaysConnect：\(client.stateLine)"
        button.setAccessibilityLabel(button.toolTip)
    }

    var image: NSImage? {
        NSImage(systemSymbolName: symbol, accessibilityDescription: headline)
            ?? NSImage(systemSymbolName: "shield", accessibilityDescription: headline)
    }
}


/// Shared by the real menu panel and the offscreen status regression.
struct PanelStatusHeader: View {
    let look: StatusLook
    let badge: GlobeIcon.Badge
    let subtitle: String
    let certificateRejected: Bool

    init(client: HelperClient, subtitle: @autoclosure () -> String) {
        certificateRejected = client.gatewayTrustFailed
        let progress = client.ownLoginProgressText
        let displayState: HelperClient.State = progress == nil ? client.state : .connecting
        look = StatusLook.of(displayState, held: client.networkHeld, hasCredentials: client.hasCredentials,
                             onDemand: client.onDemandPaused, certificateRejected: certificateRejected,
                             pendingLogin: client.loginProtectionNotice != nil)
        badge = GlobeIcon.badge(for: displayState, held: client.networkHeld, certificateRejected: certificateRejected)
        self.subtitle = certificateRejected ? client.certificateProtectionText : (progress ?? subtitle())
    }

    var body: some View {
        HStack(spacing: 12) {
            Image(nsImage: GlobeIcon.image(badge, size: 36))
                .frame(width: 40, height: 40)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                Text(look.headline)
                    .font(.title3.weight(.semibold))
                    .foregroundStyle(Color(nsColor: look.color))
                Text(subtitle)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(certificateRejected ? nil : 2)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer()
        }
    }
}
