import AppKit
import SwiftUI

@main
struct GatewayStatusHarness {
    static func check(_ ok: @autoclosure () -> Bool, _ message: String) {
        guard ok() else {
            FileHandle.standardError.write(Data("FAIL \(message)\n".utf8))
            exit(1)
        }
    }

    static func status(_ client: HelperClient, rejected: Bool, render: Bool = false) {
        let header = PanelStatusHeader(client: client, subtitle: "测试服务器 · 已连接 5 分钟")
        let button = NSButton()
        StatusLook.updateMenuButton(button, client: client)
        check(header.badge == (rejected ? .alert : .lock), "panel badge")
        check(header.look.color == (rejected ? .systemRed : .systemGreen), "panel colour")
        check(header.look.headline == (rejected ? "VPN 网关证书校验失败" : "VPN 已连接"), "panel headline")
        check(client.showsConnected == !rejected, "connection duration and traffic visibility")
        if rejected {
            check(!header.subtitle.contains("已连接") && header.subtitle == client.certificateProtectionText, "subtitle")
            check(button.toolTip?.contains("证书校验失败") == true && button.toolTip?.contains("已连接") == false, "menu tooltip")
        }
        let reference = GlobeIcon.image(rejected ? .alert : .lock)
        check(button.image?.tiffRepresentation == reference.tiffRepresentation, "menu image")
        if render {
            let view = NSHostingView(rootView: header.padding().frame(width: 360, height: 110)
                .background(Color.white).environment(\.colorScheme, .light))
            view.frame = NSRect(x: 0, y: 0, width: 360, height: 110)
            let window = NSWindow(contentRect: view.frame, styleMask: .borderless, backing: .buffered, defer: false)
            window.contentView = view
            view.layoutSubtreeIfNeeded()
            guard let rep = view.bitmapImageRepForCachingDisplay(in: view.bounds) else { exit(1) }
            view.cacheDisplay(in: view.bounds, to: rep)
            var red = 0
            var green = 0
            for x in stride(from: 0, to: rep.pixelsWide, by: 2) {
                for y in stride(from: 0, to: rep.pixelsHigh, by: 2) {
                    guard let c = rep.colorAt(x: x, y: y)?.usingColorSpace(.sRGB), c.alphaComponent > 0.5 else { continue }
                    let (r, g, b) = (c.redComponent, c.greenComponent, c.blueComponent)
                    if r > 0.55 && r > 1.4 * g && r > 1.4 * b { red += 1 }
                    if g > 0.45 && g > 1.3 * r && g > 1.2 * b { green += 1 }
                }
            }
            check(rejected ? (red > 3 && green == 0) : green > 3, "offscreen header pixels red=\(red) green=\(green)")
        }
    }

    static func main() throws {
        _ = NSApplication.shared
        let trace = try String(contentsOfFile: CommandLine.arguments[1], encoding: .utf8)
        let events = trace.split(separator: "\n").filter { $0.hasPrefix("GATEWAY_TRUST ") }
        check(events == ["GATEWAY_TRUST accepted", "GATEWAY_TRUST rejected", "GATEWAY_TRUST accepted"], "TLS fixture ordered trust callbacks")
        let login = HelperClient()
        for (state, detail, expected) in [(HelperClient.State.authenticating, "approval answered", "网关已回应，等待连接结果"),
                                          (.awaitingApproval, "tunnel negotiation accepted", "隧道协商完成，正在配置 VPN 网络")] {
            login.state = state
            login.detail = detail
            let header = PanelStatusHeader(client: login, subtitle: detail)
            check(header.subtitle == expected && header.look.headline == "正在连接…", "panel shows the real login phase")
            check(login.stateLine == expected && !login.showsConnected, "progress does not announce a live VPN")
        }
        login.gatewayTrustFailed = true
        let rejected = PanelStatusHeader(client: login, subtitle: login.detail)
        check(rejected.look.headline == StatusLook.certificateHeadline && rejected.subtitle == login.certificateProtectionText,
              "certificate failure takes priority over the last progress report")
        let c = HelperClient()
        let pin = "synthetic-session"
        for event in events {
            c.observeRelayTrust(event == "GATEWAY_TRUST accepted", pin: pin, generation: 1)
            if event == "GATEWAY_TRUST rejected" {
                status(c, rejected: true, render: true)
                check(c.certificateProtectionText.contains("尚未确认"), "before protection reply")
                c.service.rejections.last!.1(true)
                check(c.certificateProtectionText.contains("网络已拦截"), "after verified hold")
                for raw in 0...5 {
                    c.state = HelperClient.State(rawValue: raw)!
                    c.confirmRelayRecovery()
                    status(c, rejected: true)
                }
                c.state = .connected
            } else if c.gatewayTrustFailed {
                status(c, rejected: true)
                c.service.recoveries.last!.1(false)
                c.confirmRelayRecovery()
                c.service.recoveries.last!.1(true)
            }
        }
        status(c, rejected: false, render: true)
        check(Notifier.shared.failures == 1, "one notice for repeated certificate failures")

        c.observeRelayTrust(false, pin: pin, generation: 1)
        c.observeRelayTrust(true, pin: pin, generation: 1)
        let oldRecovery = c.service.recoveries.last!
        let oldHold = c.service.rejections.last!
        c.observeRelayTrust(false, pin: pin, generation: 1)
        oldRecovery.1(true)
        oldHold.1(true)
        check(!c.rejectedLoginHeld, "older incident cannot confirm protection")
        status(c, rejected: true)
        c.relayGeneration += 1
        c.observeRelayTrust(true, pin: pin, generation: 1)
        c.protectsDrops = false
        c.service.rejections.last!.1(true)
        check(c.certificateProtectionText.contains("断线保护已关闭"), "protection disabled")
        status(c, rejected: true)

        let native = HelperClient()
        native.usesCisco = true
        native.updateCiscoTrust(rejected: true, state: .reconnecting)
        native.updateCiscoTrust(rejected: false, state: .authenticating)
        status(native, rejected: true, render: true)
        native.awaitingCiscoStart = true
        native.updateCiscoTrust(rejected: false, state: .connected)
        status(native, rejected: true)
        native.awaitingCiscoStart = false
        native.updateCiscoTrust(rejected: false, state: .connected)
        status(native, rejected: false)
        print("PASS relay and Cisco failure presentation, rendered header, menu image, tooltip, stale replies and verified recovery")
    }
}
