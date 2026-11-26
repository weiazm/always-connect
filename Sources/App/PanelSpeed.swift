import Foundation

@_silgen_name("ac_speed_totals")
private func ac_speed_totals(_ proxy: UnsafePointer<CChar>?) -> UnsafeMutablePointer<CChar>?
@_silgen_name("ac_speed_totals_stop")
private func ac_speed_totals_stop()
@_silgen_name("ac_string_free")
private func speed_string_free(_ s: UnsafeMutablePointer<CChar>?)

/// The panel's 网速 card (DESIGN.md §45.4; user, 2026-11-12: not in the
/// menu bar all the time, only when the panel is opened). Lives with the
/// panel's SwiftUI tree: `start` on appear, `stop` on disappear (the
/// panel is released when it closes, §32.1). While open, every 2 s with
/// tolerance, it asks the background service for the split status (the
/// panel's 正在直连 and the proxied totals, §69.17) and, once that is in,
/// the Rust core reads the interface counters once (one sysctl, about
/// 0.4 ms, no process) and returns the totals: every column's numbers
/// come from the same moment and appear together (§69.18).
final class PanelSpeed: ObservableObject {
    struct Totals: Decodable, Equatable {
        var ready: Bool
        var total: [Int]
        var vpn: [Int]
        var direct: [Int]
        /// Through the split's proxies, taken out of the other two (§69.17).
        var proxy: [Int]?
    }

    /// Nil until the second reading (a speed needs two), and while the
    /// proxied part still needs its second one.
    @Published private(set) var totals: Totals?
    private var timer: Timer?

    func start() {
        guard timer == nil else { return }
        let t = Timer(timeInterval: 2, repeats: true) { [weak self] _ in self?.tick() }
        t.tolerance = 0.3
        RunLoop.main.add(t, forMode: .common)
        timer = t
        tick()
        // The first numbers after half a second, then every 2 s (user,
        // 2026-11-26: "界面上的一些延迟数据 刷新太慢了").
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) { [weak self] in
            guard let self, self.timer != nil else { return }
            self.tick()
        }
    }

    /// The service's answer first, then the reading.
    private func tick() {
        HelperClient.shared.refreshSplitActivity { [weak self] in
            guard let self, self.timer != nil else { return }
            self.read()
        }
    }

    func stop() {
        guard let timer else { return }
        timer.invalidate()
        self.timer = nil
        totals = nil
        ac_speed_totals_stop()
    }

    deinit {
        if let timer {
            timer.invalidate()
            ac_speed_totals_stop()
        }
    }

    private func read() {
        let proxy = HelperClient.shared.proxyBytes
        guard let raw = proxy.map({ $0.withCString { ac_speed_totals($0) } }) ?? ac_speed_totals(nil) else { return }
        defer { speed_string_free(raw) }
        let decoded = try? JSONDecoder().decode(Totals.self, from: Data(String(cString: raw).utf8))
        let next = decoded?.ready == true ? decoded : nil
        if next != totals { totals = next }
    }

    /// "2.4 MB/s", "180 KB/s", "980 B/s".
    static func text(_ bytes: Int) -> String {
        switch bytes {
        case ..<1000: return "\(bytes) B/s"
        case ..<1_000_000: return "\(bytes / 1000) KB/s"
        case ..<10_000_000: return String(format: "%.1f MB/s", Double(bytes) / 1_000_000)
        default: return "\(bytes / 1_000_000) MB/s"
        }
    }
}
