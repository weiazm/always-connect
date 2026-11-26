import Foundation

@_silgen_name("ac_proxy_probe")
private func ac_proxy_probe(_ server: UnsafePointer<CChar>, _ rules: UnsafePointer<CChar>) -> UnsafeMutablePointer<CChar>?
@_silgen_name("ac_string_free")
private func probe_string_free(_ s: UnsafeMutablePointer<CChar>?)

/// Whether a proxy works (DESIGN.md §69.8): from a check made here (the
/// Rust core connects, completes the handshake and password, and asks the
/// proxy to open a site from its rules) or from the background service's
/// real connections through it, whichever is newer.
struct ProxyCheck: Equatable {
    enum Level: String { case ok, warn, fail }
    var level: Level
    var text: String
    var millis: Int?
    var at: Date
    /// Reported by the background service from real connections.
    var fromTraffic = false

    /// The short form for a row or a tile: what it means, not how it
    /// failed (user 2026-11-25: "代理连不上就说连不上"). The reason is
    /// `text`, shown on hover and in the editor.
    var short: String {
        switch level {
        case .ok: return millis.map { "正常 · \($0) ms" } ?? "正常"
        case .warn: return "部分网站打不开"
        case .fail: return "连不上"
        }
    }

    /// Blocks up to ~20 s: never on the main thread.
    static func run(_ route: ProxyRoute, password: String?) -> ProxyCheck {
        let line = route.serverLine(password: password)
        let rules = route.sites.joined(separator: "\n")
        guard let raw = ac_proxy_probe(line, rules) else {
            return ProxyCheck(level: .fail, text: "代理地址无效", at: Date())
        }
        defer { probe_string_free(raw) }
        struct Out: Decodable { var level: String; var text: String; var millis: Int }
        guard let out = try? JSONDecoder().decode(Out.self, from: Data(String(cString: raw).utf8)) else {
            return ProxyCheck(level: .fail, text: "检测没有结果", at: Date())
        }
        return ProxyCheck(level: Level(rawValue: out.level) ?? .fail, text: out.text, millis: out.millis, at: Date())
    }
}

/// One proxy's recent results from the background service (split status).
struct ProxyTraffic: Decodable, Equatable {
    var proxy: Int
    var okAgo: Int?
    var failedAgo: Int?
    var reason: String?
}

/// The checks, kept for this run of the App only (in memory, a few
/// entries). Checks run only while the panel or a page showing proxies is
/// open: at once on opening, then at most every 2 s per proxy (user,
/// 2026-11-26: "只有打开面板做就行啊", and fast), and when real traffic failed.
final class ProxyHealth: ObservableObject {
    static let shared = ProxyHealth()
    @Published private(set) var checks: [UUID: ProxyCheck] = [:]
    @Published private(set) var checking: Set<UUID> = []
    static let gap: TimeInterval = 2

    /// Fixed results (offscreen screenshots).
    func preview(_ checks: [UUID: ProxyCheck]) { self.checks = checks }

    func check(_ routes: [ProxyRoute], force: Bool = false) {
        for route in routes where route.enabled && !checking.contains(route.id) {
            if !force, let last = checks[route.id], !last.fromTraffic, Date().timeIntervalSince(last.at) < Self.gap { continue }
            checking.insert(route.id)
            DispatchQueue.global(qos: .utility).async {
                let result = ProxyCheck.run(route, password: ProxyPasswords.password(for: route))
                DispatchQueue.main.async {
                    self.checking.remove(route.id)
                    self.checks[route.id] = result
                }
            }
        }
    }

    /// A check the editor already made for this proxy.
    func record(_ result: ProxyCheck, for id: UUID) { checks[id] = result }

    func forget(_ id: UUID) { checks[id] = nil }

    /// Real connections: a success newer than the last check keeps it
    /// green; a failure newer than the last check is shown at once and
    /// checked again (was it the proxy, or only that site?).
    func merge(_ rows: [ProxyTraffic], routes: [ProxyRoute]) {
        let now = Date()
        for row in rows where routes.indices.contains(row.proxy) {
            let route = routes[row.proxy]
            let ok = row.okAgo.map { now.addingTimeInterval(-Double($0)) }
            let failed = row.failedAgo.map { now.addingTimeInterval(-Double($0)) }
            let current = checks[route.id]
            // Seconds are rounded: "newer" means by more than two.
            func newer(_ date: Date) -> Bool { current.map { date.timeIntervalSince($0.at) > 2 } ?? true }
            if let failed, ok.map({ failed >= $0 }) ?? true, newer(failed) {
                checks[route.id] = ProxyCheck(level: .warn, text: "最近一次经它失败：\(row.reason ?? "原因不明")",
                                              at: failed, fromTraffic: true)
                check([route])
            } else if let ok, newer(ok), current?.level != .ok || current?.fromTraffic == true {
                checks[route.id] = ProxyCheck(level: .ok, text: "最近经它的连接正常", millis: current?.millis, at: ok, fromTraffic: true)
            }
        }
    }

    /// The panel tile's line for the proxies in use.
    func summary(_ routes: [ProxyRoute]) -> (text: String, level: ProxyCheck.Level?) {
        let results = routes.map { checks[$0.id] }
        if results.contains(where: { $0?.level == .fail }) { return ("连不上", .fail) }
        if results.contains(where: { $0?.level == .warn }) { return ("部分网站打不开", .warn) }
        if results.allSatisfy({ $0?.level == .ok }) {
            let fastest = results.compactMap { $0?.millis }.min()
            return ("正常" + (fastest.map { " · \($0) ms" } ?? ""), .ok)
        }
        return ("检测中…", nil)
    }
}

/// Whether the network works right now through the VPN, while the panel
/// shows it (UI-DESIGN.md 面板): a HEAD request to a few well-known
/// addresses every 2 s, the fastest answer counts. Released with the panel;
/// the last answer (one value) is kept for a minute, so a reopened panel
/// shows it at once while the next one runs (user, 2026-11-26: "刷新太慢了").
final class LinkCheck: ObservableObject {
    enum State: Equatable { case unknown, ok(Int), slow(Int), down }
    private static var recent: (state: State, at: Date)?
    /// A sample answer for the README picture.
    func showPreview(_ sample: State) { state = sample }

    @Published private(set) var state: State = LinkCheck.recent.flatMap {
        Date().timeIntervalSince($0.at) < 60 ? $0.state : nil
    } ?? .unknown {
        didSet { if state != .unknown { LinkCheck.recent = (state, Date()) } }
    }
    private var running = false
    private var last = Date.distantPast
    private var failures = 0
    private let session: URLSession = {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 4
        configuration.timeoutIntervalForResource = 5
        configuration.waitsForConnectivity = false
        configuration.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        return URLSession(configuration: configuration)
    }()

    deinit { session.invalidateAndCancel() }

    func reset() { LinkCheck.recent = nil; state = .unknown; failures = 0; last = .distantPast }

    func checkIfDue() {
        guard !running, Date().timeIntervalSince(last) >= 2 else { return }
        running = true
        last = Date()
        let group = DispatchGroup()
        let lock = NSLock()
        var fastest: Int?
        for url in ConnectionCheck.probes {
            group.enter()
            var request = URLRequest(url: url)
            request.httpMethod = "HEAD"
            let started = Date()
            session.dataTask(with: request) { _, response, _ in
                if response is HTTPURLResponse {
                    let ms = Int(Date().timeIntervalSince(started) * 1000)
                    lock.lock(); fastest = min(fastest ?? ms, ms); lock.unlock()
                }
                group.leave()
            }.resume()
        }
        group.notify(queue: .main) { [weak self] in
            guard let self else { return }
            self.running = false
            if let ms = fastest {
                self.failures = 0
                self.state = ms > 1500 ? .slow(ms) : .ok(ms)
            } else {
                // One lost round is not an outage.
                self.failures += 1
                if self.failures >= 2 { self.state = .down }
            }
        }
    }
}
