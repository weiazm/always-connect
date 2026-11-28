import Foundation

@_silgen_name("ac_proxy_probe")
private func ac_proxy_probe(_ server: UnsafePointer<CChar>, _ rules: UnsafePointer<CChar>) -> UnsafeMutablePointer<CChar>?
@_silgen_name("ac_string_free")
private func probe_string_free(_ s: UnsafeMutablePointer<CChar>?)

/// Whether a proxy works (DESIGN.md §69.8): from a check made here (the
/// Rust core connects, completes the handshake and password, and asks the
/// proxy to open a site from its rules) or from the background service's
/// real connections through it, whichever is newer.
struct ProxyCheck: Equatable, Codable {
    enum Level: String, Codable { case ok, warn, fail, pending }
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
        case .pending: return text
        case .warn: return "部分网站打不开"
        case .fail: return "连不上"
        }
    }

    static func decode(json: String) -> ProxyCheck {
        struct Out: Decodable { var level: String; var text: String; var millis: Int }
        guard let out = try? JSONDecoder().decode(Out.self, from: Data(json.utf8)) else {
            return ProxyCheck(level: .fail, text: "检测没有结果", at: Date())
        }
        return ProxyCheck(level: Level(rawValue: out.level) ?? .fail, text: out.text, millis: out.millis, at: Date())
    }

    /// Blocks up to ~20 s: never on the main thread. For SOCKS5/HTTP only.
    static func run(_ route: ProxyRoute, password: String?, obfsPassword: String? = nil) -> ProxyCheck {
        let line = route.serverLine(password: password, obfsPassword: obfsPassword)
        let rules = route.sites.joined(separator: "\n")
        guard let raw = ac_proxy_probe(line, rules) else {
            return ProxyCheck(level: .fail, text: "代理地址无效", at: Date())
        }
        defer { probe_string_free(raw) }
        return decode(json: String(cString: raw))
    }

    /// Async check for any proxy kind: SOCKS5/HTTP run in-process (Rust);
    /// Hysteria2 delegates to the background service over XPC (§七十).
    static func runAsync(_ route: ProxyRoute, password: String?, obfsPassword: String? = nil,
                         completion: @escaping (ProxyCheck) -> Void) {
        if route.kind == .hysteria2 {
            let line = route.serverLine(password: password, obfsPassword: obfsPassword)
            let rules = route.sites.joined(separator: "\n")
            HelperClient.shared.probeHysteriaProxy(serverLine: line, rules: rules, completion: completion)
            return
        }
        DispatchQueue.global(qos: .userInitiated).async {
            let result = run(route, password: password, obfsPassword: obfsPassword)
            DispatchQueue.main.async { completion(result) }
        }
    }
}

/// One proxy's recent results from the background service (split status).
struct ProxyTraffic: Decodable, Equatable {
    var key: String?
    var okAt: Double?
    var failedAt: Double?
    var reason: String?
}

@_silgen_name("ac_proxy_health_now")
private func healthNow() -> Double
@_silgen_name("ac_proxy_health_begin")
private func healthBegin(_ key: UnsafePointer<CChar>, _ now: Double, _ gap: Double, _ force: Bool) -> UInt64
@_silgen_name("ac_proxy_health_finish")
private func healthFinish(_ key: UnsafePointer<CChar>, _ ticket: UInt64, _ now: Double) -> Int32
@_silgen_name("ac_proxy_health_traffic")
private func healthTraffic(_ key: UnsafePointer<CChar>, _ at: Double) -> Bool
@_silgen_name("ac_proxy_health_reset")
private func healthReset(_ now: Double)

/// The menu-bar process owns saved proxy checks. Settings mirrors these display
/// values over its inherited socket. Probe ordering and throttling live in Rust.
final class ProxyHealth: ObservableObject {
    static let shared = ProxyHealth()
    @Published private(set) var checks: [UUID: ProxyCheck] = [:]
    @Published private(set) var checking: Set<UUID> = []
    @Published private(set) var keys: [UUID: UUID] = [:]

    struct Snapshot: Codable {
        var checks: [UUID: ProxyCheck]
        var checking: Set<UUID>
    }

    var snapshot: Snapshot { Snapshot(checks: checks, checking: checking) }
    func apply(_ s: Snapshot) {
        if checks != s.checks { checks = s.checks }
        if checking != s.checking { checking = s.checking }
    }
    func preview(_ checks: [UUID: ProxyCheck]) { self.checks = checks }

    func invalidate() {
        healthReset(healthNow())
        apply(Snapshot(checks: [:], checking: []))
    }

    func configure(_ routes: [ProxyRoute]) {
        let next = routes.reduce(into: [UUID: UUID]()) { $0[$1.id] = $1.healthKey }
        if next != keys {
            keys = next
            invalidate()
        }
    }

    func check(_ routes: [ProxyRoute], force: Bool = false) {
        if AppRole.isSettings {
            if force {
                for route in routes { SettingsLink.shared.send("checkProxy", route.id.uuidString) }
            } else {
                SettingsLink.shared.send("checkProxies")
            }
            return
        }
        for route in routes where route.enabled && keys[route.id] == route.healthKey {
            let key = route.healthKey.uuidString
            let last = checks[route.id]?.level
            let gap: Double = route.kind == .hysteria2 && last == .ok ? 30 : 2
            let ticket = healthBegin(key, healthNow(), gap, force)
            guard ticket != 0 else { continue }
            checking.insert(route.id)
            let finish: (ProxyCheck) -> Void = { result in
                let decision = healthFinish(key, ticket, healthNow())
                guard decision >= 0 else { return }
                self.checking.remove(route.id)
                if decision & 1 != 0 { self.checks[route.id] = result }
                if decision & 2 != 0 { self.check([route], force: true) }
            }
            if route.kind == .hysteria2 {
                // The service already has the saved credentials. Asking by
                // revision also distinguishes two routes to the same server.
                HelperClient.shared.probeHysteriaProxy(serverLine: "saved-hysteria2 " + key,
                    rules: route.sites.joined(separator: "\n"), completion: finish)
            } else {
                ProxyCheck.runAsync(route, password: ProxyPasswords.password(for: route), completion: finish)
            }
        }
    }

    func merge(_ rows: [ProxyTraffic], routes: [ProxyRoute]) {
        guard !AppRole.isSettings else { return }
        let byKey = routes.reduce(into: [String: ProxyRoute]()) {
            $0[$1.healthKey.uuidString.replacingOccurrences(of: "-", with: "").lowercased()] = $1
        }
        for row in rows {
            guard let key = row.key, let route = byKey[key], keys[route.id] == route.healthKey else { continue }
            let failed = (row.failedAt ?? 0) >= (row.okAt ?? 0)
            guard let observed = failed ? row.failedAt : row.okAt,
                  healthTraffic(route.healthKey.uuidString, observed) else { continue }
            let at = Date().addingTimeInterval(observed - healthNow())
            if failed {
                checks[route.id] = ProxyCheck(level: .warn, text: "最近一次经它失败：" + (row.reason ?? "原因不明"),
                                              at: at, fromTraffic: true)
            } else if checks[route.id]?.level != .ok {
                checks[route.id] = ProxyCheck(level: .ok, text: "最近经它的连接正常", at: at, fromTraffic: true)
            }
        }
    }

    /// The panel tile's line for the proxies in use.
    func summary(_ routes: [ProxyRoute]) -> (text: String, level: ProxyCheck.Level?) {
        guard !routes.isEmpty else { return ("未启用", nil) }
        let results = routes.map { checks[$0.id] }
        if results.count > 1 {
            let levels: [(ProxyCheck.Level?, String)] = [(.ok, "正常"), (.fail, "连不上"),
                (.warn, "部分网站打不开"), (.pending, "等待连接"), (nil, "检测中")]
            let groups = levels.compactMap { level, label -> String? in
                let count = results.filter { $0?.level == level }.count
                return count > 0 ? "\(count) 个\(label)" : nil
            }
            if groups.count > 1 {
                return (groups.joined(separator: " · "), results.contains { $0?.level == .fail || $0?.level == .warn } ? .warn : .pending)
            }
        }
        if results.contains(where: { $0?.level == .fail }) { return ("连不上", .fail) }
        if results.contains(where: { $0?.level == .warn }) { return ("部分网站打不开", .warn) }
        if let waiting = results.compactMap({ $0 }).first(where: { $0.level == .pending }) { return (waiting.short, .pending) }
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
