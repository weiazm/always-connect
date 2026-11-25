import CryptoKit
import Foundation

@_silgen_name("ac_geosite_from_dlc")
private func ac_geosite_from_dlc(_ data: UnsafePointer<UInt8>?, _ len: Int) -> UnsafeMutablePointer<CChar>?
@_silgen_name("ac_string_free")
private func geo_string_free(_ value: UnsafeMutablePointer<CChar>?)

/// Keeps the site lists (geosite:) current (DESIGN.md §66.30, user
/// 2026-11-24: "清单要支持自动更新的，不是跟 app 打包写死的").
///
/// A thin shell like UpdateChecker: no timer; `checkIfDue()` runs 30 s
/// after launch and on every panel open and asks at most once a day
/// (once an hour after a failed try). One small request reads the latest
/// release tag of v2fly/domain-list-community, the project the bundled
/// lists come from; only a new tag downloads its `dlc.dat` (about 2.5 MB)
/// and the SHA-256 published beside it. The file must match that hash,
/// the Rust core must read it as a full catalogue, and every list the
/// user's rules name must still be in it; otherwise the lists in use stay
/// as they were. The text goes to Application Support (GeoData reads it
/// in place of the bundled one), then the split list and exit protection
/// are sent to the background service again with the new lists.
final class GeoUpdater: ObservableObject {
    static let shared = GeoUpdater()

    @Published private(set) var checking = false
    /// The release the lists in use come from; nil = the bundled ones.
    @Published private(set) var version: String?
    @Published private(set) var lastSuccess: Date?
    /// Why the last try failed; nil when it did not.
    @Published private(set) var lastError: String?

    /// The publisher's repository; ALWAYSCONNECT_GEO_FEED replaces both
    /// addresses' common start for the local harness (scripts/geo-update-test.sh).
    private static var api: String {
        (ProcessInfo.processInfo.environment["ALWAYSCONNECT_GEO_FEED"].map { $0 + "/api" })
            ?? "https://api.github.com/repos/v2fly/domain-list-community/releases/latest"
    }
    private static func download(_ tag: String, _ file: String) -> URL? {
        let base = ProcessInfo.processInfo.environment["ALWAYSCONNECT_GEO_FEED"].map { $0 + "/download" }
            ?? "https://github.com/v2fly/domain-list-community/releases/download"
        return URL(string: "\(base)/\(tag)/\(file)")
    }

    static let bundledVersion = "2026-11-05"
    static let dayInterval: TimeInterval = 24 * 3600
    static let retryInterval: TimeInterval = 3600
    /// No reply at all is usually the network, not GitHub: the first try
    /// 30 s after launch often lands while the VPN is still connecting and
    /// drop protection holds the network (seen on the real Mac, 2026-11-25).
    static let unreachable = "连不上 GitHub"
    static let unreachableRetry: TimeInterval = 600
    private static let maxDownload = 32 << 20

    private enum Key {
        static let version = "siteListsVersion"
        static let lastAttempt = "siteListsLastAttempt"
        static let lastSuccess = "siteListsLastSuccess"
        static let lastError = "siteListsLastError"
    }

    /// The App's own preferences, shared with the settings process; the
    /// harness swaps in a scratch suite.
    static var store: UserDefaults = .standard
    private var defaults: UserDefaults { Self.store }
    /// After new lists are in place (the menu-bar App re-sends its rules).
    static var installed: () -> Void = { HelperClient.shared.siteListsChanged() }

    private init() { reload() }

    func reload() {
        let file = GeoData.updateDirectory.appendingPathComponent("geosite.txt").path
        version = FileManager.default.fileExists(atPath: file) ? defaults.string(forKey: Key.version) : nil
        let success = defaults.double(forKey: Key.lastSuccess)
        lastSuccess = success > 0 ? Date(timeIntervalSince1970: success) : nil
        lastError = defaults.string(forKey: Key.lastError)
    }

    /// `networkReady`: the VPN has just connected, so a try that found no
    /// network at all is due again at once.
    func checkIfDue(networkReady: Bool = false) {
        reload()
        guard ProfileStore.loadAppSettings().isSiteListsAutoUpdateOn else { return }
        let wait: TimeInterval
        switch lastError {
        case nil: wait = Self.dayInterval
        case Self.unreachable?: wait = networkReady ? 0 : Self.unreachableRetry
        default: wait = Self.retryInterval
        }
        if Date().timeIntervalSince1970 - defaults.double(forKey: Key.lastAttempt) >= wait { check { _ in } }
    }

    /// One try now ("立即更新", or a due check). Completion: nil = the
    /// lists are current (new or unchanged), else why not.
    func check(done: @escaping (String?) -> Void) {
        if AppRole.isSettings {
            // The menu-bar App does it, so it re-sends the rules (§37).
            checking = true
            SettingsLink.shared.send("updateSiteLists") { [weak self] reply in
                self?.checking = false
                self?.reload()
                done(reply == "1" ? nil : (self?.lastError ?? "没有更新"))
            }
            return
        }
        guard !checking else { done("正在更新"); return }
        checking = true
        defaults.set(Date().timeIntervalSince1970, forKey: Key.lastAttempt)
        let current = defaults.string(forKey: Key.version)
        let session = Self.session()
        Self.fetch(session, URL(string: Self.api)) { body in
            guard let body, let tag = Self.tag(in: body) else {
                session.finishTasksAndInvalidate()
                self.finish(error: body == nil ? Self.unreachable : "GitHub 没有给出清单版本", tag: nil, done: done)
                return
            }
            if tag == current, FileManager.default.fileExists(atPath: Self.target.path) {
                session.finishTasksAndInvalidate()
                self.finish(error: nil, tag: tag, done: done)
                return
            }
            Self.fetch(session, Self.download(tag, "dlc.dat.sha256sum")) { sum in
                Self.fetch(session, Self.download(tag, "dlc.dat")) { data in
                    session.finishTasksAndInvalidate()
                    self.finish(error: Self.install(dat: data, sum: sum), tag: tag, done: done)
                }
            }
        }
    }

    private func finish(error: String?, tag: String?, done: @escaping (String?) -> Void) {
        DispatchQueue.main.async {
            let now = Date().timeIntervalSince1970
            let changed = error == nil && tag != nil && tag != self.defaults.string(forKey: Key.version)
            if let error {
                self.defaults.set(error, forKey: Key.lastError)
            } else {
                self.defaults.removeObject(forKey: Key.lastError)
                self.defaults.set(now, forKey: Key.lastSuccess)
                if let tag { self.defaults.set(tag, forKey: Key.version) }
            }
            self.checking = false
            self.reload()
            if changed { Self.installed() }
            done(error)
        }
    }

    // MARK: - Steps (static: no state, testable)

    static var target: URL { GeoData.updateDirectory.appendingPathComponent("geosite.txt") }

    /// The lists the user's rules name (split list and exit protection).
    static var usedLists: () -> [String] = {
        let settings = ProfileStore.loadAppSettings()
        return (DirectSites.sites(settings).flatMap(\.domains) + (settings.egressProtection?.groups.flatMap(\.sites) ?? []))
            .compactMap { line in
                guard line.lowercased().hasPrefix("geosite:") else { return nil }
                return line.dropFirst(8).split(separator: "@").first.map { $0.lowercased() }
            }
    }

    private static func session() -> URLSession {
        // Ephemeral and torn down after the answer (§32.1), like UpdateChecker.
        let configuration = URLSessionConfiguration.ephemeral
        configuration.urlCache = nil
        configuration.httpCookieStorage = nil
        configuration.timeoutIntervalForRequest = 30
        return URLSession(configuration: configuration)
    }

    private static func fetch(_ session: URLSession, _ url: URL?, _ done: @escaping (Data?) -> Void) {
        guard let url, url.scheme == "https" || ProcessInfo.processInfo.environment["ALWAYSCONNECT_GEO_FEED"] != nil else {
            done(nil)
            return
        }
        var request = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 60)
        request.setValue("AlwaysConnect/\(UpdateChecker.currentVersion)", forHTTPHeaderField: "User-Agent")
        session.dataTask(with: request) { data, response, _ in
            let ok = (response as? HTTPURLResponse).map { (200..<300).contains($0.statusCode) } ?? false
            done(ok && (data?.count ?? 0) <= maxDownload ? data : nil)
        }.resume()
    }

    /// The release tag, only when it looks like the project's own
    /// (digits, as "20261124090120"): it becomes part of a download path.
    static func tag(in body: Data) -> String? {
        struct Release: Decodable { let tag_name: String }
        guard let tag = try? JSONDecoder().decode(Release.self, from: body).tag_name,
              (8...20).contains(tag.count), tag.allSatisfy(\.isASCII), tag.allSatisfy(\.isNumber) else { return nil }
        return tag
    }

    /// Checks the download and puts the converted text in place; nil when
    /// done, else why not (and nothing changed).
    static func install(dat: Data?, sum: Data?) -> String? {
        guard let dat, let sum else { return "清单没有下载完" }
        let expected = String(decoding: sum, as: UTF8.self).split(whereSeparator: \.isWhitespace).first.map(String.init)?.lowercased()
        let actual = SHA256.hash(data: dat).map { String(format: "%02x", $0) }.joined()
        guard expected == actual else { return "清单校验不通过" }
        let pointer = dat.withUnsafeBytes { raw in
            ac_geosite_from_dlc(raw.bindMemory(to: UInt8.self).baseAddress, raw.count)
        }
        guard let pointer else { return "清单内容不完整" }
        defer { geo_string_free(pointer) }
        let text = Data(bytes: pointer, count: strlen(pointer))
        let lists = Set(GeoData.listRanges(in: text).keys)
        if let missing = usedLists().first(where: { !lists.contains($0) }) {
            return "新清单里没有 geosite:\(missing)，先不更新"
        }
        do {
            try FileManager.default.createDirectory(at: GeoData.updateDirectory, withIntermediateDirectories: true)
            try text.write(to: target, options: .atomic)
        } catch {
            return "清单写不进去"
        }
        return nil
    }

    /// Back to the lists that came with the App.
    func useBundled() {
        try? FileManager.default.removeItem(at: Self.target)
        defaults.removeObject(forKey: Key.version)
        reload()
        Self.installed()
    }

    var versionText: String {
        guard let version else { return "App 自带（\(Self.bundledVersion) 版）" }
        // "20261124090120" -> "2026-11-24"
        guard version.count >= 8 else { return version }
        let digits = Array(version)
        return "\(String(digits[0..<4]))-\(String(digits[4..<6]))-\(String(digits[6..<8])) 版"
    }
}
