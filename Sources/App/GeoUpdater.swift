import CryptoKit
import Foundation

@_silgen_name("ac_geosite_from_dlc")
private func ac_geosite_from_dlc(_ data: UnsafePointer<UInt8>?, _ len: Int) -> UnsafeMutablePointer<CChar>?
@_silgen_name("ac_string_free")
private func geo_string_free(_ value: UnsafeMutablePointer<CChar>?)

/// Downloads the site lists and keeps them current (DESIGN.md §66.30, user
/// 2026-11-24: "清单要支持自动更新的，不是跟 app 打包写死的"; 2026-11-25:
/// "默认app都不带，每次安装后如果没有就初始化拉取一遍"; "本地文件如果有了，
/// 也不用每次都完整下载").
///
/// A thin shell like UpdateChecker, no timer. `checkIfDue()` runs at
/// launch, on every panel open and when the VPN connects. Without local
/// lists it tries at once (a try that finds the network held by drop
/// protection is repeated when the VPN connects); with them, once a day.
/// Each try costs one small request for the latest release tag of
/// v2fly/domain-list-community. A new tag fetches the 74-byte SHA-256 file
/// first: the same hash as the lists in place means nothing to download.
/// Only new content downloads `dlc.dat` (about 2.5 MB), which must match
/// that hash, read as a full catalogue in the Rust core and still hold
/// every list the user's rules name. The text and a version file go to
/// Application Support; the split list and exit protection are sent to the
/// background service again only when a list they use changed (a resend
/// restarts exit protection's checks).
final class GeoUpdater: ObservableObject {
    static let shared = GeoUpdater()

    @Published private(set) var checking = false
    /// The release the lists in place come from; nil = not downloaded yet.
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

    static let dayInterval: TimeInterval = 24 * 3600
    static let retryInterval: TimeInterval = 3600
    /// No reply at all is usually the network, not GitHub: a try while the
    /// VPN is connecting finds the network held by drop protection (seen on
    /// the real Mac, 2026-11-25). It is repeated when the VPN connects.
    static let unreachable = "连不上 GitHub"
    static let unreachableRetry: TimeInterval = 600
    /// Without any lists a failed try is repeated sooner.
    static let missingRetry: TimeInterval = 60
    private static let maxDownload = 32 << 20

    private enum Key {
        static let lastAttempt = "siteListsLastAttempt"
        static let lastSuccess = "siteListsLastSuccess"
        static let lastError = "siteListsLastError"
    }

    /// The App's own preferences, shared with the settings process; the
    /// harness swaps in a scratch suite.
    static var store: UserDefaults = .standard
    private var defaults: UserDefaults { Self.store }
    /// After lists the rules use changed (the rules are sent again).
    static var installed: () -> Void = { HelperClient.shared.siteListsChanged() }

    private init() { reload() }

    func reload() {
        version = GeoData.available ? Self.stamp()?.tag : nil
        let success = defaults.double(forKey: Key.lastSuccess)
        lastSuccess = success > 0 ? Date(timeIntervalSince1970: success) : nil
        lastError = defaults.string(forKey: Key.lastError)
    }

    /// `networkReady`: the VPN has just connected, so a try that found no
    /// network at all is due again at once.
    func checkIfDue(networkReady: Bool = false) {
        reload()
        let missing = !GeoData.available
        // The first download is not optional; the switch only stops updates.
        guard missing || ProfileStore.loadAppSettings().isSiteListsAutoUpdateOn else { return }
        let wait: TimeInterval
        switch lastError {
        case nil: wait = missing ? 0 : Self.dayInterval
        case Self.unreachable?: wait = networkReady ? 0 : (missing ? Self.missingRetry : Self.unreachableRetry)
        default: wait = missing ? Self.missingRetry : Self.retryInterval
        }
        if Date().timeIntervalSince1970 - defaults.double(forKey: Key.lastAttempt) >= wait { check { _ in } }
    }

    /// One try now ("立即更新", or a due check), in whichever App process
    /// asks. Completion: nil = the lists are current, else why not.
    func check(done: @escaping (String?) -> Void) {
        guard !checking else { done("正在更新"); return }
        checking = true
        defaults.set(Date().timeIntervalSince1970, forKey: Key.lastAttempt)
        let current = GeoData.available ? Self.stamp() : nil
        let session = Self.session()
        Self.fetch(session, URL(string: Self.api)) { body in
            guard let body, let tag = Self.tag(in: body) else {
                session.finishTasksAndInvalidate()
                self.finish(error: body == nil ? Self.unreachable : "GitHub 没有给出清单版本", changed: false, done: done)
                return
            }
            if tag == current?.tag {
                session.finishTasksAndInvalidate()
                self.finish(error: nil, changed: false, done: done)
                return
            }
            Self.fetch(session, Self.download(tag, "dlc.dat.sha256sum")) { sum in
                let hash = sum.flatMap(Self.hash(inSumFile:))
                if let hash, hash == current?.hash {
                    // A new tag over the same content: nothing to download.
                    session.finishTasksAndInvalidate()
                    let error = Self.writeStamp(.init(tag: tag, hash: hash)) ? nil : "清单写不进去"
                    self.finish(error: error, changed: false, done: done)
                    return
                }
                Self.fetch(session, Self.download(tag, "dlc.dat")) { data in
                    session.finishTasksAndInvalidate()
                    let (error, changed) = Self.install(dat: data, hash: hash, tag: tag)
                    self.finish(error: error, changed: changed, done: done)
                }
            }
        }
    }

    private func finish(error: String?, changed: Bool, done: @escaping (String?) -> Void) {
        DispatchQueue.main.async {
            if let error {
                self.defaults.set(error, forKey: Key.lastError)
            } else {
                self.defaults.removeObject(forKey: Key.lastError)
                self.defaults.set(Date().timeIntervalSince1970, forKey: Key.lastSuccess)
            }
            self.checking = false
            self.reload()
            if changed { Self.installed() }
            // The download, the conversion and the rules expanded again for
            // the background service are freed by now: hand the pages back
            // (§45.5; on the real Mac the App stayed 17 MB larger without it).
            MemoryRelief.soon(after: 5)
            done(error)
        }
    }

    // MARK: - Steps (static: no state, testable)

    static var target: URL { GeoData.updateDirectory.appendingPathComponent("geosite.txt") }
    /// "tag\nsha256 of dlc.dat\n" beside the lists: both App processes
    /// read the same answer (preferences caches could disagree).
    static var stampFile: URL { GeoData.updateDirectory.appendingPathComponent("version") }

    struct Stamp: Equatable {
        var tag: String
        var hash: String
    }

    static func stamp() -> Stamp? {
        guard let text = try? String(contentsOf: stampFile, encoding: .utf8) else { return nil }
        let lines = text.split(separator: "\n").map(String.init)
        guard lines.count >= 2 else { return nil }
        return Stamp(tag: lines[0], hash: lines[1])
    }

    @discardableResult
    static func writeStamp(_ stamp: Stamp) -> Bool {
        (try? Data("\(stamp.tag)\n\(stamp.hash)\n".utf8).write(to: stampFile, options: .atomic)) != nil
    }

    static func hash(inSumFile sum: Data) -> String? {
        let first = String(decoding: sum, as: UTF8.self).split(whereSeparator: \.isWhitespace).first.map(String.init)?.lowercased()
        guard let first, first.count == 64, first.allSatisfy(\.isHexDigit) else { return nil }
        return first
    }

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

    /// Checks the download and puts the converted text in place. Returns
    /// why not (nothing changed then), and whether a list the rules use
    /// is different from before.
    static func install(dat: Data?, hash: String?, tag: String) -> (error: String?, changed: Bool) {
        guard let dat, let hash else { return ("清单没有下载完", false) }
        let actual = SHA256.hash(data: dat).map { String(format: "%02x", $0) }.joined()
        guard hash == actual else { return ("清单校验不通过", false) }
        let pointer = dat.withUnsafeBytes { raw in
            ac_geosite_from_dlc(raw.bindMemory(to: UInt8.self).baseAddress, raw.count)
        }
        guard let pointer else { return ("清单内容不完整", false) }
        defer { geo_string_free(pointer) }
        let text = Data(bytes: pointer, count: strlen(pointer))
        let old = GeoData.available ? (try? Data(contentsOf: target, options: .alwaysMapped)) : nil
        var changed = old == nil
        for name in Set(usedLists()) {
            guard let range = GeoData.range(of: name, in: text) else {
                return ("新清单里没有 geosite:\(name)，先不更新", false)
            }
            if let old, old.isEmpty == false {
                let before = GeoData.range(of: name, in: old).map { old[$0] }
                if before != text[range] { changed = true }
            }
        }
        do {
            try FileManager.default.createDirectory(at: GeoData.updateDirectory, withIntermediateDirectories: true)
            try text.write(to: target, options: .atomic)
        } catch {
            return ("清单写不进去", false)
        }
        guard writeStamp(Stamp(tag: tag, hash: hash)) else { return ("清单写不进去", false) }
        return (nil, changed)
    }

    var versionText: String {
        guard let version else { return "还没下载" }
        // "20261124090120" -> "2026-11-24"
        guard version.count >= 8 else { return version }
        let digits = Array(version)
        return "\(String(digits[0..<4]))-\(String(digits[4..<6]))-\(String(digits[6..<8])) 版"
    }
}
