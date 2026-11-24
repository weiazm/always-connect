import AppKit
import Darwin

/// A program that can be protected (DESIGN §66.24): an app bundle with
/// everything inside it, or a command-line program by its file name.
/// The pattern is what the background service matches process paths with.
struct EgressAppCandidate: Identifiable, Hashable {
    let pattern: String
    let name: String
    /// A path to draw the icon from.
    let path: String
    var id: String { pattern }
    var isBundle: Bool { pattern.hasPrefix("/") }
}

enum EgressApps {
    /// The running programs, one entry per app bundle or command name.
    /// Read once when the picker opens; nothing keeps sampling.
    static func running() -> [EgressAppCandidate] {
        let count = proc_listallpids(nil, 0)
        guard count > 0 else { return [] }
        var pids = [pid_t](repeating: 0, count: Int(count) + 64)
        let got = proc_listallpids(&pids, Int32(pids.count * MemoryLayout<pid_t>.size))
        var buffer = [CChar](repeating: 0, count: Int(4 * MAXPATHLEN))
        var seen: [String: EgressAppCandidate] = [:]
        let own = Bundle.main.bundlePath
        for pid in pids.prefix(Int(max(got, 0))) where pid > 0 {
            guard proc_pidpath(pid, &buffer, UInt32(buffer.count)) > 0 else { continue }
            let path = String(cString: buffer)
            guard let candidate = candidate(forPath: path), candidate.pattern != own,
                  !systemPrefixes.contains(where: path.hasPrefix) else { continue }
            seen[candidate.pattern] = seen[candidate.pattern] ?? candidate
        }
        return seen.values.sorted { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
    }

    private static let systemPrefixes = ["/System/", "/usr/", "/bin/", "/sbin/", "/Library/Apple/",
                                         "/Library/PrivilegedHelperTools/", "/private/var/", "/Library/Developer/"]

    /// The outermost bundle in a path, or the program's file name.
    static func candidate(forPath path: String) -> EgressAppCandidate? {
        if let range = path.range(of: ".app/") ?? (path.hasSuffix(".app") ? path.range(of: ".app", options: .backwards) : nil) {
            let bundle = String(path[..<range.upperBound]).trimmingCharacters(in: CharacterSet(charactersIn: "/"))
            let root = "/" + bundle
            return .init(pattern: root, name: displayName(root), path: root)
        }
        let name = (path as NSString).lastPathComponent
        guard !name.isEmpty else { return nil }
        return .init(pattern: name, name: name, path: path)
    }

    static func displayName(_ pattern: String) -> String {
        guard pattern.hasPrefix("/") else { return pattern }
        let name = FileManager.default.displayName(atPath: pattern)
        return name.hasSuffix(".app") ? String(name.dropLast(4)) : name
    }

    static func icon(_ pattern: String) -> NSImage {
        if pattern.hasPrefix("/"), FileManager.default.fileExists(atPath: pattern) {
            return NSWorkspace.shared.icon(forFile: pattern)
        }
        return NSImage(systemSymbolName: "terminal", accessibilityDescription: nil) ?? NSImage()
    }

    /// The entry for a process name from the Connections page (lsof's
    /// command name), matched against what is running now.
    static func matching(process: String, in candidates: [EgressAppCandidate]) -> EgressAppCandidate? {
        candidates.first { $0.name == process || ($0.pattern as NSString).lastPathComponent == process }
            ?? candidates.first { process.hasPrefix($0.name) || $0.name.hasPrefix(process) }
    }
}

extension EgressProtection.Group {
    var appNames: [String] { apps.map(EgressApps.displayName) }
}
