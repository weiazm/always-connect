import Foundation

struct EgressProtection: Codable, Equatable {
    var enabled = false
    var groups: [Group] = []
    var methods: [Method] = []

    var isActive: Bool { enabled && groups.contains(where: \.enabled) }

    var availableMethods: [Method] {
        Method.presets.map { method($0.id) ?? $0 }
            + methods.filter { item in !Method.presets.contains { $0.id == item.id } }
    }

    func method(_ id: String?) -> Method? {
        guard let id else { return nil }
        return methods.first { $0.id == id } ?? Method.presets.first { $0.id == id }
    }

    func directMembers(in group: Group) -> [Member] {
        group.members.filter { $0.concreteHost != nil && method($0.method)?.isDirect == true }
    }

    @discardableResult
    mutating func disableGroup(_ id: UInt32) -> Bool {
        guard let index = groups.firstIndex(where: { $0.id == id && $0.enabled }) else { return false }
        groups[index].enabled = false
        return true
    }

    /// Existing active groups stay armed when an edit removes their last direct method.
    /// Turning protection on, or enabling an additional group, requires a direct method.
    func permitsActivation(comparedTo previous: Self) -> Bool {
        guard enabled else { return true }
        return groups.allSatisfy { group in
            !group.enabled || !directMembers(in: group).isEmpty
                || (previous.enabled && previous.groups.contains { $0.id == group.id && $0.enabled })
        }
    }

    struct Group: Codable, Equatable, Identifiable {
        var id: UInt32
        var name: String
        var enabled = false
        var members: [Member] = []
        var cidrs: [String] = []
        var expect: [String] = []
    }

    struct Member: Codable, Equatable, Identifiable {
        var pattern: String
        var method: String?
        var probeHost: String?
        var id: String { pattern }
        var concreteHost: String? {
            let name = pattern.trimmingCharacters(in: .whitespacesAndNewlines)
            guard name.hasPrefix("*.") else { return Self.validHost(name) ? name : nil }
            guard let probeHost, Self.validHost(probeHost), matchesSite(probeHost) else { return nil }
            return probeHost
        }

        func matchesSite(_ host: String) -> Bool {
            let dots = CharacterSet(charactersIn: ".")
            let name = pattern.trimmingCharacters(in: .whitespacesAndNewlines)
                .lowercased().trimmingCharacters(in: dots)
            let target = host.lowercased().trimmingCharacters(in: dots)
            return name.hasPrefix("*.") ? target.hasSuffix(String(name.dropFirst())) : target == name
        }

        private static func validHost(_ host: String) -> Bool {
            let name = host.last == "." ? host.dropLast() : host[...]
            return host.utf8.count <= 253 && !name.isEmpty
                && name.split(separator: ".", omittingEmptySubsequences: false).allSatisfy { label in
                    !label.isEmpty && label.utf8.count <= 63 && label.utf8.allSatisfy {
                        (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || $0 == 45
                    }
                }
        }
    }

    struct Method: Codable, Equatable, Identifiable {
        var id: String
        var name: String
        var url: String
        var head = false
        var extract: Extract

        var isDirect: Bool {
            guard url.hasPrefix("https://") else { return false }
            let authority = url.dropFirst("https://".count).prefix { $0 != "/" }
            if authority == "{host}" { return true }
            guard authority.hasPrefix("{host}:"),
                  let port = UInt16(authority.dropFirst("{host}:".count)) else { return false }
            return port != 0
        }

        static let presets = [
            Self(id: "trace", name: "网站自己的检测地址", url: "https://{host}/cdn-cgi/trace",
                 extract: .init(kind: .kv, key: "loc")),
            Self(id: "cdn-node", name: "CDN 节点（近似）", url: "https://{host}/", head: true,
                 extract: .init(kind: .header, key: "cf-ray,x-amz-cf-pop,x-served-by")),
        ]
    }

    struct Extract: Codable, Equatable {
        enum Kind: String, Codable, CaseIterable { case kv, json, header }
        var kind: Kind
        var key: String
        var regex: String?
    }

    struct Observation: Codable, Equatable, Identifiable {
        let host: String
        let method: String
        let country: String?
        let ip: String?
        let error: String?
        var evidence: String? = nil
        var peerAddress: String? = nil
        var id: String { method }
    }

    struct Status: Decodable {
        let running: Bool
        let checking: [UInt32]
        let groups: [GroupState]
        let records: [BlockRecord]
    }

    struct GroupState: Decodable, Identifiable {
        let id: UInt32
        let name: String
        let state: String
        let lastCheck: Double
        let observed: [Observation]
        var reason: String? = nil
        var level: String? = nil
        var blockedCount: UInt64? = nil
        var lastBlockedHost: String? = nil
        var lastBlockedCountry: String? = nil
        var sites: [SiteState]? = nil
        var blocked: Bool { state == "blocked" }
    }

    struct SiteState: Decodable, Identifiable {
        let host: String
        let state: String
        let lastCheck: Double
        let country: String?
        let blockedCount: UInt64
        var id: String { host }
    }

    struct SetupProbe: Decodable {
        struct Result: Decodable {
            let address: String
            let method: String
            let status: String
            let country: String?
            let error: String?
        }
        let host: String
        let method: String
        let status: String
        let error: String?
        let resolvedAddressCount: Int
        let probedAddressCount: Int
        let truncated: Bool
        let coverageIncomplete: Bool
        let results: [Result]
    }

    struct BlockRecord: Decodable {
        let started: Double
        let ended: Double?
        let group: UInt32
        let name: String
        let host: String?
        let observed: [Observation]
        let expected: [String]
    }
}
