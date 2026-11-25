import Foundation

/// Exit protection (DESIGN §66.25): for each rule, the sites to protect
/// (with subdomains) and the countries their connections may leave from.
struct EgressProtection: Codable, Equatable {
    var enabled = false
    var groups: [Group] = []
    /// How many of the busiest servers are re-checked in the background
    /// (DESIGN §66.31); nil = 5, 0 = off, at most 20.
    var prefetch: Int? = nil
    /// Steer protected names to an entry with a verified exit (§66.28);
    /// nil = on.
    var steer: Bool? = nil

    static let defaultPrefetch = 5
    static let maxPrefetch = 20

    var isActive: Bool { enabled && groups.contains { $0.enabled && !$0.sites.isEmpty } }

    @discardableResult
    mutating func disableGroup(_ id: UInt32) -> Bool {
        guard let index = groups.firstIndex(where: { $0.id == id && $0.enabled }) else { return false }
        groups[index].enabled = false
        return true
    }

    /// An enabled rule needs a site and an allowed country.
    func permitsActivation(comparedTo previous: Self) -> Bool {
        guard enabled else { return true }
        return groups.allSatisfy { group in
            !group.enabled || (!group.sites.isEmpty && !group.expect.isEmpty)
                || (previous.enabled && previous.groups.contains { $0.id == group.id && $0.enabled })
        }
    }

    enum Unverified: String, Codable, CaseIterable, Identifiable {
        case allow, whenWrong, block
        var id: Self { self }
    }

    struct Group: Codable, Equatable, Identifiable {
        var id: UInt32
        var name: String
        var enabled = false
        /// Canonical split-list entries.
        var sites: [String] = []
        /// Allowed exit countries (ISO 3166 alpha-2).
        var expect: [String] = []
        var unverified: Unverified = .whenWrong
        /// Transient expanded entries, sent only to the background service.
        var matches: [String]? = nil
    }

    var withoutExpandedMatches: Self {
        var result = self
        for index in result.groups.indices { result.groups[index].matches = nil }
        return result
    }

    /// What one check saw for one site at one server.
    struct Observation: Codable, Equatable, Identifiable {
        let host: String
        let country: String?
        let ip: String?
        let error: String?
        var peerAddress: String? = nil
        /// Set on a wrong-country observation the user may approve.
        var approvalId: String? = nil
        var displayedHost: String { host.isEmpty ? (peerAddress ?? "无网站名") : host }
        var id: String { host + " " + (peerAddress ?? "") }
    }

    struct Status: Decodable {
        let running: Bool
        let checking: [UInt32]
        let groups: [GroupState]
        let records: [BlockRecord]
    }

    /// A rule's state: "ok", "blocked" (some servers exit from a wrong
    /// country; only those are blocked) or "unknown". While blocked,
    /// `observed` lists those servers.
    struct GroupState: Decodable, Identifiable {
        let id: UInt32
        let name: String
        let state: String
        let lastCheck: Double
        let observed: [Observation]
        var blockedCount: UInt64? = nil
        var unverifiedCount: UInt64? = nil
        /// Names answered with another entry of their CDN whose exit was
        /// verified (DESIGN §66.28).
        var steered: [String]? = nil
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

extension EgressProtection.Group {
    private enum LegacyKeys: String, CodingKey { case members }
    private struct LegacyMember: Decodable { let pattern: String }

    /// Rules saved before §66.25 listed website members ("example.com",
    /// "*.example.com", "geosite:…"); they become the sites they named.
    init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        id = try values.decode(UInt32.self, forKey: .id)
        name = try values.decode(String.self, forKey: .name)
        enabled = try values.decodeIfPresent(Bool.self, forKey: .enabled) ?? false
        unverified = try values.decodeIfPresent(EgressProtection.Unverified.self, forKey: .unverified) ?? .whenWrong
        matches = try values.decodeIfPresent([String].self, forKey: .matches)
        expect = try values.decodeIfPresent([String].self, forKey: .expect) ?? []
        var sites = try values.decodeIfPresent([String].self, forKey: .sites) ?? []
        if sites.isEmpty {
            let legacy = try decoder.container(keyedBy: LegacyKeys.self)
            let members = (try? legacy.decodeIfPresent([LegacyMember].self, forKey: .members)) ?? nil
            for member in members ?? [] {
                let site = member.pattern.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
                    .replacingOccurrences(of: "*.", with: "").trimmingCharacters(in: CharacterSet(charactersIn: "."))
                if !site.isEmpty, !site.contains(":"), site.contains("."), !sites.contains(site) { sites.append(site) }
            }
        }
        self.sites = sites
    }
}
