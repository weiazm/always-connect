import Foundation

struct EgressProtection: Codable, Equatable {
    var enabled = false
    var groups: [Group] = []
    var methods: [Method] = []

    var isActive: Bool { enabled && groups.contains(where: \.enabled) }

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
        var concreteHost: String? { probeHost ?? (pattern.hasPrefix("*.") || pattern.hasPrefix("geosite:") ? nil : pattern) }
    }

    struct Method: Codable, Equatable, Identifiable {
        var id: String
        var name: String
        var url: String
        var head = false
        var extract: Extract

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
        var blocked: Bool { state == "blocked" }
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
