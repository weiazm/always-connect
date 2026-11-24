import Foundation

/// What can be added to exit protection right now: the VPN connections
/// of each program, merged by website, plus bare addresses for programs
/// that never looked a name up. Built from one connection snapshot and
/// the Connections page's bounded recent visits; nothing is sampled for it.
struct EgressCandidate: Identifiable, Hashable {
    enum Kind: Hashable { case website(String), address(String) }
    let kind: Kind
    /// Hosts seen under this website, most recent first.
    let examples: [String]
    var id: String {
        switch kind {
        case .website(let site): return "w:" + site
        case .address(let ip): return "a:" + ip
        }
    }
    var host: String? { if case .website = kind { return examples.first }; return nil }
    var address: String? { if case .address(let ip) = kind { return ip }; return nil }
    var name: String {
        switch kind {
        case .website(let site): return site
        case .address(let ip): return ip
        }
    }
}

struct EgressProgramGroup: Identifiable, Hashable {
    let process: String
    var items: [EgressCandidate]
    var id: String { process }
}

enum EgressCandidates {
    static func grouped(_ rows: [ConnectionRow], recent: [EgressRecentVisits.Visit] = [],
                        config: EgressProtection, direct: [DirectSite], focus: String? = nil) -> [EgressProgramGroup] {
        var sites: [String: [String: [String]]] = [:]
        var addresses: [String: Set<String>] = [:]
        let covered = Set(config.groups.flatMap(\.cidrs))
        let seen = rows.map { ($0.process, $0.host, $0.remote, $0.via) }
            + recent.map { ($0.process, Optional($0.host), "", "vpn") }
        for (process, host, remote, via) in seen where via == "vpn" {
            if let host, let scope = EgressWebsiteScope(host, includesSubdomains: true) {
                guard config.rule(covering: scope.host) == nil,
                      DirectSites.covering(direct, host: scope.host, address: remote) == nil else { continue }
                var hosts = sites[process, default: [:]][scope.website, default: []]
                if !hosts.contains(scope.host) { hosts.append(scope.host) }
                sites[process, default: [:]][scope.website] = hosts
            } else if host == nil, isPublicIPv4(remote), !covered.contains(remote + "/32"),
                      DirectSites.covering(direct, host: nil, address: remote) == nil {
                addresses[process, default: []].insert(remote)
            }
        }
        let processes = Set(sites.keys).union(addresses.keys)
        let groups = processes.map { process -> EgressProgramGroup in
            let named = (sites[process] ?? [:]).map { site, hosts in
                // Probe the site itself when it was seen, else its busiest name.
                EgressCandidate(kind: .website(site), examples: hosts.contains(site) ? [site] + hosts.filter { $0 != site } : hosts)
            }.sorted { ($0.examples.count, $1.name) > ($1.examples.count, $0.name) }
            let bare = (addresses[process] ?? []).sorted().map { EgressCandidate(kind: .address($0), examples: [$0]) }
            return .init(process: process, items: named + bare)
        }
        return groups.sorted { left, right in
            if (left.process == focus) != (right.process == focus) { return left.process == focus }
            return (left.items.count, right.process) > (right.items.count, left.process)
        }
    }

    static func isPublicIPv4(_ text: String) -> Bool {
        let parts = text.split(separator: ".").compactMap { UInt8($0) }
        guard parts.count == 4, text.split(separator: ".").count == 4 else { return false }
        switch (parts[0], parts[1]) {
        case (10, _), (127, _), (0, _), (169, 254), (192, 168): return false
        case (172, 16...31), (100, 64...127): return false
        default: return parts[0] < 224
        }
    }
}
