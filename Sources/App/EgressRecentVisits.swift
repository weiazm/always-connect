import Foundation
import SwiftUI

/// Settings-process only. Reuses the Connections page's existing samples,
/// keeps a bounded set in memory and disappears with the Settings window.
final class EgressRecentVisits: ObservableObject {
    static let shared = EgressRecentVisits()
    struct Visit: Hashable {
        let host: String
        let process: String
        let firstSeen: Date
        let lastSeen: Date
    }
    private struct Key: Hashable {
        let host: String
        let process: String
    }
    @Published private(set) var visits: [Visit] = []
    private var present = Set<Key>()

    func record(_ rows: [ConnectionRow], at now: Date = Date()) {
        let old = Dictionary(uniqueKeysWithValues: visits.map { (Key(host: $0.host, process: $0.process), $0) })
        let observed = Set(rows.compactMap { row -> Key? in
            guard row.via == "vpn", let host = row.host,
                  let scope = EgressWebsiteScope(host, includesSubdomains: false) else { return nil }
            return Key(host: scope.host, process: row.process)
        })
        let current = observed.map { key in
            Visit(host: key.host, process: key.process, firstSeen: present.contains(key) ? old[key]?.firstSeen ?? now : now,
                  lastSeen: now)
        }
        let recent = current + visits.filter { !observed.contains(Key(host: $0.host, process: $0.process)) }
        visits = Array(recent.sorted {
            $0.lastSeen == $1.lastSeen ? ($0.host, $0.process) < ($1.host, $1.process) : $0.lastSeen > $1.lastSeen
        }.prefix(128))
        present = Set(visits.map { Key(host: $0.host, process: $0.process) }).intersection(observed)
    }

    func recentSites(config: EgressProtection, direct: [DirectSite]) -> [String] {
        eligible(visits, config: config, direct: direct, limit: 8)
    }

    func recommendations(for source: [Visit], config: EgressProtection, direct: [DirectSite]) -> [String] {
        let related = visits.filter { visit in
            source.contains {
                visit.process == $0.process && abs(visit.firstSeen.timeIntervalSince($0.firstSeen)) <= 10
            }
        }
        return eligible(related, config: config, direct: direct, limit: 5)
    }

    private func eligible(_ candidates: [Visit], config: EgressProtection, direct: [DirectSite], limit: Int) -> [String] {
        var sites = Set<String>()
        var eligible: [String] = []
        for visit in candidates {
            let host = visit.host
            guard config.rule(covering: host) == nil, DirectSites.covering(direct, host: host, address: "") == nil,
                  sites.insert(DirectSites.site(of: host)).inserted else { continue }
            eligible.append(host)
            if eligible.count == limit { break }
        }
        return eligible
    }
}
