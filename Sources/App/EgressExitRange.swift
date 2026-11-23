import Foundation
import Network

/// A display choice derived from one observed exit address. The background
/// service owns CIDR validation and the decision to accept an approval.
struct EgressExitAddress: Hashable, Identifiable {
    let address: String
    let single: String
    let subnet: String
    let isIPv6: Bool

    var id: String { address }

    init?(_ text: String) {
        guard !text.contains("%") else { return nil }
        if let ip = IPv4Address(text) {
            let prefix = Data(Array(ip.rawValue.prefix(3)) + [UInt8(0)])
            guard let network = IPv4Address(prefix) else { return nil }
            address = String(describing: ip)
            single = address + "/32"
            subnet = "\(network)/24"
            isIPv6 = false
        } else if let ip = IPv6Address(text) {
            let prefix = Data(Array(ip.rawValue.prefix(8)) + Array(repeating: UInt8(0), count: 8))
            guard let network = IPv6Address(prefix) else { return nil }
            address = String(describing: ip)
            single = address + "/128"
            subnet = "\(network)/64"
            isIPv6 = true
        } else {
            return nil
        }
    }

    func permitsChoice(_ range: String) -> Bool { range == single || range == subnet }
}

struct EgressExitRangeSuggestions: Equatable {
    let addresses: [EgressExitAddress]

    init(addresses: [EgressExitAddress]) {
        self.addresses = Set(addresses).sorted { $0.address < $1.address }
    }

    var recommended: [String] { Set(addresses.map { $0.isIPv6 ? $0.single : $0.subnet }).sorted() }

    func canConfirm(_ selected: Set<String>) -> Bool {
        !selected.isEmpty && selected.allSatisfy { range in addresses.contains { $0.permitsChoice(range) } }
    }

    static func from(_ results: [String: EgressProtection.SetupProbe], allowedCountries: [String],
                     config: EgressProtection) -> Self {
        let addresses = results.flatMap { (host, result) -> [EgressExitAddress] in
            guard host == result.host, result.status == "ok", config.method(result.method)?.isDirect == true else { return [] }
            return result.results.prefix(8).compactMap { row in
                guard row.status == "ok", row.method == result.method,
                      let country = row.country, allowedCountries.contains(country),
                      IPv4Address(row.address) != nil || IPv6Address(row.address) != nil,
                      let ip = row.exitIP else { return nil }
                return EgressExitAddress(ip)
            }
        }
        return Self(addresses: addresses)
    }
}

struct EgressExitRangeOffer: Identifiable, Equatable {
    let host: String
    let proof: String
    let suggestions: EgressExitRangeSuggestions
    var id: String { proof }

    static func from(_ results: [String: EgressProtection.SetupProbe], countries: [String],
                     config: EgressProtection) -> [Self] {
        results.sorted { $0.key < $1.key }.compactMap { host, result in
            guard let proof = result.proofId, !proof.isEmpty else { return nil }
            let suggestions = EgressExitRangeSuggestions.from([host: result], allowedCountries: countries, config: config)
            guard !suggestions.addresses.isEmpty else { return nil }
            return Self(host: host, proof: proof, suggestions: suggestions)
        }
    }
}

struct EgressExitRangeSelection: Equatable {
    let proof: String
    var ranges: Set<String>

    func verified(in offers: [EgressExitRangeOffer]) -> Bool {
        offers.first { $0.proof == proof }?.suggestions.canConfirm(ranges) == true
    }
}

struct EgressExitRangeSetup: Codable {
    let proposed: EgressProtection
    let previous: EgressProtection
    let group: UInt32
    let proof: String

    init?(proposed: EgressProtection, previous: EgressProtection, group: UInt32, selection: EgressExitRangeSelection,
          offers: [EgressExitRangeOffer]) {
        guard selection.verified(in: offers),
              let index = proposed.groups.firstIndex(where: { $0.id == group && $0.enabled }) else { return nil }
        var candidate = proposed
        candidate.groups[index].exitRangeCheck = true
        candidate.groups[index].exitRanges = selection.ranges.sorted()
        self.proposed = candidate
        self.previous = previous
        self.group = group
        proof = selection.proof
    }

    func applying(accepted: Bool?, now current: EgressProtection, sameSession: Bool) -> EgressProtection? {
        guard accepted == true, sameSession, current == previous else { return nil }
        return proposed
    }
}

struct EgressExitRangeApproval: Codable, Equatable, Identifiable {
    let group: UInt32
    let started: Double
    let observation: EgressProtection.Observation
    let cidr: String
    var id: String { "\(group):\(started):\(observation.host):\(observation.peerAddress ?? ""):\(cidr)" }

    func applying(_ ranges: [String]?, then stored: EgressProtection, now current: EgressProtection,
                  sameSession: Bool) -> EgressProtection? {
        guard sameSession, current.enabled, current.methods == stored.methods,
              let rule = stored.groups.first(where: { $0.id == group && $0.enabled && $0.exitRangeCheck }),
              let ranges, Set(ranges).count == ranges.count, Set(ranges) == Set(rule.exitRanges + [cidr]),
              let index = current.groups.firstIndex(of: rule) else { return nil }
        var updated = current
        updated.groups[index].exitRanges = ranges
        return updated
    }
}

extension EgressProtection.Observation {
    fileprivate var provableExitAddress: EgressExitAddress? {
        guard failureReason == "exit-range-mismatch", evidenceKind == .direct,
              let approvalId, !approvalId.isEmpty,
              let peerAddress, IPv4Address(peerAddress) != nil || IPv6Address(peerAddress) != nil,
              let ip else { return nil }
        return EgressExitAddress(ip)
    }

    fileprivate func matchesRangeProof(_ current: Self) -> Bool {
        provableExitAddress != nil && host == current.host && method == current.method && peerAddress == current.peerAddress
            && country == current.country && ip == current.ip && approvalId == current.approvalId
            && current.provableExitAddress != nil
    }
}

extension EgressProtection.Status {
    struct ExitChange: Identifiable {
        let group: UInt32
        let started: Double
        let observation: EgressProtection.Observation
        let exit: EgressExitAddress

        var id: String { approval(for: exit.single).id }
        func approval(for cidr: String) -> EgressExitRangeApproval {
            .init(group: group, started: started, observation: observation, cidr: cidr)
        }
    }

    func exitChanges(for rule: EgressProtection.Group) -> [ExitChange] {
        guard running, rule.enabled, rule.exitRangeCheck,
              let current = groups.first(where: { $0.id == rule.id && $0.blocked && $0.reason == nil }),
              let record = records.first(where: { $0.group == rule.id && $0.ended == nil })
        else { return [] }
        var seen = Set<String>()
        return current.observed.compactMap { obs in
            guard let exit = obs.provableExitAddress, let country = obs.country, rule.expect.contains(country),
                  !rule.exitRanges.contains(exit.single), !rule.exitRanges.contains(exit.subnet) else { return nil }
            let change = ExitChange(group: rule.id, started: record.started, observation: obs, exit: exit)
            return seen.insert(change.id).inserted ? change : nil
        }
    }

    func permits(_ approval: EgressExitRangeApproval, in config: EgressProtection) -> Bool {
        guard config.enabled,
              let rule = config.groups.first(where: { $0.id == approval.group }),
              config.directMembers(in: rule).contains(where: { member in
                  member.method == approval.observation.method && member.matchesSite(approval.observation.host)
              }) else { return false }
        return exitChanges(for: rule).contains {
            $0.started == approval.started && approval.observation.matchesRangeProof($0.observation)
                && $0.exit.permitsChoice(approval.cidr)
        }
    }
}
