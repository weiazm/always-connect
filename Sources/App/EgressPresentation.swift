import Foundation
import Network

extension EgressProtection.Method {
    static let thirdPartyCaption = "第三方查询点：仅供参考，不参与放行或拦截"
    var scopeCaption: String { isDirect ? "直接检查网站" : Self.thirdPartyCaption }

    static func preferredDirectMethod(_ methods: [Self], observations: [EgressProtection.Observation]) -> String? {
        methods.first { method in
            method.isDirect && observations.contains { $0.method == method.id && $0.country != nil }
        }?.id
    }
}

extension EgressProtection {
    enum BlockReason: String {
        case noDirectMethod = "no-direct-method"
        case failedTargetOverflow = "failed-target-overflow"

        var caption: String {
            switch self {
            case .noDirectMethod: return "无法核实网站本身的出口，已拦截这组新连接"
            case .failedTargetOverflow: return "失败地址过多，已拦截这组新连接"
            }
        }
    }

    struct BlockedGroupNotice: Identifiable, Equatable {
        let id: UInt32
        let name: String
        let reason: BlockReason
    }

    enum Evidence: String, CaseIterable {
        case direct, proxy, member, unknown
        case thirdParty = "third-party"

        var caption: String {
            switch self {
            case .direct: return "直接观测（同名、固定目的地址）"
            case .proxy: return "按借用身份查到（代理观测）"
            case .thirdParty: return Method.thirdPartyCaption
            case .member: return "按网站名查询（组内成员）"
            case .unknown: return "来源未记录"
            }
        }
    }

    /// An action from a notification may only expand the countries of the
    /// same currently blocked direct targets.
    struct DirectTargetObservation: Hashable {
        let host: String
        let address: String
        let method: String
        let country: String
    }

    static func directFailures(_ observations: [Observation], expected: [String]) -> Set<DirectTargetObservation>? {
        let failed = observations.filter { $0.evidenceKind != .thirdParty && $0.isOutside(expected) }
        guard !failed.isEmpty else { return nil }
        let direct = failed.compactMap(\.directTarget)
        return direct.count == failed.count ? Set(direct) : nil
    }
}

extension EgressProtection.Observation {
    var evidenceKind: EgressProtection.Evidence {
        evidence.flatMap(EgressProtection.Evidence.init(rawValue:)) ?? .unknown
    }

    private var countryAndAddress: String {
        guard let country else { return "未查到" }
        return country + (ip.map { "（出口 IP \($0)）" } ?? "")
    }

    var observationCaption: String {
        let address = peerAddress.map { "（目的地址 \($0)）" } ?? ""
        return "\(host)\(address)：\(countryAndAddress) · \(evidenceKind.caption)"
    }

    func isOutside(_ expected: [String]) -> Bool {
        guard let country else { return true }
        return !expected.contains { $0.caseInsensitiveCompare(country) == .orderedSame }
    }

    fileprivate var directTarget: EgressProtection.DirectTargetObservation? {
        guard evidenceKind == .direct, let country, let address = peerAddress,
              IPv4Address(address) != nil || IPv6Address(address) != nil,
              country.utf8.count == 2, country.utf8.allSatisfy({ (65...90).contains($0) }) else { return nil }
        return .init(host: host, address: address, method: method, country: country)
    }
}

extension EgressProtection.GroupState {
    var blockReason: EgressProtection.BlockReason? {
        reason.flatMap(EgressProtection.BlockReason.init(rawValue:))
    }

    var blockCaption: String? {
        guard blocked else { return nil }
        return blockReason?.caption ?? "部分地址出口未通过，已拦截相关新连接"
    }
}

extension EgressProtection.Status {
    var blockingNotices: [EgressProtection.BlockedGroupNotice] {
        groups.compactMap { group in
            guard group.blocked, let reason = group.blockReason else { return nil }
            return .init(id: group.id, name: group.name, reason: reason)
        }
    }
}

extension EgressProtection.BlockRecord {
    func directFailures() -> Set<EgressProtection.DirectTargetObservation>? {
        EgressProtection.directFailures(observed, expected: expected)
    }

    func directTargetsToTrust(current: EgressProtection.GroupState) -> Set<EgressProtection.DirectTargetObservation>? {
        guard ended == nil, current.id == group, current.blocked, current.reason == nil,
              let failures = directFailures(),
              failures == EgressProtection.directFailures(current.observed, expected: expected) else { return nil }
        return failures
    }

    var evidenceSummary: String {
        let counts = Dictionary(grouping: observed, by: \.evidenceKind).mapValues(\.count)
        return EgressProtection.Evidence.allCases.compactMap { evidence in
            counts[evidence].map { "\(evidence.rawValue)=\($0)" }
        }.joined(separator: "，")
    }
}
