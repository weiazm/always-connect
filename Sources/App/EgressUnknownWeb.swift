import Foundation
import Network

/// The destination displayed before a user confirms an exception. Both
/// address families are shown without allowing a range or a port list.
struct EgressUnknownWebEndpoint: Codable, Hashable, Identifiable {
    let address: String
    let port: UInt16

    var id: String { label }
    var label: String { address.contains(":") ? "[\(address)]:\(port)" : "\(address):\(port)" }
    var isExactWebDestination: Bool {
        [80, 443, 8443].contains(port) && !address.contains("%")
            && (IPv4Address(address) != nil || IPv6Address(address) != nil)
    }
}

enum EgressUnknownWebText {
    static func count(_ count: UInt64) -> String {
        "本次已记录 \(count) 条被拦的无名网页连接"
    }

    static let turnOff = "关闭后，认不出网站的公网网页连接将不再被这项保护拦截。受保护网站仍按各自的规则检查。"

    static func allow(_ endpoint: EgressUnknownWebEndpoint) -> String {
        "只为 \(endpoint.label) 跳过认不出网站的连接拦截。此地址上的受保护网站仍按原规则检查。"
    }

    static func revoke(_ endpoint: EgressUnknownWebEndpoint) -> String {
        "撤回 \(endpoint.label) 的例外。下次认不出网站时，这个地址和端口将重新按拦截设置处理。"
    }

    static let rejected = "未能确认修改。请查看刷新后的后台状态。"
}

struct EgressUnknownWebChange: Codable, Equatable {
    let endpoint: EgressUnknownWebEndpoint
    let allow: Bool
    let approvalId: String
}

extension EgressProtection.UnknownWebRecord {
    var endpoint: EgressUnknownWebEndpoint { .init(address: address, port: port) }

    var change: EgressUnknownWebChange? {
        guard count > 0, endpoint.isExactWebDestination, let approvalId, !approvalId.isEmpty else { return nil }
        return .init(endpoint: endpoint, allow: !allowed, approvalId: approvalId)
    }
}

extension EgressProtection.Status {
    func permits(_ request: EgressUnknownWebChange, config: EgressProtection) -> Bool {
        guard running, config.isActive, !request.allow || config.blocksUnidentifiedWeb,
              let rows = unknownWeb else { return false }
        let matches = rows.filter { $0.endpoint == request.endpoint }
        return matches.count == 1 && matches.first?.change == request
    }

    func applied(_ request: EgressUnknownWebChange) -> Bool {
        guard running, let rows = unknownWeb else { return false }
        let matches = rows.filter { $0.endpoint == request.endpoint }
        return matches.count == 1 && matches.first?.allowed == request.allow
    }
}
