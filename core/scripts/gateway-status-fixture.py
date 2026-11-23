"""Exercise the production App's status bindings without its installed service or keychain."""
from pathlib import Path
import sys

repo, output = map(Path, sys.argv[1:])
source = (repo/'Sources/App/HelperClient.swift').read_text()

def declaration(prefix):
    start = source.index(prefix)
    opening = source.index('{', start)
    level = 1
    end = opening + 1
    while level:
        level += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end].removeprefix('private ')

members = [
    'enum State: Int', 'var ownLoginProgressText: String?', 'var stateLine: String', 'var showsConnected: Bool',
    'var certificateProtectionText: String', 'private func showGatewayRejection()',
    'private func observeRelayTrust(', 'private func confirmRelayRecovery()',
    'private func updateCiscoTrust(',
]
output.write_text('''import Foundation
struct ProfileStore {
    struct Profile { var server = "gateway.example" }
    static func loadProfile() -> Profile { Profile() }
}
final class Notifier {
    static let shared = Notifier()
    var failures = 0
    func notifyGatewayCertificateFailure() { failures += 1 }
}
final class Service {
    var rejections: [(UInt64, (Bool) -> Void)] = []
    var recoveries: [(UInt64, (Bool) -> Void)] = []
    func recordGatewayRejection(_ pin: String, incident: UInt64, withReply: @escaping (Bool) -> Void) {
        rejections.append((incident, withReply))
    }
    func hasVerifiedRelayTunnel(_ pin: String, incident: UInt64, withReply: @escaping (Bool) -> Void) {
        recoveries.append((incident, withReply))
    }
}
final class HelperClient {
    let service = Service()
    var state = State.connected
    var detail = ""
    var hasCredentials = true
    var onDemandPaused = false
    var onDemandRuleName: String?
    var usesCisco = false
    var dropRetryCount = 0
    var networkHeld = false
    var protectsDrops = true
    var loginProtectionNotice: String?
    var gatewayTrustFailed = false
    var rejectedLoginHeld = false
    var relayIncident: UInt64 = 0
    var revalidatedRelayPin: String?
    var pendingRecovery: UInt64?
    var awaitingCiscoStart = false
    var relayGeneration = 1
    var connectedSince: Date?
    var sessionProven = true
    func startConnectionCheck() {}
    func egressRPC(_ call: (Service, @escaping (Bool) -> Void) -> Void, completion: @escaping (Bool?) -> Void) {
        call(service) { completion($0) }
    }
''' + '\n'.join(declaration(m) for m in members) + '\n}\n')
