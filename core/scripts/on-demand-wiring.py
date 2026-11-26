#!/usr/bin/env python3
"""Compile real HelperClient I/O bindings against deterministic XPC/Cisco stubs.
Policy fault sequences live in Rust on_demand/runtime.rs, not duplicated here.
"""
from pathlib import Path
import sys
root, output = map(Path, sys.argv[1:])
source = (root / 'Sources/App/HelperClient.swift').read_text()
service = (root / 'Sources/Helper/HelperDaemon.swift').read_text()
def block(text, marker):
    start = text.index(marker)
    opening = text.index('{', start)
    if 'func ' in marker:
        paren = text.index('(', start)
        level = 0
        for at in range(paren, len(text)):
            level += (text[at] == '(') - (text[at] == ')')
            if level == 0:
                opening = text.index('{', at + 1)
                break
    depth = 0
    for end in range(opening, len(text)):
        if text[end] == '{':
            depth += 1
        elif text[end] == '}':
            depth -= 1
            if depth == 0:
                return text[start:end + 1]
    raise ValueError(marker)

methods = [
    'private func setupOnDemandDisconnection()', 'private func verifyOnDemandIdle(',
    'func connectWithStoredCredentials(', 'private func startStoredConnection(', 'func disconnect(\n', 'private func watchRestore(',
    'func onDemandSettingsChanged()', 'func prepareForForcedRestore()',
    'func forcedRestoreAbandoned()', 'func forcedRestoreDone()', 'func disconnectByUser()', 'private func setKillSwitch(', 'func setConnectionMode(',
    'private var mayPrepareLoginGateway:', 'private func resetGatewayPreparation(', 'func expireGatewayPreparation()',
    'func prepareGatewayForConnection(',
    'func prepareGatewayWhileDirect(', 'private func isGatewayPreparationCurrent(', 'private func prepareUncachedGateway(',
    'private func watchLogin(', 'private var loginAwaitsEngine:', 'private func loginStepFailed('
]
body = '\n'.join(block(source, marker).replace('private func ', 'func ', 1) for marker in methods)
# The ordering fixtures use a synthetic engine start. Entry fixtures opt in to the complete production method.
body = body.replace('func startStoredConnection(allowLookup:', 'func exerciseStoredConnection(allowLookup:', 1)
readiness = block((root / 'Sources/App/LoginGatewayPreparation.swift').read_text(), 'enum LoginGatewayReadiness')
panel_action = block((root / 'Sources/App/PanelAndSettings.swift').read_text(), 'private var primaryButton:')
assert 'manager.loginGatewayReadiness' not in panel_action
assert 'onStart()' in panel_action and 'ProtectedLoginNotice.preparingGateway' in panel_action
assert 'Button(preparing ? "取消连接"' in panel_action and 'onStop()' in panel_action
callbacks = '\n'.join(block(source, marker) for marker in [
    'onDemand.disconnect =', 'onDemand.waiting =', 'onDemand.connect =', 'onDemand.connectAtLaunch =',
    'onDemand.stopUser =', 'onDemand.recheck =', 'onDemand.changed =', 'onDemand.refreshService ='])
view = (root / 'Sources/App/OnDemandSettings.swift').read_text()
editor = view[view.index('private struct OnDemandRuleEditor'):]
fill_methods = '\n'.join(block(editor, marker).replace('private func ', 'func ', 1) for marker in [
    'private func fillCurrentNetwork()', 'private func stopFill()', 'private func values('])
fill_methods = fill_methods.replace('monitor.pathUpdateHandler = { path in', 'monitor.pathUpdateHandler = { [self] path in')
fill_methods = fill_methods.replace('DispatchQueue.main.async {', 'DispatchQueue.main.async { [self] in')
fill_methods = fill_methods.replace('deadline: .now() + 3) {', 'deadline: .now() + 3) { [self] in')
disappear = block(view, '.onDisappear')[len('.onDisappear'):].replace('{', '{ [self] in', 1)

service_protection = block(service, 'func setKillSwitch(')

fixture = r'''
import Foundation
struct DispatchQueue {
    init(label: String) {}
    static let main = Queue()
    static func global(qos: DispatchQoS.QoSClass) -> Queue { main }
}
final class Queue {
    var timers: [() -> Void] = []
    func async(execute: () -> Void) { execute() }
    func asyncAfter(deadline: DispatchTime, execute: @escaping () -> Void) { timers.append(execute) }
}
struct AppRole { static let isSettings = false }
enum RelayLog { static var lines: [String] = []; static func write(_ line: String) { lines.append(line) } }
final class SettingsLink { static let shared = SettingsLink(); func send(_ action: String) {} }
struct Settings { var onDemandEnabled: Bool?; var onDemandRules: [OnDemandRule]?; var isDropProtectionOn = true; var connectionMode = "cisco" }
struct Profile { var server = "vpn-a.example" }
enum ProfileStore {
    static var settings = Settings(onDemandEnabled: true, onDemandRules: [])
    static var profile = Profile()
    static func loadAppSettings() -> Settings { settings }
    static func saveAppSettings(_ value: Settings) { settings = value }
    static func loadProfile() -> Profile { profile }
    static func loadUsername() -> String? { "fixture-user" }
}
enum HelperInstaller { static var installedHelperMatchesBundle = true }
struct Tracker { func noteUserStop() {} }
final class ServiceQueue {
    var blocked = false
    var pending: [() -> Void] = []
    func async(execute: @escaping () -> Void) { pending.append(execute); drain() }
    func drain() { while !blocked && !pending.isEmpty { pending.removeFirst()() } }
}
final class KillSwitch {
    enum Mode: Int { case off = 0, connected = 1, blocking = 2 }
    static let shared = KillSwitch()
    var held = false
    func set(mode: Mode, tunnelIf: String, gatewayIps: [String], reply: (Bool, String) -> Void) {
        held = mode != .off
        reply(true, "")
    }
}
enum CLIOrchestrator { static let defaultSupportDir = URL(fileURLWithPath: "/") }
enum LoginGatewayCache { static func rememberConnected(in dir: URL, target: String, peer: String) -> Bool { true } }
struct GatewayAddress: Equatable {
    let server: String
    init?(_ server: String) { self.server = server }
}
enum CiscoProfiles { static func resolve(_ name: String) -> String { name } }
var directRoute = true
func ac_login_direct_route() -> Bool { directRoute }
final class LoginGatewayPreparation {
    enum Status { case idle, preparing, ready, unavailable, certificateRejected, timedOut, dnsFailed }
    var phase: Status = .idle
    var checks = 0
    var ipv4Only = false
    var done: (() -> Void)?
    func status(for target: GatewayAddress) -> Status { phase }
    func confirmDirect() {}
    func prepareWhileDirect(_ target: GatewayAddress, ipv4Only: Bool, completion: @escaping () -> Void) -> Status {
        prepareWhileDirect(target, ipv4Only: ipv4Only, deadline: .now() + 2, completion: completion)
    }
    func prepareWhileDirect(_ target: GatewayAddress, ipv4Only: Bool, deadline: DispatchTime,
                            joinOnly: Bool = false, completion: @escaping () -> Void) -> Status {
        if joinOnly && phase != .preparing { return phase }
        guard DispatchTime.now() < deadline else { return .unavailable }
        self.ipv4Only = ipv4Only
        if phase == .ready { return .ready }
        if phase != .preparing { checks += 1 }
        phase = .preparing
        done = completion
        return phase
    }
    func takeResultForIntent(_ target: GatewayAddress?) -> (address: String?, certificateRejected: Bool) {
        let result = (phase == .ready ? "192.0.2.7" : nil, phase == .certificateRejected)
        cancel()
        return result
    }
    func cancel() { phase = .idle; done = nil }
}
LOGIN_GATEWAY_READINESS
PROTECTED_NOTICE
final class Service {
    static func log(_ detail: String) {}
    var preparedLogin: (target: String, gateways: [String], cisco: Bool)?
    let queue = ServiceQueue()
    var userReleased = true
    SERVER_PROTECTION_BODY
}
final class Resource {
    var pathUpdateHandler: (() -> Void)?
    var cancelled = false
    func cancel() { cancelled = true }
}
struct FactsReader { func watch(enabled: Bool) {} }
final class Relay {}
final class Cisco {
    var completion: (() -> Void)?
    var isManaging = true
    var rearms = 0
    func rearm() { rearms += 1 }
    func disconnect(completion: @escaping () -> Void) {
        isManaging = false
        self.completion = completion
    }
}
enum CiscoEngine {
    static var observedState = "Disconnected"
    struct Result { var status: Int32; var output: String }
    static func run(_ args: [String], timeout: TimeInterval) -> Result {
        precondition(args == ["state"] && timeout == 5)
        return Result(status: 0, output: observedState)
    }
    static func parseState(_ text: String) -> String? { text }
}
final class Proxy {
    var code = 1
    var held = false
    var cachedGateway = true
    var opens = 0
    var finishPeers: [String] = []
    func requestProtectedLogin(_ server: String, cisco: Bool, candidate: String, rejected: Bool,
                               allowPreparation: Bool, deadline: UInt64,
                               withReply reply: @escaping (UInt64, Bool, [String], String) -> Void) {
        opens += 1
        enqueue {
            if rejected { reply(0, false, [], ProtectedLoginNotice.noTrustedAddress) }
            else if self.cachedGateway || !candidate.isEmpty { reply(0, true, ["192.0.2.7"], "") }
            else if allowPreparation && !self.held { reply(1, false, [], "") }
            else { reply(0, false, [], ProtectedLoginNotice.preparationUnavailable) }
        }
    }
    func finishProtectedLogin(_ ticket: UInt64, candidate: String, withReply reply: @escaping (Bool, [String], String) -> Void) {
        finishPeers.append(candidate)
        held = true
        reply(!candidate.isEmpty, candidate.isEmpty ? [] : [candidate], candidate.isEmpty ? ProtectedLoginNotice.noTrustedAddress : "")
    }
    var blocked = false
    var dropsStatus = false
    var delayedStatus: [() -> Void] = []
    var queue: [() -> Void] = []
    var replies: [() -> Void] = []
    var calls: [String] = []
    func enqueue(_ work: @escaping () -> Void) { queue.append(work); drain() }
    func drain() { while !blocked && !queue.isEmpty { queue.removeFirst()() } }
    func disconnect(_ reply: @escaping () -> Void) {
        enqueue { self.calls.append("disconnect"); self.code = 0; self.held = false; self.replies.append(reply) }
    }
    func getStatus(_ reply: @escaping (Int, String) -> Void) {
        enqueue { self.calls.append("status"); if !self.dropsStatus { reply(self.code, "") } else { self.delayedStatus.append { reply(self.code, "") } } }
    }
    func getNetworkHeld(_ reply: @escaping (Bool) -> Void) {
        enqueue { self.calls.append("held"); reply(self.held) }
    }
    func setKillSwitch(_ mode: Int, tunnelIf: String, gatewayIps: [String], reply: @escaping (Bool, String) -> Void) {
        let apply = { self.calls.append("arm"); self.held = mode != 0; reply(true, "") }
        if HelperInstaller.installedHelperMatchesBundle { enqueue(apply) } else { apply() }
    }
}
final class Client {
    enum State { case disconnected }
    var state = State.disconnected
    var networkHeld = false
    var endingApp = false
    var protectsDrops: Bool { ProfileStore.loadAppSettings().isDropProtectionOn }
    var pendingProtectedStart: UInt64?
    var protectedLoginRetries = 0
    var protectedLoginRetryPending = false
    static let protectedLoginRetryLimit = 2
    let loginWatch = OnDemandMachine("login_watch")
    var loginWatchRetrying = false
    var loginStepFailure: String?
    var splitWarning: String?
    var awaitingCiscoStart = false
    var loginIntentActive = false
    var gatewayTrustFailed = false
    var rejectedLoginHeld = false
    let loginPreparation = LoginGatewayPreparation()
    var loginPreparationRequest: UInt64 = 0
    var loginPreparationForConnection: UInt64?
    var loginPreparationTarget: GatewayAddress?
    var loginPreparationProfileName: String?
    var loginGatewayReadiness = LoginGatewayReadiness.idle
    var cachedReplies: [(Bool?) -> Void] = []
    var holdReplies: [(Bool?) -> Void] = []
    var loginProtectionNotice: String?
    let onDemand = OnDemandController()
    let onDemandDisconnect = OnDemandDisconnect()
    let protection = OnDemandProtection()
    var onDemandPaused = false
    var onDemandRuleName: String?
    var awaitingRestartRecovery = false
    var onDemandDebounce: DispatchWorkItem?
    var pendingOnDemandFacts: Int?
    let networkFacts = FactsReader()
    let dropTracker = Tracker()
    var resettingNetwork = false
    var helperUnresponsive = false
    var hasCredentials = true
    var starts = 0
    var pfWarning: String?
    var cisco: Cisco?
    var ownConnection = false
    var splitActivity: String?
    var switchIsOn: Bool { proxy.code != 0 || proxy.held }
    var usesCisco: Bool { cisco != nil && !ownConnection }
    let proxy = Proxy()
    init() {
        setupOnDemandDisconnection()
        CALLBACKS
        onDemand.active = { true }
        onDemand.collect = { _, done in done(OnDemandFacts(network: "wifi", ssid: "Example-WiFi")) }
        var rule = OnDemandRule()
        rule.ssids = ["Example-WiFi"]
        ProfileStore.settings = Settings(onDemandEnabled: true, onDemandRules: [rule])
    }
    func ensureConnection(_ body: (Proxy) -> Void) { body(proxy) }
    func takeRelay() -> Relay? { Relay() }
    func retire(_ relay: Relay?) {}
    func refreshHeld() {}
    func fetchNetworkHeld(completion: @escaping (Bool?) -> Void) { holdReplies.append(completion) }
    func fetchTrustedLoginGateway(_ server: String, cisco: Bool, completion: @escaping (Bool?) -> Void) {
        cachedReplies.append(completion)
    }
    func refreshStatus() { onDemandDisconnect.recheck() }
    func markHelperReachable() { helperUnresponsive = false }
    func scheduleRestartRecovery(wasActive: Bool) {}
    /// The service gives no answer within the App's 3 s.
    var rpcSilent = false
    func egressRPC<Value>(_ call: @escaping (Proxy, @escaping (Value) -> Void) -> Void, completion: @escaping (Value?) -> Void) {
        if rpcSilent { completion(nil); return }
        call(proxy) { completion($0) }
    }
    var exerciseCommonLogin = false
    func startStoredConnection(allowLookup: Bool = false) -> Bool {
        if exerciseCommonLogin { return exerciseStoredConnection(allowLookup: allowLookup) }
        protection.startSession(usesCisco: usesCisco)
        cisco?.isManaging = true
        starts += 1
        proxy.code = 1
        return true
    }
    func showGatewayRejection() { gatewayTrustFailed = true }
    func continueStoredConnection(_ profile: Profile, username: String, server: String, addresses: [String]?, session: UInt64) -> Bool {
        cisco?.isManaging = true
        starts += 1
        proxy.code = 1
        return true
    }
    METHODS
}
final class NWPathMonitor {
    static var latest: NWPathMonitor?
    var pathUpdateHandler: ((Int) -> Void)?
    var cancelled = false
    init() { Self.latest = self }
    func start(queue: DispatchQueue) {}
    func cancel() { cancelled = true }
}
final class NetworkFacts {
    static var authorizationRequested = false
    func collect(path: Int, needsSSID: Bool, requestLocationAuthorization: Bool) -> OnDemandFacts {
        Self.authorizationRequested = requestLocationAuthorization
        return OnDemandFacts(network: "wifi", ssid: nil, domains: ["corp.example.com", "example.net"], servers: ["192.0.2.53"])
    }
}
final class RuleEditor {
    var rule = OnDemandRule(network: "wired")
    var filling = false
    var fillGeneration = 0
    var fillMonitor: NWPathMonitor?
    var fillReader: NetworkFacts?
    var fillNote: String?
    var ssids = "Custom"
    var domains = "Corp.Example.COM"
    var servers = "192.0.2.54"
    EDITOR_FILL_BODY
}
final class ViewLifecycle {
    var testing = true
    var testGeneration = 1
    var testProbe: Resource? = Resource()
    var testMonitor: Resource? = Resource()
    var testFacts: Resource? = Resource()
    func disappear() { let callback: () -> Void = DISAPPEAR; callback() }
}
@main struct WiringTest {
    static var count = 0
    static func check(_ result: @autoclosure () -> Bool, _ name: String) {
        precondition(result(), "FAIL " + name)
        count += 1
        print("PASS " + name)
    }
    static func main() {
        setbuf(stdout, nil)
        let client = Client()
        client.onDemandSettingsChanged()
        check(client.onDemandPaused && !client.onDemandDisconnect.waiting,
              "production bindings execute stop and pass raw observations to Rust without a disconnect reply")
        check(client.proxy.calls == ["disconnect", "status", "held"], "idle reads fence disconnect on the same proxy")
        _ = client.connectWithStoredCredentials(manual: true)
        check(client.starts == 1, "production manual entry dispatches Rust start action")
        client.proxy.replies.forEach { $0() }
        check(client.starts == 1 && client.proxy.code == 1, "late reply is forwarded without touching the new session")

        let queued = Client()
        queued.proxy.blocked = true
        queued.onDemandSettingsChanged()
        _ = queued.connectWithStoredCredentials(manual: true)
        check(queued.starts == 0, "queued system disconnect cannot be bypassed")
        queued.proxy.blocked = false
        queued.proxy.drain()
        check(queued.starts == 1 && queued.proxy.code == 1, "serial RPC observations release exactly one start")

        for finished in [false, true] {
            let cisco = Client()
            cisco.cisco = Cisco()
            cisco.onDemandSettingsChanged()
            cisco.prepareForForcedRestore()
            cisco.gatewayTrustFailed = true
            _ = cisco.connectWithStoredCredentials(manual: true)
            CiscoEngine.observedState = "Connected"
            cisco.cisco?.completion?()
            if finished { cisco.forcedRestoreDone() } else { cisco.forcedRestoreAbandoned() }
            check(cisco.gatewayTrustFailed != finished, "only a completed manual restore clears the certificate error")
            check(cisco.starts == 0, "forced restore forwards raw Cisco state without declaring idle")
            CiscoEngine.observedState = "Disconnected"
            cisco.refreshStatus()
            check(cisco.starts == 1, "Cisco CLI observation and recovery callback reach Rust")
        }
        let delayed = Client()
        delayed.cisco = Cisco()
        delayed.proxy.blocked = true
        var timers: [(Double, () -> Void)] = []
        delayed.onDemandDisconnect.schedule = { timers.append(($0, $1)) }
        delayed.onDemandSettingsChanged()
        _ = delayed.connectWithStoredCredentials(manual: true)
        delayed.cisco?.completion?()
        timers.filter { $0.0 == 10 }.forEach { $0.1() }
        check(delayed.starts == 1, "bounded release reaches the production connection entry without status replies")
        HelperInstaller.installedHelperMatchesBundle = false
        delayed.setKillSwitch(1, tunnelIf: "utun9", gatewayIps: ["192.0.2.1"])
        check(!delayed.proxy.calls.contains("arm"), "new Cisco protection waits behind the old server disconnect")
        delayed.proxy.blocked = false
        delayed.proxy.drain()
        check(delayed.proxy.calls.firstIndex(of: "arm")! > delayed.proxy.calls.lastIndex(of: "disconnect")!
              && delayed.proxy.held,
              "old queued unload precedes rearm even on the old service")
        delayed.proxy.replies.forEach { $0() }
        check(delayed.starts == 1 && delayed.proxy.held, "late disconnect replies cannot unload new protection")

        HelperInstaller.installedHelperMatchesBundle = true
        let lost = Client()
        lost.cisco = Cisco()
        lost.proxy.blocked = true
        lost.proxy.dropsStatus = true
        var lostTimers: [(Double, () -> Void)] = []
        lost.onDemandDisconnect.schedule = { lostTimers.append(($0, $1)) }
        lost.onDemandSettingsChanged()
        _ = lost.connectWithStoredCredentials(manual: true)
        lost.cisco?.completion?()
        lostTimers.filter { $0.0 == 10 }.forEach { $0.1() }
        lost.setKillSwitch(1, tunnelIf: "utun9", gatewayIps: ["192.0.2.1"])
        lost.proxy.blocked = false
        lost.proxy.drain()
        check(lost.starts == 1 && lost.proxy.held, "new service arms protection even if every status reply is lost")
        lost.proxy.replies.forEach { $0() }
        check(lost.proxy.held, "late replies cannot remove the reply-independent arm")
        let service = Service()
        service.queue.blocked = true
        service.queue.async { KillSwitch.shared.held = false }
        service.setKillSwitch(1, tunnelIf: "utun9", gatewayIps: ["192.0.2.1"]) { _, _ in }
        check(!KillSwitch.shared.held, "production service queues protection behind pending disconnect")
        service.queue.blocked = false
        service.queue.drain()
        check(KillSwitch.shared.held && !service.userReleased, "production service installs protection after old unload")

        let slow = Client()
        slow.cisco = Cisco()
        var deadlines: [() -> Void] = []
        slow.onDemandDisconnect.schedule = { _, done in deadlines.append(done) }
        slow.onDemandSettingsChanged()
        deadlines.forEach { $0() }
        DispatchQueue.main.timers.forEach { $0() }
        check(!slow.helperUnresponsive, "slow Cisco stop with a helper reply does not claim helper failure")

        // Verify F4: the old service executes its status request but delays the reply.
        HelperInstaller.installedHelperMatchesBundle = false
        let lateArm = Client()
        lateArm.cisco = Cisco()
        lateArm.proxy.dropsStatus = true
        lateArm.setKillSwitch(2, tunnelIf: "utun9", gatewayIps: ["192.0.2.1"])
        lateArm.disconnectByUser()
        lateArm.cisco?.completion?()
        check(!lateArm.proxy.held, "F4 manual disconnect releases protection before the old status reply")
        lateArm.proxy.delayedStatus.removeFirst()()
        print("F4 observed held=\(lateArm.proxy.held) calls=\(lateArm.proxy.calls)")
        check(!lateArm.proxy.held && !lateArm.proxy.calls.contains("arm"),
              "F4 late old-service status reply cannot rearm after manual disconnect")

        let lateOff = Client()
        lateOff.cisco = Cisco()
        lateOff.proxy.dropsStatus = true
        lateOff.setKillSwitch(0, tunnelIf: "", gatewayIps: [])
        _ = lateOff.connectWithStoredCredentials(manual: true)
        lateOff.setKillSwitch(1, tunnelIf: "utun10", gatewayIps: ["192.0.2.2"])
        lateOff.proxy.delayedStatus.removeLast()()
        check(lateOff.proxy.held, "new session protection is installed before delivering old off")
        lateOff.proxy.delayedStatus.removeFirst()()
        check(lateOff.proxy.held && lateOff.proxy.calls.filter { $0 == "arm" }.count == 1,
              "late old off cannot unload a new session's protection")

        for reset in ["forced", "mode", "on-demand"] {
            let c = Client()
            c.cisco = Cisco()
            c.proxy.dropsStatus = true
            c.setKillSwitch(2, tunnelIf: "utun9", gatewayIps: ["192.0.2.1"])
            if reset == "forced" { c.prepareForForcedRestore() }
            if reset == "mode" { c.setConnectionMode(own: true) }
            if reset == "on-demand" { c.onDemandSettingsChanged() }
            c.proxy.delayedStatus.removeFirst()()
            check(!c.proxy.held && !c.proxy.calls.contains("arm"), "production boundary cancels delayed protection: " + reset)
        }
        HelperInstaller.installedHelperMatchesBundle = true
        let oldStop = Client()
        oldStop.cisco = Cisco()
        oldStop.disconnectByUser()
        let oldCompletion = oldStop.cisco!.completion!
        _ = oldStop.connectWithStoredCredentials(manual: true)
        oldStop.setKillSwitch(1, tunnelIf: "utun10", gatewayIps: ["192.0.2.2"])
        oldCompletion()
        check(oldStop.proxy.held && oldStop.proxy.calls.filter { $0 == "disconnect" }.count == 1,
              "old local-stop callback cannot submit another unload against a newer session")
        DispatchQueue.main.timers.forEach { $0() }
        check(lateArm.pfWarning == nil, "cancelled protection deadline cannot report a stale warning")
        HelperInstaller.installedHelperMatchesBundle = false

        let cancelled = Client()
        cancelled.cisco = Cisco()
        cancelled.proxy.dropsStatus = true
        cancelled.setKillSwitch(2, tunnelIf: "utun9", gatewayIps: ["192.0.2.1"])
        cancelled.prepareForForcedRestore()
        cancelled.forcedRestoreAbandoned()
        cancelled.setKillSwitch(1, tunnelIf: "utun10", gatewayIps: ["192.0.2.2"])
        cancelled.proxy.delayedStatus.removeLast()()
        cancelled.proxy.delayedStatus.removeFirst()()
        check(cancelled.proxy.held && cancelled.cisco?.rearms == 1
              && cancelled.proxy.calls.filter { $0 == "arm" }.count == 1,
              "cancelled restore rearms surviving Cisco with a new intent and rejects the pre-restore reply")

        let latest = Client()
        latest.cisco = Cisco()
        latest.proxy.dropsStatus = true
        latest.setKillSwitch(2, tunnelIf: "utun9", gatewayIps: ["192.0.2.1"])
        latest.setKillSwitch(0, tunnelIf: "", gatewayIps: [])
        latest.proxy.delayedStatus.removeFirst()()
        latest.proxy.delayedStatus.removeFirst()()
        check(!latest.proxy.held && latest.proxy.calls.filter { $0 == "arm" }.count == 1,
              "only the latest protection intent is submitted within one session")
        HelperInstaller.installedHelperMatchesBundle = true
        let fresh = Client()
        fresh.cisco = Cisco()
        fresh.proxy.blocked = true
        fresh.setKillSwitch(2, tunnelIf: "utun9", gatewayIps: ["192.0.2.1"])
        fresh.disconnectByUser()
        fresh.cisco?.completion?()
        fresh.proxy.blocked = false
        fresh.proxy.drain()
        check(!fresh.proxy.held, "new-service FIFO arm then manual disconnect still leaves direct networking")

        let readiness = Client()
        readiness.prepareGatewayWhileDirect()
        check(readiness.loginGatewayReadiness == .checking && readiness.loginGatewayReadiness.isBusy,
              "the passive check reports progress while the panel keeps its connect action")
        readiness.cachedReplies.removeFirst()(true)
        check(readiness.loginGatewayReadiness == .cached && readiness.loginGatewayReadiness.canConnect
              && readiness.holdReplies.isEmpty && readiness.loginPreparation.checks == 0,
              "verified cache makes the panel ready without preparing TLS")

        readiness.prepareGatewayWhileDirect()
        readiness.cachedReplies.removeFirst()(nil)
        check(readiness.loginGatewayReadiness == .networkUnknown && readiness.holdReplies.isEmpty,
              "missing cache reply does not become a cache miss or start preparation")
        readiness.prepareGatewayWhileDirect(retry: true)
        readiness.cachedReplies.removeFirst()(false)
        readiness.holdReplies.removeFirst()(nil)
        check(readiness.loginGatewayReadiness == .networkUnknown && readiness.loginPreparation.checks == 0,
              "unknown firewall status cannot start preparation")
        directRoute = false
        readiness.prepareGatewayWhileDirect(retry: true)
        readiness.cachedReplies.removeFirst()(false)
        readiness.holdReplies.removeFirst()(false)
        check(readiness.loginGatewayReadiness == .networkUnknown && readiness.loginPreparation.checks == 0,
              "a non-direct route cannot start preparation")
        directRoute = true
        readiness.prepareGatewayWhileDirect(retry: true)
        readiness.cachedReplies.removeFirst()(false)
        readiness.holdReplies.removeFirst()(false)
        check(readiness.loginGatewayReadiness == .preparing && readiness.loginPreparation.checks == 1
              && readiness.loginPreparation.ipv4Only, "confirmed direct own mode begins one IPv4 preparation")
        readiness.prepareGatewayWhileDirect()
        check(readiness.cachedReplies.isEmpty, "reopening while preparing does not submit another request")
        readiness.loginPreparation.phase = .ready
        readiness.loginPreparation.done?()
        check(readiness.loginGatewayReadiness == .candidate && readiness.loginGatewayReadiness.canConnect,
              "a fresh verified candidate makes the panel ready")
        readiness.loginPreparation.phase = .idle
        readiness.expireGatewayPreparation()
        check(readiness.loginGatewayReadiness == .idle, "expired candidate clears the ready state")

        readiness.prepareGatewayWhileDirect()
        readiness.cachedReplies.removeFirst()(false)
        readiness.holdReplies.removeFirst()(false)
        readiness.loginPreparation.phase = .certificateRejected
        readiness.loginPreparation.done?()
        check(readiness.loginGatewayReadiness == .certificateRejected && !readiness.loginGatewayReadiness.canConnect,
              "certificate rejection records its own reason without a usable address")
        readiness.prepareGatewayWhileDirect(retry: true)
        readiness.cachedReplies.removeFirst()(false)
        readiness.holdReplies.removeFirst()(false)
        readiness.loginPreparation.phase = .unavailable
        readiness.loginPreparation.done?()
        check(readiness.loginGatewayReadiness == .unavailable && !readiness.loginGatewayReadiness.canConnect,
              "a preparation timeout does not display a certificate error")

        readiness.prepareGatewayWhileDirect()
        let oldReply = readiness.cachedReplies.removeFirst()
        ProfileStore.profile.server = "vpn-b.example"
        readiness.prepareGatewayWhileDirect()
        oldReply(true)
        check(readiness.loginGatewayReadiness == .checking, "a late cache hit for the previous server is ignored")
        readiness.cachedReplies.removeFirst()(false)
        readiness.holdReplies.removeFirst()(false)
        let oldPreparation = readiness.loginPreparation.done
        readiness.cisco = Cisco()
        readiness.resetGatewayPreparation()
        readiness.prepareGatewayWhileDirect()
        readiness.loginPreparation.phase = .ready
        oldPreparation?()
        check(readiness.loginGatewayReadiness == .checking, "a late TLS result from the previous mode is ignored")
        readiness.resetGatewayPreparation()
        readiness.cachedReplies.removeFirst()(true)
        check(readiness.loginGatewayReadiness == .idle, "a cancelled request cannot change readiness")
        ProfileStore.profile = Profile()

        let joining = Client()
        joining.prepareGatewayWhileDirect()
        joining.cachedReplies.removeFirst()(false)
        joining.holdReplies.removeFirst()(false)
        let passiveCompletion = joining.loginPreparation.done
        joining.loginIntentActive = true
        var connectionResults: [LoginGatewayReadiness] = []
        let deadline = DispatchTime.now() + 3
        joining.prepareGatewayForConnection(deadline: deadline) { connectionResults.append($0) }
        joining.prepareGatewayForConnection(deadline: deadline) { connectionResults.append($0) }
        check(joining.loginPreparation.checks == 1 && joining.cachedReplies.isEmpty && joining.holdReplies.isEmpty,
              "the click joins the selected server check without repeating TLS or service queries")
        passiveCompletion?()
        check(connectionResults.isEmpty, "the original passive observer cannot start the connection")
        joining.loginPreparation.phase = .ready
        let joinedCompletion = joining.loginPreparation.done
        joinedCompletion?()
        joinedCompletion?()
        check(connectionResults == [.candidate], "joined preparation completes exactly once")

        let expired = Client()
        expired.loginIntentActive = true
        var expiredResult: LoginGatewayReadiness?
        expired.prepareGatewayForConnection(deadline: .now()) { expiredResult = $0 }
        check(expiredResult == .timedOut && expired.loginPreparation.checks == 0,
              "an exhausted connection deadline starts no TLS work")

        let heldConnection = Client()
        heldConnection.loginIntentActive = true
        heldConnection.networkHeld = true
        var heldResult: LoginGatewayReadiness?
        heldConnection.prepareGatewayForConnection(deadline: deadline) { heldResult = $0 }
        check(heldResult == .networkUnknown && heldConnection.loginPreparation.checks == 0,
              "a held connection cannot start preparing a gateway")

        let replacement = Client()
        replacement.loginIntentActive = true
        var replacementResults: [LoginGatewayReadiness] = []
        replacement.prepareGatewayForConnection(deadline: deadline) { replacementResults.append($0) }
        let replaced = replacement.loginPreparation.done
        ProfileStore.profile.server = "vpn-b.example"
        replacement.resetGatewayPreparation()
        replacement.prepareGatewayForConnection(deadline: deadline) { replacementResults.append($0) }
        replaced?()
        check(replacementResults.isEmpty, "a replaced server callback cannot continue the new connection")
        replacement.loginPreparation.phase = .certificateRejected
        replacement.loginPreparation.done?()
        check(replacementResults == [.certificateRejected], "only the current trust refusal reaches the common entry")
        ProfileStore.profile = Profile()

        for manual in [true, false] {
            let first = Client()
            first.exerciseCommonLogin = true
            first.proxy.cachedGateway = false
            if manual { _ = first.connectWithStoredCredentials(manual: true) }
            else {
                first.onDemand.configure(enabled: false, rules: [])
                first.onDemand.holdLaunch()
                first.onDemand.launchFinished(true)
            }
            check(first.proxy.opens == 1 && first.starts == 0 && first.loginPreparation.checks == 1,
                  "both entry points prepare exactly once after a service grant")
            _ = first.connectWithStoredCredentials(manual: manual)
            check(first.proxy.opens == 1 && first.loginProtectionNotice == ProtectedLoginNotice.preparingGateway,
                  "a repeated intent cannot extend the window")
            first.loginPreparation.phase = .ready
            first.loginPreparation.done?()
            check(first.proxy.finishPeers == ["192.0.2.7"] && first.starts == 1 && first.networkHeld,
                  "verified peer is consumed only after protection confirms")
        }
        let wake = Client()
        wake.exerciseCommonLogin = true
        wake.proxy.cachedGateway = false
        wake.onDemand.configure(enabled: false, rules: [])
        _ = wake.connectWithStoredCredentials()
        check(wake.proxy.opens == 1 && wake.loginPreparation.checks == 0 && wake.starts == 0,
              "a non-launch automatic request never opens a direct lookup window")
        let failedJoin = Client()
        failedJoin.exerciseCommonLogin = true
        failedJoin.proxy.cachedGateway = false
        failedJoin.loginPreparationTarget = GatewayAddress(ProfileStore.profile.server)
        failedJoin.loginPreparationProfileName = ProfileStore.profile.server
        failedJoin.loginPreparation.phase = .preparing
        failedJoin.proxy.blocked = true
        _ = failedJoin.connectWithStoredCredentials(manual: true)
        failedJoin.loginPreparation.phase = .certificateRejected
        failedJoin.proxy.blocked = false
        failedJoin.proxy.drain()
        check(failedJoin.starts == 0 && failedJoin.loginPreparation.checks == 0 &&
              failedJoin.proxy.finishPeers == [""] && failedJoin.gatewayTrustFailed && failedJoin.rejectedLoginHeld,
              "rejection during the service round trip blocks without a second lookup")
        // §69.10: a service that does not answer in time (it just
        // started) is asked again twice; then the login stops, said plainly.
        let silent = Client()
        silent.exerciseCommonLogin = true
        silent.rpcSilent = true
        silent.onDemand.configure(enabled: false, rules: [])
        DispatchQueue.main.timers = []
        _ = silent.connectWithStoredCredentials()
        check(silent.loginProtectionNotice == ProtectedLoginNotice.serviceSlowRetrying && silent.protectedLoginRetryPending
              && DispatchQueue.main.timers.count == 1 && silent.starts == 0 && !silent.networkHeld,
              "an unanswered protected login is retried, never logged in unprotected")
        for _ in 0..<3 {
            let due = DispatchQueue.main.timers
            DispatchQueue.main.timers = []
            due.forEach { $0() }
        }
        check(silent.loginProtectionNotice == ProtectedLoginNotice.serviceDidNotAnswer && !silent.protectedLoginRetryPending
              && silent.protectedLoginRetries == 0 && silent.starts == 0 && !silent.networkHeld && DispatchQueue.main.timers.isEmpty,
              "after two retries the login stops with a plain reason")
        silent.rpcSilent = false
        _ = silent.connectWithStoredCredentials(manual: true)
        check(silent.starts == 1 && silent.networkHeld, "turning it on again logs in once the service answers")
        // §69.18: a login that holds the network but whose engine never
        // starts (after the 2026-11-26 update) is started again with the
        // hold kept; after two fresh starts it stops and says why.
        let stuck = Client()
        stuck.exerciseCommonLogin = true
        stuck.onDemand.configure(enabled: false, rules: [])
        DispatchQueue.main.timers = []
        RelayLog.lines = []
        _ = stuck.connectWithStoredCredentials(manual: true)
        check(stuck.starts == 1 && stuck.networkHeld && DispatchQueue.main.timers.count == 1
              && RelayLog.lines == ["login: network held, preparing the relay"],
              "a login that holds the network is watched and logged")
        for round in 1...2 {
            let due = DispatchQueue.main.timers
            DispatchQueue.main.timers = []
            due.forEach { $0() }
            check(stuck.starts == round + 1 && stuck.networkHeld && stuck.loginProtectionNotice == "网络已拦截，正在连接 VPN",
                  "a stuck login starts again with the network still held (\(round))")
        }
        let last = DispatchQueue.main.timers
        DispatchQueue.main.timers = []
        last.forEach { $0() }
        check(stuck.starts == 3 && stuck.networkHeld && stuck.loginProtectionNotice?.hasPrefix("没能开始登录") == true
              && DispatchQueue.main.timers.isEmpty,
              "after two fresh starts the login stops, still held, and says why")
        let failing = Client()
        failing.exerciseCommonLogin = true
        failing.onDemand.configure(enabled: false, rules: [])
        DispatchQueue.main.timers = []
        _ = failing.connectWithStoredCredentials(manual: true)
        failing.loginStepFailed("后台服务没有接受连接请求")
        check(failing.starts == 2 && failing.networkHeld, "a failed step starts again at once")
        failing.disconnect()
        let after = DispatchQueue.main.timers
        DispatchQueue.main.timers = []
        after.forEach { $0() }
        check(failing.starts == 2, "a stop ends the watch: no start after it")
        let moved = Client()
        moved.exerciseCommonLogin = true
        moved.onDemand.configure(enabled: false, rules: [])
        DispatchQueue.main.timers = []
        _ = moved.connectWithStoredCredentials(manual: true)
        moved.loginIntentActive = false
        let quiet = DispatchQueue.main.timers
        DispatchQueue.main.timers = []
        quiet.forEach { $0() }
        check(moved.starts == 1 && DispatchQueue.main.timers.isEmpty, "a login no longer waiting is left alone")
        let restored = Client()
        restored.exerciseCommonLogin = true
        restored.proxy.cachedGateway = false
        _ = restored.connectWithStoredCredentials(manual: true)
        let late = restored.loginPreparation.done
        restored.disconnectByUser()
        late?()
        check(restored.starts == 0 && restored.proxy.finishPeers.isEmpty,
              "manual disconnect discards a late preparation result")
        let editor = RuleEditor()
        editor.fillCurrentNetwork()
        let monitor = NWPathMonitor.latest!
        monitor.pathUpdateHandler?(0)
        check(editor.rule.network == "wired" && editor.ssids == "Custom" && !NetworkFacts.authorizationRequested,
              "production fill keeps explicit network and SSID input without requesting authorization")
        check(editor.domains == "Corp.Example.COM, example.net" && editor.servers == "192.0.2.54, 192.0.2.53"
              && monitor.cancelled && editor.fillMonitor == nil && !editor.filling,
              "production fill merges facts and disposes the one-shot monitor")
        editor.fillCurrentNetwork()
        let lateFill = NWPathMonitor.latest!.pathUpdateHandler
        editor.stopFill()
        editor.domains = "custom.example"
        lateFill?(0)
        check(editor.domains == "custom.example", "cancelled editor rejects late network facts")

        let view = ViewLifecycle()
        let probe = view.testProbe!
        view.disappear()
        check(!view.testing && probe.cancelled && view.testProbe == nil && view.testMonitor == nil,
              "production settings disappearance cancels resources and restores test button")
        print("\(count) production I/O wiring assertions passed")
    }
}
'''
for key, value in [('CALLBACKS', callbacks), ('METHODS', body), ('DISAPPEAR', disappear), ('EDITOR_FILL_BODY', fill_methods), ('SERVER_PROTECTION_BODY', service_protection), ('LOGIN_GATEWAY_READINESS', readiness), ('PROTECTED_NOTICE', block((root/'Sources/Shared/HelperXPC.swift').read_text(), 'enum ProtectedLoginNotice'))]:
    fixture = fixture.replace(key, value)
output.write_text(fixture)
