import AppKit
import Foundation

// Harness for Sources/App/CiscoEngine.swift against core/scripts/
// fake-cisco-vpn.sh (DESIGN.md §21.4). Compiled with the engine by
// scripts/cisco-engine-test.sh; prints one EVENT line per callback.

final class HelperClient {
    enum State: Int {
        case disconnected = 0, connecting, authenticating, awaitingApproval, connected, reconnecting
    }
}

@main
struct Harness {
    static func main() {
        let dir = ProcessInfo.processInfo.environment["FAKE_CISCO_DIR"]!
        var available = true
        CiscoEngine.physicalAvailability = { available }
        CiscoEngine.cliPath = CommandLine.arguments[1]
        CiscoEngine.approvalTimeoutMinimum = 0.5
        // The fake CLI changes no routes: the fallback check finds drops.
        CiscoEngine.monitorInterval = 4
        var password = "good"
        let engine = CiscoEngine()
        let start = Date()
        func log(_ s: String) {
            print(String(format: "%5.1f ", Date().timeIntervalSince(start)) + s)
            fflush(stdout)
        }
        engine.credentialsProvider = { .init(entry: "VPN-A", username: "u", password: password) }
        engine.onStatus = { state, detail, rejected in
            log("EVENT state=\(state) \(detail) certificateRejected=\(rejected)")
        }
        engine.onTerminal = { log("EVENT terminal=\($0)") }
        engine.onProtectionRequest = { mode, _, gws, done in
            log("EVENT killswitch=\(mode) gw=\(gws.joined(separator: ","))")
            done(true)
        }
        func setState(_ s: String) {
            try? s.write(toFile: dir + "/state", atomically: true, encoding: .utf8)
        }
        func wait(_ seconds: Double) {
            RunLoop.main.run(until: Date().addingTimeInterval(seconds))
        }
        func loginCount() -> Int {
            (try? String(contentsOfFile: dir + "/commands", encoding: .utf8))?.split(separator: "\n").count ?? 0
        }
        func until(_ observed: () -> Bool) {
            let deadline = Date().addingTimeInterval(18)
            while !observed() && Date() < deadline { wait(0.05) }
            precondition(observed(), "expected fake CLI event was not observed")
        }
        if CommandLine.arguments.last == "4" {
            var connected = false
            var feedbackBeforeExit = false
            var reportedRetries = 0
            var rejectionCount = 0
            var blockingCount = 0
            engine.onStatus = { state, detail, rejected in
                log("EVENT state=\(state) \(detail) certificateRejected=\(rejected)")
                connected = state == .connected && !rejected
                if rejected {
                    rejectionCount += 1
                    if detail.contains("后重试") { reportedRetries += 1 }
                    if !FileManager.default.fileExists(atPath: dir + "/certificate-complete") {
                        feedbackBeforeExit = true
                    }
                }
            }
            engine.onProtectionRequest = { mode, _, _, done in
                log("EVENT killswitch=\(mode)")
                if mode == 2 { blockingCount += 1 }
                done(true)
            }
            log("STEP feedback-seed")
            engine.connect()
            until { connected }
            log("STEP feedback-reconnect")
            password = "certfail-conflicting"
            setState("Disconnected")
            engine.networkChanged()
            until { reportedRetries > 0 }
            log("certificate-feedback-before-cli-exit=\(feedbackBeforeExit)")
            log("STEP feedback-restart")
            let beforeRearmBlocks = blockingCount
            let beforeRearmFeedback = rejectionCount
            engine.rearm()
            until { blockingCount > beforeRearmBlocks && rejectionCount > beforeRearmFeedback }
            let beforeRefresh = reportedRetries
            engine.refresh()
            until { reportedRetries > beforeRefresh }
            log("STEP feedback-still-stale")
            let beforeStaleLogin = loginCount()
            let beforeStaleReport = reportedRetries
            password = "stale-after-rejection"
            setState("Disconnected")
            until { loginCount() > beforeStaleLogin && reportedRetries > beforeStaleReport }
            log("STEP feedback-recovery")
            password = "good"
            setState("Disconnected")
            until { connected }
            var disconnected = false
            engine.disconnect { disconnected = true }
            until { disconnected }
            log("DONE")
            return
        }
        if CommandLine.arguments.last == "3" {
            log("STEP certificate-failure")
            password = "certfail"
            var replies: [(Bool) -> Void] = []
            engine.onProtectionRequest = { mode, _, gws, done in
                log("EVENT killswitch=\(mode) gw=\(gws.joined(separator: ","))")
                replies.append(done)
            }
            engine.connect()
            until { replies.count == 1 }
            let timedOutReply = replies.removeFirst()
            until { replies.count == 1 }
            timedOutReply(true)
            wait(0.2)
            log("no-login-after-late-timeout=\(loginCount() == 0)")
            replies.removeFirst()(false)
            until { replies.count == 1 }
            log("no-login-after-refusal=\(loginCount() == 0)")
            replies.removeFirst()(true)
            until { loginCount() == 1 && replies.count == 1 }
            replies.removeFirst()(true)
            until { loginCount() == 2 && replies.count == 1 }
            let lateReply = replies.removeFirst()
            var disconnected = false
            engine.disconnect { disconnected = true }
            until { disconnected }
            lateReply(true)
            wait(0.5)
            log("no-login-after-manual-stop=\(loginCount() == 2)")
            log("STEP stale-success")
            engine.onProtectionRequest = { mode, _, gws, done in
                log("EVENT killswitch=\(mode) gw=\(gws.joined(separator: ","))")
                done(true)
            }
            var sawUnconfirmedSession = false
            engine.onStatus = { state, detail, rejected in
                log("EVENT state=\(state) \(detail) certificateRejected=\(rejected)")
                if detail == "Cisco 会话尚未确认" { sawUnconfirmedSession = true }
            }
            password = "stale-success"
            engine.connect()
            until { sawUnconfirmedSession }
            disconnected = false
            engine.disconnect { disconnected = true }
            until { disconnected }
            log("DONE")
            return
        }
        // Parts 1 and 2 run independently with separate fake-CLI state and defaults domains.
        let part = CommandLine.arguments.count > 2 ? CommandLine.arguments[2] : "all"
        if part != "2" {
            log("STEP connect")
            engine.connect(); wait(4)
            log("STEP drop")
            setState("Disconnected"); wait(9)
            log("STEP manual-disconnect")
            let done = DispatchSemaphore(value: 0)
            engine.disconnect { done.signal() }; wait(2)
            log("STEP rejected")
            password = "bad"
            engine.connect(); wait(5)
            log("STEP transient-then-good")
            password = "flaky"
            engine.connect(); wait(2)
            password = "good"; wait(5)
            engine.disconnect {}; wait(1)
            log("STEP approval-expired")
            password = "noapprove"
            engine.connect(); wait(3)
            engine.disconnect {}; wait(1)
            log("STEP quick-login-failed")
            password = "quickfail"
            engine.connect(); wait(2)
            log("STEP pushed-failure")
            engine.disconnect {}; wait(1)
            password = "pushfail"
            engine.connect(); wait(3)
            engine.disconnect {}; wait(1)
        }
        if part == "1" { log("DONE"); return }
        password = "good"
        log("STEP adopt-on-refresh")
        setState("Disconnected")
        engine.connect(); wait(3)
        let second = CiscoEngine()
        second.credentialsProvider = engine.credentialsProvider
        second.onState = { state, detail in log("EVENT2 state=\(state) \(detail)") }
        second.onProtectionRequest = { mode, _, _, done in log("EVENT2 killswitch=\(mode)"); done(true) }
        second.refresh(); wait(3)
        log("STEP no-adopt-foreign")
        // A Cisco session the user started in Cisco's own window
        // (DESIGN.md §25.4): never adopted, never armed.
        UserDefaults.standard.set(false, forKey: CiscoEngine.ownedKey)
        let third = CiscoEngine()
        third.credentialsProvider = engine.credentialsProvider
        third.onState = { state, detail in log("EVENT3 state=\(state) \(detail)") }
        third.onProtectionRequest = { mode, _, _, done in log("EVENT3 killswitch=\(mode)"); done(true) }
        third.refresh(); wait(3)
        log("EVENT3 managing=\(third.isManaging)")
        engine.disconnect {}; second.disconnect {}; wait(2)
        func cancellationCount() -> Int {
            (try? String(contentsOfFile: dir + "/cancellations", encoding: .utf8))?.split(separator: "\n").count ?? 0
        }
        log("STEP offline-cancel")
        let beforeCancel = cancellationCount()
        password = "slow"
        engine.connect(); wait(1)
        available = false
        engine.networkChanged(); wait(3)
        log("offline owned=\(engine.isManaging)")
        log("offline cancel-issued=\(cancellationCount() > beforeCancel)")
        let stoppedState = (try? String(contentsOfFile: dir + "/state", encoding: .utf8))?.trimmingCharacters(in: .whitespacesAndNewlines) ?? "unknown"
        log("offline daemon-state=\(stoppedState)")
        log("STEP offline-resume")
        password = "good"
        available = true
        engine.networkChanged(); wait(3)
        engine.disconnect {}; wait(1)
        log("STEP offline-manual-stop")
        password = "slow"
        engine.connect(); wait(1)
        available = false
        engine.networkChanged(); wait(3)
        engine.disconnect {}; wait(1)
        log("STEP restored-after-manual")
        available = true
        engine.networkChanged(); wait(2)
        log("STEP stop-active-login")
        let beforeActiveStop = cancellationCount()
        password = "slow"
        engine.connect(); wait(1)
        engine.disconnect {}; wait(3)
        log("cancelled owned=\(engine.isManaging)")
        log("active cancel-issued=\(cancellationCount() > beforeActiveStop)")
        // A session Cisco already holds is kept through an outage (§64.2).
        log("STEP offline-keep")
        password = "good"
        engine.connect(); wait(3)
        let loginsBeforeKeep = loginCount()
        let cancelsBeforeKeep = cancellationCount()
        available = false
        engine.networkChanged(); wait(3)
        log("keep cancel-issued=\(cancellationCount() > cancelsBeforeKeep)")
        available = true
        engine.networkChanged(); wait(3)
        log("keep relogin=\(loginCount() > loginsBeforeKeep)")
        engine.disconnect {}; wait(1)
        log("DONE")
    }
}

// Declared by CertificateRelay.swift in the App; the harness links only
// the engine's shell.
@_silgen_name("ac_string_free")
func ac_string_free(_ s: UnsafeMutablePointer<CChar>?)
