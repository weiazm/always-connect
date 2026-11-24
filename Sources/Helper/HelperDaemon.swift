import Foundation
import Security

/// Helper-side XPC daemon (DESIGN.md §16.9).
///
/// Run as a LaunchDaemon (root) via `AlwaysConnectHelper daemon`. It
/// owns one CLIOrchestrator at a time and forwards its state to the
/// App over XPC. The daemon never stores credentials: they arrive per
/// connect call and live only in the engine's memory.
///
/// The session belongs to the daemon, not to an XPC connection: the
/// App quitting, crashing or relaunching only adds or removes a
/// status subscriber. Losing the UI is never a manual disconnect, so
/// it can never restore the local network (DESIGN.md §二十).
///
/// Client validation (DESIGN.md §36.3): only the App signed with the
/// same certificate as this daemon may connect (ClientRequirement). A
/// refused client is turned away at the listener, before any method
/// runs, and every message is checked again by audit token
/// (setCodeSigningRequirement): an arbitrary local process cannot
/// drive the root daemon's pf rules or tunnel. A daemon without a
/// signing certificate (ad-hoc build) accepts nobody; local builds are
/// signed with scripts/dev-signing-identity.sh's identity.
final class HelperDaemon: NSObject, NSXPCListenerDelegate {
    private let listener: NSXPCListener
    private let session = HelperSession()
    private let clientUID = ClientUIDPolicy()

    init(machServiceName: String = AlwaysConnectHelperMachService) {
        listener = NSXPCListener(machServiceName: machServiceName)
        super.init()
        listener.delegate = self
    }

    func shutdown() {
        session.shutdown()
        Self.endOwnProcesses()
    }

    func start() {
        // A crashed predecessor's openconnect (F6): the
        // engine that ran them is gone, nothing will ever stop them.
        Self.endOwnProcesses(includeChildren: false)
        // The network gate (DESIGN.md §25.2): adopt a hold from this
        // boot (blocking set, grace clock running until an App is
        // back), drop one from an earlier boot. A hold that outlives
        // its App is released as on a quit.
        NetworkGuard.shared.onGraceExpired = { [weak self] in
            guard let self else { return }
            self.session.releaseEverything(reason: NetworkGuard.Reason.appGone)
            self.startQuickIdleExit()
        }
        NetworkGuard.shared.adoptAtStart()
        // Routes and DNS entries a dead session left (§26.3, §26.5).
        let direct = DirectRoutes.undoAtStart(supportDir: CLIOrchestrator.defaultSupportDir,
                                              noRoutes: TestSeam.isActive)
        if direct != "none" { HelperSession.log("direct routes at start: \(direct)") }
        if let script = try? VpncScript.install() {
            let done = CLIOrchestrator.undoJournalAtStart(scriptPath: script)
            if done != "none" { HelperSession.log("route journal at start: \(done)") }
        }
        listener.resume()
        startIdleExit()
    }

    /// Quitting the App means nothing of ours keeps running (DESIGN.md
    /// §21.5, §23.11): with no App attached, no tunnel, no kill switch
    /// and no held network, the daemon exits cleanly. launchd starts
    /// it again on demand (MachServices) and restarts it only after a
    /// crash (KeepAlive Crashed = true, DESIGN.md §25.6).
    ///
    /// The last App leaving (a quit invalidates its connection) starts
    /// a 1 s check, so the daemon is gone a few seconds after the App
    /// instead of 30-45 s later; an openconnect still logging out keeps
    /// the session non-idle until it has exited. The 15 s check stays
    /// as the fallback (a daemon started at boot with no App at all).
    private var idleTimer: DispatchSourceTimer?
    private var quickTimer: DispatchSourceTimer?
    private let idleQueue = DispatchQueue(label: "com.alwaysconnect.helper.idle")
    private var idleChecks = 0
    private var quickChecks = 0

    private func startIdleExit() {
        session.onLastClientGone = { [weak self] in self?.startQuickIdleExit() }
        let timer = DispatchSource.makeTimerSource(queue: idleQueue)
        timer.schedule(deadline: .now() + 15, repeating: 15, leeway: .seconds(3))
        timer.setEventHandler { [weak self] in
            guard let self else { return }
            self.idleChecks = self.isFullyIdle ? self.idleChecks + 1 : 0
            if self.idleChecks >= 2 { self.exitIdle() }
        }
        timer.resume()
        idleTimer = timer
    }

    private var isFullyIdle: Bool {
        session.isIdle && KillSwitch.shared.isOff && !CLIOrchestrator.localNetworkHeld()
    }

    /// Exposed for the grace path; idempotent while a check runs.
    func checkIdleSoon() { startQuickIdleExit() }

    /// Two idle checks in a row, 1 s apart, then exit. Gives up after
    /// a minute (a held network or an App reattaching keeps it busy;
    /// the 15 s check takes over from there).
    private func startQuickIdleExit() {
        idleQueue.async {
            guard self.quickTimer == nil else { return }
            self.quickChecks = 0
            var ticks = 0
            let timer = DispatchSource.makeTimerSource(queue: self.idleQueue)
            timer.schedule(deadline: .now() + 1, repeating: 1)
            timer.setEventHandler { [weak self] in
                guard let self else { return }
                ticks += 1
                self.quickChecks = self.isFullyIdle ? self.quickChecks + 1 : 0
                if self.quickChecks >= 2 { self.exitIdle() }
                if ticks >= 60 {
                    self.quickTimer?.cancel()
                    self.quickTimer = nil
                }
            }
            timer.resume()
            self.quickTimer = timer
        }
    }

    private func exitIdle() {
        HelperSession.log("idle, exiting")
        Self.endOwnProcesses()
        exit(0)
    }

    /// Before the daemon exits (idle, or SIGTERM from launchd) and when
    /// it starts: its own children (openconnect, a vpnc-script, a pfctl
    /// or route call), and any openconnect an earlier run left behind —
    /// found by our installed vpnc-script on its command line
    /// (`--script`) (§23.7, §23.11, F6).
    static func endOwnProcesses(includeChildren: Bool = true) {
        var targets = includeChildren ? ProcessSweep.descendants() : []
        for (program, marker) in leftoverMarkers {
            for pid in ProcessSweep.pids(commandContaining: marker) where !targets.contains(pid) {
                // Our exact arguments AND the program: a `tail -f` on the
                // log or a recover running the script is not a leftover.
                guard let line = ProcessSweep.commandLine(of: pid), line.contains(program) else { continue }
                targets.append(pid)
            }
        }
        // SIGHUP: an openconnect that outlived a crashed service leaves
        // without logging the session off, so the App's reconnect can
        // reuse the cookie (§30.3; SIGTERM cost a phone approval).
        let killed = ProcessSweep.terminate(targets, grace: 2, signal: includeChildren ? SIGTERM : SIGHUP)
        if !targets.isEmpty {
            HelperSession.log("ended \(targets.count) leftover process(es), \(killed.count) by SIGKILL")
        }
    }

    /// (program, exact argument) pairs of what an earlier run started:
    /// openconnect with our installed vpnc-script.
    static var leftoverMarkers: [(String, String)] {
        let dir = CLIOrchestrator.defaultSupportDir
        let script = dir.appendingPathComponent("alwaysconnect-vpnc.sh").path
        let gate = ClientRequirement.egressGatePath
        let quotedScript = CLIOrchestrator.shellQuoted(script)
        return [
            ("openconnect", "--script=" + quotedScript),
            ("openconnect", "--script=" + CLIOrchestrator.shellQuoted(gate) + " " + quotedScript),
            (gate, gate + " " + script),
        ]
    }

    // MARK: - NSXPCListenerDelegate

    func listener(
        _ listener: NSXPCListener,
        shouldAcceptNewConnection connection: NSXPCConnection
    ) -> Bool {
        guard let requirement = ClientRequirement.forThisProcess else {
            fputs("HelperDaemon: refused client: this background service has no signing "
                  + "certificate (ad-hoc build); sign with scripts/dev-signing-identity.sh\n", stderr)
            return false
        }
        guard ClientRequirement.runningProcess(pid: connection.processIdentifier,
                                               satisfies: requirement) else {
            fputs("HelperDaemon: refused client pid \(connection.processIdentifier): "
                  + "not the App signed like this service\n", stderr)
            return false
        }
        connection.setCodeSigningRequirement(requirement)
        // The uid is supplied by XPC, never by the caller's payload. Claim
        // ownership only after signing validation; retain it through grace.
        guard clientUID.accept(connection.effectiveUserIdentifier) else {
            fputs("HelperDaemon: refused client from another login session\n", stderr)
            return false
        }
        connection.exportedInterface = NSXPCInterface(with: AlwaysConnectHelperProtocol.self)
        connection.exportedObject = session
        connection.remoteObjectInterface = NSXPCInterface(
            with: AlwaysConnectHelperClientProtocol.self)
        // Unsubscribe only: the engine keeps running (and pf keeps
        // holding) whether or not any App is attached.
        connection.invalidationHandler = { [weak self, weak connection] in
            guard let self, let connection else { return }
            self.session.removeClient(connection)
        }
        connection.resume()
        session.addClient(connection)
        return true
    }
}

/// The daemon's one VPN session: translates XPC calls into engine
/// actions and engine state into XPC pushes to every attached App.
/// All mutable state lives on `queue`; XPC replies and engine
/// callbacks arrive on arbitrary threads and hop onto it.
final class HelperSession: NSObject, AlwaysConnectHelperProtocol {
    private let queue = DispatchQueue(label: "com.alwaysconnect.helper.session")
    private var clients: [ObjectIdentifier: NSXPCConnection] = [:]
    private var engine: CLIOrchestrator?
    /// The parameters of the engine currently running (nil once it
    /// reaches a terminal state). A repeated connect with the same
    /// parameters — the App relaunching and auto-connecting — joins
    /// the running session instead of tearing it down.
    private var activeParameters: [String]?
    /// Set by prepareRelay, used by the next connect (DESIGN.md §二十三).
    private var relay: RelaySettings?
    /// Names that go out the local network (DESIGN.md §26.5), from the App.
    private var directDomains: [String] = []
    /// The App's direct networks (its list and the local network), kept
    /// for the next engine: one that starts takes over a held set at
    /// once and must pass the LAN from its first second (§30.1).
    private var allowNetworks: [String] = []
    /// 断线保护 for the own connection (DESIGN.md §26.19), from the App.
    private var requiresLoginPreparation = !TestSeam.isActive
    private var preparedLogin: (target: GatewayAddress, gateways: [String], physical: String, cisco: Bool)?
    private var pendingLogin: (ticket: UInt64, target: GatewayAddress, physical: String, cisco: Bool)?
    private var dropProtection = true
    private var egress = EgressProtection()
    private var egressConfigured = false
    private var probingEgress = false
    private var lastStateCode = 0
    private var lastDetail = ""
    /// Last terminal reason code + drop-episode retries, for
    /// getSessionInfo (DESIGN.md §十九): 0 = none/ongoing,
    /// 1 = manual stop, 2 = credentials rejected, 3 = attempts
    /// exhausted. Reset on every new connect.
    private var lastReasonCode = 0
    private var lastRetryCount = 0

    /// One timestamped line to the daemon's stderr (launchd's
    /// StandardErrorPath when configured). Engine details only:
    /// never credentials, never raw child output.
    static func log(_ line: String) {
        let stamp = ISO8601DateFormatter().string(from: Date())
        FileHandle.standardError.write(Data("\(stamp) \(line)\n".utf8))
    }

    /// Keeps the daemon's log (launchd's StandardErrorPath) bounded
    /// (§32.3): it only ever grew, and the dev install logs every
    /// redacted openconnect line of every login. Over `limit` bytes it
    /// is cut to its last `keep` bytes, from the start of a line. Run at
    /// start and on every connect; stderr that is not a file is left.
    static func trimLog(limit: Int = 4_000_000, keep: Int = 1_000_000) {
        var info = stat()
        guard fstat(STDERR_FILENO, &info) == 0, info.st_mode & S_IFMT == S_IFREG,
              Int(info.st_size) > limit else { return }
        let size = Int(info.st_size)
        // launchd opens the file write-only: read it through its path.
        var path = [CChar](repeating: 0, count: Int(MAXPATHLEN))
        guard fcntl(STDERR_FILENO, F_GETPATH, &path) == 0 else { return }
        let reader = open(path, O_RDONLY)
        guard reader >= 0 else { return }
        var tail = [UInt8](repeating: 0, count: keep)
        let read = pread(reader, &tail, keep, off_t(size - keep))
        Darwin.close(reader)
        guard read > 0 else { return }
        var kept = tail.prefix(read)
        if let newline = kept.firstIndex(of: 0x0A) { kept = kept[(newline + 1)...] }
        guard ftruncate(STDERR_FILENO, 0) == 0 else { return }
        lseek(STDERR_FILENO, 0, SEEK_SET)
        _ = kept.withUnsafeBytes { write(STDERR_FILENO, $0.baseAddress, $0.count) }
        log("log trimmed: was \(size) bytes, kept the last \(kept.count)")
    }

    /// No App attached and no session running or retrying.
    var isIdle: Bool {
        queue.sync { clients.isEmpty && activeParameters == nil && !NetworkGuard.shared.hasPendingLoginDeadline }
    }

    func addClient(_ connection: NSXPCConnection) {
        let app = AppRelauncher.App(pid: connection.processIdentifier,
                                    uid: connection.effectiveUserIdentifier)
        queue.async {
            self.clients[ObjectIdentifier(connection)] = connection
            self.ownerAttached(app: app)
            self.push(to: connection, state: self.lastStateCode, detail: self.lastDetail)
        }
    }

    /// Called (on `queue`) when the last App connection goes away.
    var onLastClientGone: (() -> Void)?

    func removeClient(_ connection: NSXPCConnection) {
        queue.async {
            guard self.clients.removeValue(forKey: ObjectIdentifier(connection)) != nil else { return }
            if self.clients.isEmpty { self.ownerGone() }
        }
    }

    private let relauncher = AppRelauncher()

    /// On `queue`. An App is attached: the gate's hold has an owner.
    func ownerAttached(app: AppRelauncher.App?) {
        if let app { relauncher.remember(app) }
        NetworkGuard.shared.ownerAttached()
    }

    /// Session harness only: an App attaching or vanishing, no XPC.
    func harnessOwner(attached: Bool, appPath: String? = nil) {
        queue.sync {
            if attached {
                ownerAttached(app: appPath.map { AppRelauncher.App(path: $0, uid: getuid()) })
            } else {
                ownerGone()
            }
        }
    }

    /// On `queue`. The last App went away. A quit releases first, so a
    /// hold still in place means the App did not quit on purpose
    /// (crash, force quit): start the gate's grace clock and try to
    /// bring the App back (DESIGN.md §25.2).
    func ownerGone() {
        // After the user's own release (a quit, a disconnect) the App
        // leaving is expected: no relaunch, even if a late engine event
        // briefly re-created a hold (it is released by the engine's own
        // wind-down).
        let sessionActive = (activeParameters != nil || pendingLogin != nil) && !userReleased
        NetworkGuard.shared.ownerLost(sessionActive: sessionActive)
        if !userReleased, NetworkGuard.shared.isHolding || sessionActive {
            relauncher.relaunch()
        }
        onLastClientGone?()
    }

    /// Set by the user's release, cleared by the next connect or arm.
    private var userReleased = false

    func connect(
        server: String,
        group: String,
        username: String,
        password: String,
        withReply reply: @escaping (Bool) -> Void
    ) {
        queue.async {
            // A new relay (the App restarted it: new pin, maybe a new
            // gateway address) must restart the engine too.
            let parameters = [server, group, username, password,
                              self.relay?.gatewayIp ?? "", self.relay?.serverPin ?? ""]
            if self.activeParameters == parameters {
                reply(true)
                return
            }
            self.startEngine(server: server, group: group, username: username,
                             password: password, parameters: parameters, reply: reply)
        }
    }

    /// On `queue`. Different parameters while an engine runs (the
    /// Credentials page's test connection) replace it, as before.
    /// An engine still winding down (a replacement waits for it), and
    /// the start that waits: a later connect or a disconnect bumps the
    /// generation, so a superseded start never runs.
    private var stoppingEngine: CLIOrchestrator?
    private var startGeneration = 0

    private func startEngine(
        server: String, group: String, username: String, password: String,
        parameters: [String], reply: @escaping (Bool) -> Void
    ) {
        startGeneration += 1
        userReleased = false
        let generation = startGeneration
        // Replacing a running engine (new server, new relay): stop it
        // the whole way first — routes back, its own pf hold released —
        // then start the new one (§25.7). Starting at once left the old
        // blocking set and missing default route in the new one's way.
        var sameLogin = false
        if let previous = engine, let running = activeParameters {
            stoppingEngine = previous
            // Same server, group and user: only the App's relay changed
            // (the App was reopened, or picked another gateway address).
            sameLogin = Array(running.prefix(3)) == Array(parameters.prefix(3))
        }
        engine = nil
        activeParameters = nil
        if stoppingEngine != nil, dropProtection, NetworkGuard.shared.isHolding {
            // Fail-closed handover (§30.1): the outgoing engine's release
            // is ignored from here, the new one takes the set over at its
            // start. Before, the network was open for the whole new login.
            NetworkGuard.shared.supersedeOwnHolders()
        }
        if let stopping = stoppingEngine {
            var started = false
            let begin: () -> Void = { [weak self] in
                guard let self else { return }
                self.queue.async {
                    guard !started else { return }
                    started = true
                    if self.stoppingEngine === stopping { self.stoppingEngine = nil }
                    guard generation == self.startGeneration else { reply(false); return }
                    self.startEngineNow(server: server, group: group, username: username,
                                        password: password, parameters: parameters, reply: reply)
                }
            }
            stopping.stop(keepSession: sameLogin, completion: begin)
            // Fallback only: the old engine's own restore must not land
            // on top of the new session's routes (§30.3).
            queue.asyncAfter(deadline: .now() + 20) { begin() }
            return
        }
        startEngineNow(server: server, group: group, username: username,
                       password: password, parameters: parameters, reply: reply)
    }

    private func startEngineNow(
        server: String, group: String, username: String, password: String,
        parameters: [String], reply: @escaping (Bool) -> Void
    ) {
        // A helper upgrade, stale relay or direct XPC caller cannot skip protection.
        // The non-root session harness exercises legacy starts with its private firewall.
        let login = preparedLogin
        if dropProtection && requiresLoginPreparation {
            guard let login, !login.cisco, login.target == GatewayAddress(server),
                  relay.map({ login.gateways.contains($0.gatewayIp) }) ?? true else {
                let firewall = NetworkGuard.shared
                let holder = firewall.newOwnHolder()
                _ = firewall.installLogin(holder: holder, physical: "", gateways: [],
                                          port: GatewayAddress(server)?.port ?? 443, cisco: false, verify: false)
                Self.log("protected login paused: missing current preparation")
                reply(false); return
            }
        }
        lastReasonCode = 0
        lastRetryCount = 0
        let script: String
        do {
            script = try VpncScript.install()
        } catch {
            reply(false)
            return
        }
        var config = CLIOrchestrator.Config(
            server: server,
            group: group,
            username: username,
            password: password,
            openconnectPath: nil,
            scriptPath: script,
            cookieStore: CookieStore(fileURL: CookieStore.defaultFileURL),
            physicalIf: "en0",
            allowNetworks: allowNetworks,  // the App's last push (§27.1, §30.1)
            maxAttempts: nil,
            noRoutes: TestSeam.isActive,
            supportDir: nil
        )
        config.relay = relay
        // Own connection: the domain split's forwarder runs (§26.5).
        if relay != nil { config.directDomains = directDomains }
        if relay != nil { config.egress = egress }
        config.dropProtection = dropProtection
        if !TestSeam.isActive || login != nil {
            config.loginTarget = GatewayAddress(server)
            config.loginGateways = login?.gateways ?? []
            if let login { config.physicalIf = login.physical }
        }
        // Redacted child output into the daemon's log (launchd
        // StandardErrorPath), only when the plist opts in: the dev
        // install does, to record the real gateway's output shapes
        // (approval wait, rejection text) that DESIGN §16.5 waits on.
        config.debugChildOutput =
            ProcessInfo.processInfo.environment["ALWAYSCONNECT_DEBUG_CHILD_OUTPUT"] == "1"
        Self.trimLog()
        let engine = CLIOrchestrator(config: config)
        engine.onState = { [weak self, weak engine] state, detail in
            guard let self, let engine else { return }
            let retries = engine.episodeRetries
            Self.log("state=\(state.rawValue) \(detail)")
            self.queue.async {
                guard self.engine === engine else { return }
                self.lastStateCode = state.rawValue
                self.lastDetail = detail
                self.lastRetryCount = retries
                self.push(state: state.rawValue, detail: detail)
            }
        }
        engine.onTerminal = { [weak self, weak engine] reason in
            guard let self, let engine else { return }
            let retries = engine.episodeRetries
            let error = engine.lastError
            Self.log("terminal=\(reason)")
            self.queue.async {
                guard self.engine === engine else { return }
                // A finished engine is gone: keeping the object made the
                // next disconnect (in Cisco mode) call its no-op stop()
                // instead of releasing the kill switch (§25.1, F1).
                self.engine = nil
                self.activeParameters = nil
                switch reason {
                case .stoppedManual: self.lastReasonCode = 1
                case .authFailure: self.lastReasonCode = 2
                case .attemptsExhausted: self.lastReasonCode = 3
                case .componentMissing: self.lastReasonCode = 4
                case .approvalDeclined: self.lastReasonCode = 5
                }
                self.lastRetryCount = retries
                // Terminal state is already reflected by the last pushed
                // state + detail; the App maps authFailure to its error row.
                if reason == .authFailure || reason == .approvalDeclined, let error {
                    self.push(state: self.lastStateCode, detail: error)
                }
            }
        }
        self.engine = engine
        activeParameters = parameters
        engine.start()
        reply(true)
    }

    /// The user asked for the direct network back: every holder lets
    /// go, whatever ran before in this service's lifetime (§25.1, F1).
    func disconnect(withReply reply: @escaping () -> Void) {
        queue.async {
            self.releaseEverythingLocked(reason: NetworkGuard.Reason.user)
            reply()
        }
    }

    /// The same, when the gate's grace ended with no App back.
    func releaseEverything(reason: String) {
        queue.sync {
            // The grace callback hops queues; an App that attached in
            // between keeps its session.
            if reason == NetworkGuard.Reason.appGone, !clients.isEmpty { return }
            releaseEverythingLocked(reason: reason)
        }
    }

    /// On `queue`. pf first — the network is direct the moment this
    /// returns — then the parts that take their time.
    private func releaseEverythingLocked(reason: String) {
        pendingLogin = nil
        startGeneration += 1 // a replacement waiting to start never does
        preparedLogin = nil
        if reason == NetworkGuard.Reason.user { userReleased = true }
        NetworkGuard.shared.release(holder: nil, reason: reason)
        // The Cisco kill switch, always: an own-connection engine
        // object must never stand in for it.
        KillSwitch.shared.disarm()
        if let engine, activeParameters != nil {
            // A running own connection restores routes itself once
            // openconnect has logged out.
            engine.stop()
        } else {
            engine = nil
            activeParameters = nil
            // No engine running: a Cisco session, or a service
            // restarted under a held set (DESIGN.md §20.4, §二十一).
            if let script = try? VpncScript.install() {
                CLIOrchestrator.restoreLocalNetworkWithoutEngine(scriptPath: script, reason: reason)
            }
        }
    }

    func setDirectDomains(_ domains: [String], withReply reply: @escaping (Bool) -> Void) {
        queue.async {
            // Rules as the App expanded them (§26.13); SplitRules ignores
            // what it does not understand.
            self.directDomains = domains.map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
            self.engine?.updateDirectDomains(self.directDomains)
            reply(true)
        }
    }

    func setDropProtection(_ on: Bool, withReply reply: @escaping (Bool) -> Void) {
        queue.async {
            let wasGated = self.dropProtection && self.egress.isActive
            self.dropProtection = on
            if !on {
                if self.pendingLogin != nil {
                    self.pendingLogin = nil
                    NetworkGuard.shared.release(holder: nil, reason: NetworkGuard.Reason.user)
                }
                self.preparedLogin = nil
                self.egress.enabled = false
                if wasGated && self.restartForEgressChange() { reply(true); return }
            }
            if let engine = self.engine {
                engine.updateDropProtection(on)
            } else if !on, let held = NetworkGuard.shared.held, held.holder != NetworkGuard.ciscoHolder {
                // Switched off with no engine to ask: a set a restarted
                // service adopted or a refused login left (§30.1) goes
                // now, as the switch promises.
                if let script = try? VpncScript.install() {
                    CLIOrchestrator.restoreLocalNetworkWithoutEngine(scriptPath: script,
                                                                     reason: NetworkGuard.Reason.user)
                }
            }
            reply(true)
        }
    }

    /// Use the normal same-login handover so the cookie and network hold survive.
    @discardableResult
    private func restartForEgressChange() -> Bool {
        guard relay != nil, let parameters = activeParameters else { return false }
        startEngine(server: parameters[0], group: parameters[1], username: parameters[2],
                    password: parameters[3], parameters: parameters) { _ in }
        return true
    }

    func setEgressProtection(_ json: String, withReply reply: @escaping (Bool) -> Void) {
        queue.async {
            guard ac_egress_config_valid(json),
                  let config = try? JSONDecoder().decode(EgressProtection.self, from: Data(json.utf8)),
                  !config.enabled || self.dropProtection else { reply(false); return }
            // The first profile hydration may restore already confirmed prefixes. A live
            // edit that enables or expands source trust must use a confirmation endpoint.
            if (self.egressConfigured || self.engine != nil) && config.groups.contains(where: { next in
                guard next.exitRangeCheck else { return false }
                let old = self.egress.groups.first { $0.id == next.id }
                return old?.exitRangeCheck != true || !Set(next.exitRanges).isSubset(of: Set(old?.exitRanges ?? []))
            }) { reply(false); return }
            self.applyEgressConfiguration(config, json: json)
            reply(true)
        }
    }

    private func applyEgressConfiguration(_ config: EgressProtection, json: String) {
        let modeChanged = config.isActive != egress.isActive
        egress = config
        egressConfigured = true
        if relay != nil && modeChanged {
            // Only switching the gate on or off changes how OpenConnect is started.
            HelperSession.log("egress: protection turned \(config.isActive ? "on" : "off"); reconnecting with the same login")
        }
        if relay != nil && !(modeChanged && restartForEgressChange()) { engine?.updateEgress(json) }
    }

    func confirmEgressRangeSetup(_ proposed: String, previous: String, group: UInt32, proof: String,
                                withReply reply: @escaping (Bool) -> Void) {
        queue.async {
            guard self.dropProtection, !self.userReleased, self.relay != nil,
                  ac_egress_config_valid(proposed),
                  let old = try? JSONDecoder().decode(EgressProtection.self, from: Data(previous.utf8)),
                  let new = try? JSONDecoder().decode(EgressProtection.self, from: Data(proposed.utf8)),
                  self.egress == old,
                  self.engine?.confirmRangeSetup(previous, proposed: proposed, group: group, proof: proof) == true else {
                reply(false); return
            }
            self.applyEgressConfiguration(new, json: proposed)
            reply(true)
        }
    }

    func allowEgressRange(_ cidr: String, group: UInt32, started: Double, evidence: String,
                          withReply reply: @escaping (Bool, [String]) -> Void) {
        queue.async {
            guard self.dropProtection, self.egress.isActive,
                  let index = self.egress.groups.firstIndex(where: { $0.id == group && $0.enabled && $0.exitRangeCheck }),
                  let ranges = self.engine?.allowEgressRange(cidr, group: group, started: started,
                                                             evidence: evidence, expected: self.egress) else {
                reply(false, []); return
            }
            self.egress.groups[index].exitRanges = ranges
            reply(true, ranges)
        }
    }

    func getEgressStatus(withReply reply: @escaping (String) -> Void) {
        queue.async { reply(self.engine?.egressStatus() ?? "{}") }
    }

    func retryLoginNow(withReply reply: @escaping (Bool) -> Void) {
        queue.async {
            let taken = self.engine?.retryNow() ?? false
            if taken { HelperSession.log("login retry requested by the user") }
            reply(taken)
        }
    }

    func setUnknownWebException(_ address: String, port: Int, allow: Bool, approvalId: String,
                                withReply reply: @escaping (Bool) -> Void) {
        queue.async {
            guard self.dropProtection, self.egress.isActive, !self.userReleased, [80,443,8443].contains(port),
                  let engine = self.engine else { reply(false); return }
            reply(engine.setUnknownWebException(address, port: UInt16(port), allow: allow, approvalId: approvalId))
        }
    }

    func recheckEgressFailures(_ group: UInt32, withReply reply: @escaping (Bool) -> Void) {
        queue.async {
            guard self.dropProtection, self.egress.isActive, let engine = self.engine else { reply(false); return }
            DispatchQueue.global(qos: .userInitiated).async {
                let finished = engine.recheckEgressFailures(group)
                self.queue.async { reply(finished && self.engine === engine) }
            }
        }
    }

    func allowEgressCountry(_ country: String, group: UInt32, started: Double, evidence: String,
                            withReply reply: @escaping (Bool, [String]) -> Void) {
        queue.async {
            guard self.dropProtection, self.egress.isActive,
                  let index = self.egress.groups.firstIndex(where: { $0.id == group && $0.enabled }),
                  let countries = self.engine?.allowEgressCountry(country, group: group, started: started,
                                                                  evidence: evidence, expected: self.egress) else {
                reply(false, [])
                return
            }
            self.egress.groups[index].expect = countries
            reply(true, countries)
        }
    }

    func probeEgress(_ host: String, withReply reply: @escaping (String) -> Void) {
        queue.async {
            guard self.relay != nil, !self.probingEgress, let engine = self.engine else { reply("[]"); return }
            self.probingEgress = true
            DispatchQueue.global(qos: .userInitiated).async {
                let result = engine.probeEgress(host)
                self.queue.async {
                    self.probingEgress = false
                    reply(self.engine === engine ? result : "[]")
                }
            }
        }
    }

    func probeEgressSummary(_ host: String, method: String, withReply reply: @escaping (String) -> Void) {
        func failure(_ reason: String, status: String = "unavailable") -> String {
            let fields: [String: Any] = [
                "host": "", "method": "", "status": status, "error": reason,
                "resolvedAddressCount": 0, "probedAddressCount": 0,
                "truncated": false, "coverageIncomplete": true, "results": [],
            ]
            guard let data = try? JSONSerialization.data(withJSONObject: fields) else { return "{}" }
            return String(decoding: data, as: UTF8.self)
        }
        queue.async {
            guard host.utf8.count <= 254, !host.utf8.contains(0) else {
                reply(failure("invalidHost", status: "invalid")); return
            }
            guard method.utf8.count <= 524_288, !method.utf8.contains(0) else {
                reply(failure("invalidMethod", status: "invalid")); return
            }
            guard self.relay != nil, !self.userReleased, let engine = self.engine else {
                reply(failure("tunnelUnavailable")); return
            }
            guard !self.probingEgress else { reply(failure("busy")); return }
            self.probingEgress = true
            DispatchQueue.global(qos: .userInitiated).async {
                let result = engine.probeEgressSummary(host, method: method)
                self.queue.async {
                    self.probingEgress = false
                    reply(self.engine === engine && !self.userReleased ? result : failure("tunnelUnavailable"))
                }
            }
        }
    }

    func getSplitActivity(withReply reply: @escaping ([String], Int, Bool) -> Void) {
        queue.async {
            guard let engine = self.engine else { reply([], 0, false); return }
            let (entries, addresses) = engine.splitActivity()
            reply(entries, addresses, true)
        }
    }

    func getSplitStatus(withReply reply: @escaping (String) -> Void) {
        queue.async { reply(self.engine?.splitStatusJSON() ?? "{}") }
    }

    func getConnections(withReply reply: @escaping (String) -> Void) {
        queue.async {
            let engine = self.engine
            let cisco = KillSwitch.shared.snapshot
            DispatchQueue.global(qos: .userInitiated).async {
                let fallback = cisco?.gatewayIps ?? []
                reply(engine?.connectionsJSON(fallbackGateways: fallback)
                      ?? CLIOrchestrator.connectionsJSONWithoutEngine(gateways: fallback))
            }
        }
    }

    func updateAllowNetworks(_ networks: [String], withReply reply: @escaping (Bool) -> Void) {
        queue.async {
            let valid = networks.map { $0.trimmingCharacters(in: .whitespaces) }.filter { isValidCIDR($0) }
            if NetworkGuard.shared.held?.inputs.loginPort == nil {
                KillSwitch.shared.updateAllowNetworks(networks)
            }
            self.allowNetworks = valid
            guard let engine = self.engine else {
                // Held with no engine (a refused login, §30.1): the new
                // LAN gets through the held set too.
                NetworkGuard.shared.updateHeldAllowNetworks(valid)
                reply(true)
                return
            }
            engine.updateAllowNetworks(networks)
            reply(true)
        }
    }

    func getSessionInfo(withReply reply: @escaping (Int, Int) -> Void) {
        queue.async { reply(self.lastReasonCode, self.lastRetryCount) }
    }

    func getStatus(withReply reply: @escaping (Int, String) -> Void) {
        queue.async { reply(self.lastStateCode, self.lastDetail) }
    }

    func getNetworkHeld(withReply reply: @escaping (Bool) -> Void) {
        queue.async { reply(CLIOrchestrator.localNetworkHeld()) }
    }

    func getLastRelease(withReply reply: @escaping (String, Double) -> Void) {
        let last = NetworkGuard.shared.lastRelease
        reply(last?.reason ?? "", last?.at.timeIntervalSince1970 ?? 0)
    }

    /// SIGTERM from launchd: take the openconnect child down too.
    func shutdown() {
        let current = queue.sync { engine }
        current?.killChild()
    }

    private func activeRelayEngine(_ pin: String) -> CLIOrchestrator? {
        guard !userReleased, !pin.isEmpty, relay?.serverPin == pin, activeParameters?.last == pin else { return nil }
        return engine
    }

    func gatewayCertificateRejected(_ serverPin: String, withReply reply: @escaping (Bool) -> Void) {
        recordGatewayRejection(serverPin, incident: 0, withReply: reply)
    }

    func recordGatewayRejection(_ serverPin: String, incident: UInt64, withReply reply: @escaping (Bool) -> Void) {
        queue.async { reply(self.activeRelayEngine(serverPin)?.rejectGatewayCertificate(incident) ?? false) }
    }

    func hasVerifiedRelayTunnel(_ serverPin: String, incident: UInt64, withReply reply: @escaping (Bool) -> Void) {
        queue.async {
            let direct = serverPin.isEmpty && !self.userReleased && self.relay == nil && self.activeParameters?.last == ""
            let engine = direct ? self.engine : self.activeRelayEngine(serverPin)
            reply(engine?.hasVerifiedTunnel(incident) ?? false)
        }
    }

    private func loginAddresses(for target: GatewayAddress, cisco: Bool, candidate: String = "") -> [String] {
        var addresses = LoginGatewayCache.lookup(in: CLIOrchestrator.defaultSupportDir, target: target)
        if NetworkGuard.isIPAddress(candidate), !addresses.contains(candidate) {
            addresses.insert(candidate, at: 0)
        }
        if !cisco { addresses = addresses.filter(isValidIPv4) }
        return Array(addresses.prefix(8))
    }

    func hasTrustedLoginGateway(_ server: String, cisco: Bool, withReply reply: @escaping (Bool) -> Void) {
        getLoginGatewayReadiness(server, cisco: cisco) { reply($0 == 1) }
    }

    private func savedGatewayReadiness(_ target: GatewayAddress, cisco: Bool) -> Int {
        guard let peers = LoginGatewayCache.read(in: CLIOrchestrator.defaultSupportDir, target: target) else { return -1 }
        return peers.contains(where: { cisco || isValidIPv4($0) }) ? 1 : 0
    }

    func getLoginGatewayReadiness(_ server: String, cisco: Bool, withReply reply: @escaping (Int) -> Void) {
        queue.async {
            guard let target = GatewayAddress(server) else { reply(-1); return }
            reply(self.savedGatewayReadiness(target, cisco: cisco))
        }
    }

    private func startLoginHolder(cisco: Bool) -> String {
        self.requiresLoginPreparation = true
        self.preparedLogin = nil
        self.pendingLogin = nil
        self.startGeneration += 1
        self.userReleased = false
        self.dropProtection = true
        let firewall = NetworkGuard.shared
        firewall.supersedeOwnHolders()
        return cisco ? NetworkGuard.ciscoHolder : firewall.newOwnHolder()
    }

    private func loginPhysicalInterface() -> String? {
        TestSeam.isActive ? "en0" : PhysicalNetwork.current(preferring: "")?.interface
    }

    private func loginDirectInterface() -> String? {
        TestSeam.isActive ? "en0" : NetworkGuard.take(ac_login_direct_interface())
    }

    private func installProtectedLogin(target: GatewayAddress?, holder: String, cisco: Bool, candidate: String,
                                       blockOnly: Bool = false, emptyNotice: String = ProtectedLoginNotice.noTrustedAddress,
                                       reply: (Bool, [String], String) -> Void) {
        func reject(_ message: String) {
            Self.log("protected login paused: " + message)
            reply(false, [], message)
        }
        let firewall = NetworkGuard.shared
        let port = target?.port ?? 443
        if let error = firewall.installLogin(holder: holder, physical: "", gateways: [], port: port, cisco: cisco, verify: false) {
            reject(error); return
        }
        guard let target, let physical = loginPhysicalInterface() else {
            reject("网关或物理网络不可用，登录已暂停"); return
        }
        let addresses = blockOnly ? [] : loginAddresses(for: target, cisco: cisco, candidate: candidate)
        if let error = firewall.installLogin(holder: holder, physical: physical, gateways: addresses,
                                             port: port, cisco: cisco, verify: true) {
            _ = firewall.installLogin(holder: holder, physical: physical, gateways: [], port: port, cisco: cisco, verify: false)
            reject(error); return
        }
        guard !addresses.isEmpty else { reject(emptyNotice); return }
        preparedLogin = (target, addresses, physical, cisco)
        Self.log(candidate.isEmpty ? "protected login verified (cache only)" : "protected login verified")
        reply(true, addresses, "")
    }

    func beginProtectedLogin(_ server: String, cisco: Bool, candidate: String,
                             withReply reply: @escaping (Bool, [String], String) -> Void) {
        queue.async {
            self.installProtectedLogin(target: GatewayAddress(server), holder: self.startLoginHolder(cisco: cisco),
                                       cisco: cisco, candidate: candidate, reply: reply)
        }
    }

    func requestProtectedLogin(_ server: String, cisco: Bool, candidate: String, rejected: Bool,
                               allowPreparation: Bool, deadline: UInt64,
                               withReply reply: @escaping (UInt64, Bool, [String], String) -> Void) {
        queue.async {
            let firewall = NetworkGuard.shared
            let canPrepare = allowPreparation && !rejected && candidate.isEmpty && self.pendingLogin == nil
                && self.activeParameters == nil && !firewall.isHolding
            let target = GatewayAddress(server)
            let holder = self.startLoginHolder(cisco: cisco)
            func protect(blockOnly: Bool, notice: String = ProtectedLoginNotice.noTrustedAddress) {
                self.installProtectedLogin(target: target, holder: holder, cisco: cisco, candidate: candidate,
                                           blockOnly: blockOnly, emptyNotice: notice) { reply(0, $0, $1, $2) }
            }
            guard canPrepare, let target else {
                protect(blockOnly: rejected); return
            }
            switch self.savedGatewayReadiness(target, cisco: cisco) {
            case 0: break
            case 1: protect(blockOnly: false); return
            default: protect(blockOnly: true, notice: "网络已拦截。后台服务无法核实已保存的网关地址。"); return
            }
            guard DispatchTime.now().uptimeNanoseconds < deadline else {
                protect(blockOnly: true, notice: ProtectedLoginNotice.preparationTimedOut); return
            }
            guard let physical = self.loginDirectInterface() else {
                protect(blockOnly: true, notice: ProtectedLoginNotice.preparationUnavailable); return
            }
            let ticket = firewall.armLoginDeadline(holder: holder, physical: physical, port: target.port,
                                                   cisco: cisco, deadline: deadline)
            guard ticket != 0 else {
                let notice = DispatchTime.now().uptimeNanoseconds >= deadline
                    ? ProtectedLoginNotice.preparationTimedOut : ProtectedLoginNotice.preparationUnavailable
                protect(blockOnly: true, notice: notice); return
            }
            self.pendingLogin = (ticket, target, physical, cisco)
            // The anchor audit may have consumed the remainder of the budget.
            guard DispatchTime.now().uptimeNanoseconds < deadline, !firewall.isHolding else {
                self.finishPendingLogin(ticket, candidate: "", emptyNotice: ProtectedLoginNotice.preparationUnavailable) {
                    reply(0, $0, $1, $2)
                }
                return
            }
            reply(ticket, false, [], "")
        }
    }

    private func finishPendingLogin(_ ticket: UInt64, candidate: String, emptyNotice: String,
                                    reply: (Bool, [String], String) -> Void) {
        guard let pending = pendingLogin, pending.ticket == ticket, !userReleased else {
            reply(false, [], "连接请求已过期"); return
        }
        pendingLogin = nil
        let usable = pending.cisco ? NetworkGuard.isIPAddress(candidate) : isValidIPv4(candidate)
        let routeChanged = usable && loginDirectInterface() != pending.physical
        let peers = usable && !routeChanged ? [candidate] : []
        let firewall = NetworkGuard.shared
        if let error = firewall.finishLoginDeadline(ticket, gateways: peers) {
            let notice = firewall.loginDeadlineStatus(ticket) == .timedOutBlocked ? ProtectedLoginNotice.preparationTimedOut : error
            Self.log("protected login paused: " + notice)
            reply(false, [], notice)
        } else if peers.isEmpty {
            let notice = routeChanged ? ProtectedLoginNotice.preparationUnavailable : emptyNotice
            Self.log("protected login paused: " + notice)
            reply(false, [], notice)
        } else {
            preparedLogin = (pending.target, peers, pending.physical, pending.cisco)
            Self.log("protected login verified (prepared gateway)")
            reply(true, peers, "")
        }
    }

    func finishProtectedLogin(_ ticket: UInt64, candidate: String,
                              withReply reply: @escaping (Bool, [String], String) -> Void) {
        queue.async {
            self.finishPendingLogin(ticket, candidate: candidate, emptyNotice: ProtectedLoginNotice.noTrustedAddress, reply: reply)
        }
    }

    func prepareRelay(gatewayIp: String, serverPin: String,
                      withReply reply: @escaping (String) -> Void) {
        queue.async {
            guard !gatewayIp.isEmpty else {
                self.relay = nil
                reply("")
                return
            }
            var v4 = in_addr()
            guard inet_pton(AF_INET, gatewayIp, &v4) == 1, RelaySettings.isValidPin(serverPin),
                  let files = try? RelayClientIdentity.ensure(supportDir: CLIOrchestrator.defaultSupportDir)
            else {
                Self.log("prepareRelay rejected")
                reply("")
                return
            }
            self.relay = RelaySettings(
                gatewayIp: gatewayIp, serverPin: serverPin,
                certificatePath: files.certificatePath, keyPath: files.keyPath)
            Self.log("prepareRelay ok")
            reply(files.certificatePEM)
        }
    }

    func setKillSwitch(_ mode: Int, tunnelIf: String, gatewayIps: [String],
                       withReply reply: @escaping (Bool, String) -> Void) {
        guard let parsed = KillSwitch.Mode(rawValue: mode) else {
            reply(false, "unknown kill switch mode")
            return
        }
        // Serialize the system effect too, not just userReleased: an older
        // queued disconnect must never unload a new session's protection.
        queue.async {
            if parsed != .off { self.userReleased = false }
            let login = self.preparedLogin
            KillSwitch.shared.set(mode: parsed, tunnelIf: tunnelIf, gatewayIps: gatewayIps) { ok, message in
                if ok, parsed == .connected, let login, login.cisco, gatewayIps.count == 1,
                   login.gateways.contains(gatewayIps[0]) {
                    if !LoginGatewayCache.rememberConnected(in: CLIOrchestrator.defaultSupportDir,
                                                           target: login.target, peer: gatewayIps[0]) {
                        Self.log("gateway cache write failed")
                    }
                }
                reply(ok, message)
            }
        }
    }

    func evaluateRule(
        app: String,
        domain: String,
        ip: String,
        rulesJSON: String,
        defaultMode: Int,
        withReply reply: @escaping (Int, String) -> Void
    ) {
        let (direction, reason) = RuleEvaluator.evaluate(
            app: app, domain: domain, ip: ip,
            rulesJSON: rulesJSON, defaultMode: defaultMode)
        reply(direction, reason)
    }

    func resolveGatewayIPv4(_ host: String, withReply reply: @escaping ([String]) -> Void) {
        if let held = NetworkGuard.shared.held, held.inputs.loginPort != nil && held.inputs.tunnelIf.isEmpty {
            reply([]); return
        }
        guard let lease = GatewayLookupLease() else { reply([]); return }
        DispatchQueue.global(qos: .utility).async {
            withExtendedLifetime(lease) {
                let context = NetworkGuard.shared.gatewayBootstrapContext
                guard ac_gateway_active(lease.handle),
                      let network = PhysicalNetwork.current(preferring: context?.physicalIf ?? "") else { reply([]); return }
                let servers = context?.localDNSServers ?? LocalDNS.servers(for: network.interface)
                let csv = NetworkGuard.take(ac_resolve_gateway(lease.handle, host, servers.joined(separator: ","), network.interface)) ?? ""
                reply(csv.split(separator: ",").map(String.init))
            }
        }
    }

    func getStats(withReply reply: @escaping (Int64, Int64, String) -> Void) {
        queue.async {
            guard let tunnelIf = self.engine?.tunnelInterface else {
                reply(0, 0, "")
                return
            }
            let (bytesIn, bytesOut) = SystemChecks.interfaceBytes(tunnelIf)
            reply(bytesIn, bytesOut, tunnelIf)
        }
    }

    func runLeakCheck(withReply reply: @escaping (String) -> Void) {
        queue.async {
            let engine = self.engine
            if let engine {
                // Read-only subprocesses must not occupy the session's serial
                // queue: disconnect and recovery stay responsive.
                DispatchQueue.global(qos: .utility).async { reply(engine.runNetworkCheck()) }
                return
            }
            // Cisco engine (DESIGN.md §二十一): no engine of ours, the
            // kill switch knows the tunnel and the gateways.
            let cisco = engine?.tunnelInterface == nil ? KillSwitch.shared.snapshot : nil
            let items = SystemChecks.runLeakCheck(
                tunnelIf: engine?.tunnelInterface ?? cisco?.tunnelIf,
                // Only the live session's server (listed first) must
                // route via the physical interface; the other gateways
                // in the allowlist are spares that may route anywhere.
                gatewayIps: engine?.gatewayAddresses ?? Array((cisco?.gatewayIps ?? []).prefix(1)),
                physicalIf: engine?.physicalInterface ?? cisco?.physicalIf ?? "en0",
                tunnelDns: engine?.tunnelDnsServers ?? [])
            let data = (try? JSONEncoder().encode(items)) ?? Data("[]".utf8)
            reply(String(data: data, encoding: .utf8) ?? "[]")
        }
    }

    /// On `queue`.
    private func push(state: Int, detail: String) {
        for connection in clients.values {
            push(to: connection, state: state, detail: detail)
        }
    }

    private func push(to connection: NSXPCConnection, state: Int, detail: String) {
        guard let proxy = connection.remoteObjectProxy
                as? AlwaysConnectHelperClientProtocol
        else { return }
        proxy.statusChanged(state: state, detail: detail)
    }
}

@_silgen_name("ac_resolve_gateway")
func ac_resolve_gateway(_ lease: OpaquePointer, _ host: UnsafePointer<CChar>, _ servers: UnsafePointer<CChar>, _ interface: UnsafePointer<CChar>) -> UnsafeMutablePointer<CChar>?


private final class GatewayLookupLease: @unchecked Sendable {
    let handle: OpaquePointer
    init?() { guard let handle = ac_gateway_claim() else { return nil }; self.handle = handle }
    deinit { ac_gateway_free(handle) }
}
@_silgen_name("ac_gateway_claim") func ac_gateway_claim() -> OpaquePointer?
@_silgen_name("ac_gateway_active") func ac_gateway_active(_ lease: OpaquePointer) -> Bool
@_silgen_name("ac_gateway_free") func ac_gateway_free(_ lease: OpaquePointer)

@_silgen_name("ac_login_direct_interface") private func ac_login_direct_interface() -> UnsafeMutablePointer<CChar>?
