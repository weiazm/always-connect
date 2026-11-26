import AppKit
import Security
import ServiceManagement

/// Installs the privileged Helper as a LaunchDaemon via SMAppService
/// (UI-DESIGN.md §七 Helper 未装 / 未运行).
///
/// The daemon plist + Helper binary are embedded in the App bundle by
/// the "Embed Helper daemon" build phase (project.yml):
/// Contents/Library/LaunchDaemons/. Real install effect needs a
/// signed build and admin authorization, so it is Mac-only to verify;
/// this code only compiles on CI.
///
/// register() on an already-registered service is treated as success:
/// the panel's install button must be idempotent. A first register()
/// of a daemon succeeds but leaves it in .requiresApproval until the
/// user enables it under System Settings > Login Items; that is not
/// success (the daemon is not running yet), so the installer opens
/// that pane and reports the pending approval instead.
enum HelperInstaller {
    /// The file name inside Contents/Library/LaunchDaemons, extension
    /// included: SMAppService looks the plist up by exact file name.
    private static let plistName = "com.alwaysconnect.app.helper.plist"

    enum InstallError: LocalizedError {
        case approvalRequired
        case notEnabled
        case cancelled
        case scriptFailed(String)

        var errorDescription: String? {
            switch self {
            case .approvalRequired:
                return "请在系统设置的登录项中允许 AlwaysConnect，再回到这里"
            case .notEnabled:
                return "后台服务未能启用，请检查系统设置中的登录项"
            case .cancelled:
                return "已取消：需要输入电脑密码才能安装"
            case .scriptFailed(let message):
                return "安装失败：\(message)"
            }
        }
    }

    /// Install failure in the user's words.
    static func failureText(_ error: Error) -> String {
        if let error = error as? InstallError {
            return error.errorDescription ?? "安装失败"
        }
        return "安装失败：\(error.localizedDescription)"
    }

    static var isTeamSigned: Bool {
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(Bundle.main.bundleURL as CFURL, [], &code) == errSecSuccess,
              let code else { return false }
        var info: CFDictionary?
        guard SecCodeCopySigningInformation(code, [], &info) == errSecSuccess,
              let dict = info as? [String: Any] else { return false }
        return dict[kSecCodeInfoTeamIdentifier as String] != nil
    }

    static var status: SMAppService.Status {
        SMAppService.daemon(plistName: plistName).status
    }

    /// A build without a developer-team signature cannot use
    /// SMAppService at all. It installs the same daemon the classic way
    /// instead (DESIGN.md §21.8): the bundled dev-helper.sh, run as root
    /// behind the standard macOS administrator password dialog — the
    /// user never has to open a terminal.
    static let installPrompt = "AlwaysConnect 要安装后台服务（断线时封网用）。"
    static let updatePrompt = "AlwaysConnect 已更新，要同时更新后台服务（断线时封网用）。"
    static let retryPrompt = "后台服务的自动更新没有完成，再授权一次就能装好（断线时封网用）。"

    private static func installWithAdminPassword(
        prompt: String,
        completion: @escaping (Result<Void, Error>) -> Void
    ) {
        PrivilegedBundle.run(resource: "dev-helper.sh", arguments: ["install"], helper: true,
                             prompt: prompt) { result in
            if let code = result.errorNumber {
                completion(.failure(code == -128 ? InstallError.cancelled
                                                 : InstallError.scriptFailed(result.errorMessage ?? "未知错误")))
            } else {
                completion(.success(()))
            }
        }
    }

    // MARK: - The service updates itself (§69.11)

    static let servicePlistPath = "/Library/LaunchDaemons/com.alwaysconnect.app.helper.plist"

    /// The installed service declares (in its world-readable launchd
    /// plist) that it knows updateService: asking an older one would drop
    /// the XPC connection.
    static var serviceCanUpdateItself: Bool {
        guard let plist = NSDictionary(contentsOfFile: servicePlistPath) as? [String: Any],
              let environment = plist["EnvironmentVariables"] as? [String: String] else { return false }
        return environment["ALWAYSCONNECT_SERVICE_UPDATE"] == "1"
    }

    /// `didNotReturn`: the service took the update but no new one answered
    /// (§69.15): never left like that, the password install follows.
    enum ServiceUpdateOutcome { case updated, cancelled, failed(String), didNotReturn(String), notTaken }

    /// The user's approval for ServiceUpdateRight, kept by `authorization`
    /// until the service has checked it. Blocks on the system dialog.
    private static func approval(prompt: String) -> (AuthorizationRef, Data)? {
        var authorization: AuthorizationRef?
        guard AuthorizationCreate(nil, nil, [], &authorization) == errAuthorizationSuccess,
              let authorization else { return nil }
        let granted: OSStatus = ServiceUpdateRight.name.withCString { name in
            kAuthorizationEnvironmentPrompt.withCString { promptKey in
                prompt.withCString { text in
                    var item = AuthorizationItem(name: name, valueLength: 0, value: nil, flags: 0)
                    var promptItem = AuthorizationItem(name: promptKey, valueLength: Int(strlen(text)),
                                                       value: UnsafeMutableRawPointer(mutating: text), flags: 0)
                    return withUnsafeMutablePointer(to: &item) { items in
                        withUnsafeMutablePointer(to: &promptItem) { environmentItems in
                            var rights = AuthorizationRights(count: 1, items: items)
                            var environment = AuthorizationEnvironment(count: 1, items: environmentItems)
                            return AuthorizationCopyRights(authorization, &rights, &environment,
                                                           [.interactionAllowed, .extendRights, .preAuthorize], nil)
                        }
                    }
                }
            }
        }
        guard granted == errAuthorizationSuccess else {
            AuthorizationFree(authorization, [.destroyRights])
            return granted == errAuthorizationCanceled ? (authorization, Data()) : nil
        }
        var external = AuthorizationExternalForm()
        guard AuthorizationMakeExternalForm(authorization, &external) == errAuthorizationSuccess else {
            AuthorizationFree(authorization, [.destroyRights])
            return nil
        }
        return (authorization, withUnsafeBytes(of: &external) { Data($0) })
    }

    private static func updateThroughService(prompt: String, completion: @escaping (ServiceUpdateOutcome) -> Void) {
        DispatchQueue.global(qos: .userInitiated).async {
            guard let (authorization, form) = approval(prompt: prompt) else {
                DispatchQueue.main.async { completion(.notTaken) }
                return
            }
            guard !form.isEmpty else {
                DispatchQueue.main.async { completion(.cancelled) }
                return
            }
            DispatchQueue.main.async {
                HelperClient.shared.askServiceToUpdate(form) { started, reason in
                    AuthorizationFree(authorization, [.destroyRights])
                    guard let started else { completion(.notTaken); return }
                    guard started else { completion(.failed(reason)); return }
                    waitForUpdatedService(deadline: Date().addingTimeInterval(60), completion: completion)
                }
            }
        }
    }

    /// The replaced service is ours once its code matches this App's and
    /// it answers again.
    private static func waitForUpdatedService(deadline: Date, completion: @escaping (ServiceUpdateOutcome) -> Void) {
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) {
            if installedHelperMatchesBundle {
                HelperClient.shared.waitUntilServiceAnswers(deadline: deadline) { answered in
                    completion(answered ? .updated : .didNotReturn("新的后台服务没有回应"))
                }
            } else if Date() >= deadline {
                completion(.didNotReturn("后台服务没有在一分钟内完成更新"))
            } else {
                waitForUpdatedService(deadline: deadline, completion: completion)
            }
        }
    }

    /// The way out when the background service does not answer
    /// (DESIGN.md §25.5, F9): the bundled dev-helper.sh `recover`, as
    /// root behind the standard administrator password dialog —
    /// restores routes/DNS, empties our pf anchor, gives our pf enable
    /// reference back and clears the held state, without the service.
    static func forceRecover(completion: @escaping (Result<Void, Error>) -> Void) {
        PrivilegedBundle.run(resource: "dev-helper.sh", arguments: ["recover"],
                             prompt: "AlwaysConnect 要强制恢复网络（后台服务没有响应）。") { result in
            if let code = result.errorNumber {
                completion(.failure(code == -128 ? InstallError.cancelled
                                                 : InstallError.scriptFailed(result.errorMessage ?? "未知错误")))
            } else {
                completion(.success(()))
            }
        }
    }

    private static var bundledHelperPath: String? {
        let path = Bundle.main.bundleURL
            .appendingPathComponent("Contents/Library/LaunchDaemons/AlwaysConnectHelper").path
        return FileManager.default.isExecutableFile(atPath: path) ? path : nil
    }

    /// Dev install only: the installed daemon's code differs from the
    /// one in this App (the App was rebuilt), so the panel offers an
    /// update. Compares the code-directory hashes, not the files: every
    /// rebuild re-signs with a new signing time, which made identical
    /// code look outdated and asked for the admin password for nothing.
    static var installedHelperOutdated: Bool {
        guard !isTeamSigned, let bundled = bundledHelperPath,
              let installed = codeHash(
                atPath: "/Library/PrivilegedHelperTools/com.alwaysconnect.app.helper"),
              let current = codeHash(atPath: bundled)
        else { return false }
        return installed != current
    }

    /// Only a matching installed binary is known to serialize protection RPCs.
    /// Unknown/older services retain the client's acknowledged queue barrier.
    static var installedHelperMatchesBundle: Bool {
        guard let bundled = bundledHelperPath,
              let installed = codeHash(atPath: "/Library/PrivilegedHelperTools/com.alwaysconnect.app.helper"),
              let current = codeHash(atPath: bundled) else { return false }
        return installed == current
    }

    private static func codeHash(atPath path: String) -> Data? {
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &code) == errSecSuccess,
              let code else { return nil }
        var info: CFDictionary?
        guard SecCodeCopySigningInformation(code, [], &info) == errSecSuccess else { return nil }
        return (info as? [String: Any])?[kSecCodeInfoUnique as String] as? Data
    }

    static func install(prompt: String = installPrompt,
                        completion: @escaping (Result<Void, Error>) -> Void) {
        guard isTeamSigned else {
            // An installed service that can update itself does it after the
            // user's approval in a dialog that offers Touch ID (§69.11); any
            // other case, or a refusal by the service, keeps the password path.
            guard installedHelperOutdated, serviceCanUpdateItself else {
                installWithAdminPassword(prompt: prompt, completion: completion)
                return
            }
            updateThroughService(prompt: prompt) { outcome in
                switch outcome {
                case .updated: completion(.success(()))
                case .cancelled: completion(.failure(InstallError.cancelled))
                case .failed(let reason): completion(.failure(InstallError.scriptFailed(reason)))
                // The safety net: an update that started but left no
                // working service is finished the way that always works.
                case .didNotReturn: installWithAdminPassword(prompt: retryPrompt, completion: completion)
                case .notTaken: installWithAdminPassword(prompt: prompt, completion: completion)
                }
            }
            return
        }
        let service = SMAppService.daemon(plistName: plistName)
        if service.status == .enabled {
            completion(.success(()))
            return
        }
        do {
            if service.status != .requiresApproval {
                try service.register()
            }
            switch service.status {
            case .enabled:
                completion(.success(()))
            case .requiresApproval:
                SMAppService.openSystemSettingsLoginItems()
                completion(.failure(InstallError.approvalRequired))
            default:
                completion(.failure(InstallError.notEnabled))
            }
        } catch {
            completion(.failure(error))
        }
    }
}
