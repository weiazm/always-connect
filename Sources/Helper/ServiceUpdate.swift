import Foundation
import Security

/// The background service replaces itself after the user's approval
/// (DESIGN.md §69.11, user 2026-11-25: "改用系统授权框，支持指纹"). Same
/// trust as the administrator-password path: the user approves every
/// update (now in a dialog that offers Touch ID), and root only runs a
/// root-private snapshot of the caller's bundle that carries our own
/// certificate and is not older than what is installed.
enum ServiceUpdate {
    static let logPath = "/Library/Logs/AlwaysConnect/service-update.log"

    /// The external form must hold ServiceUpdateRight already granted:
    /// checked with the system, never with any interaction here.
    static func authorized(_ data: Data) -> Bool {
        guard data.count == MemoryLayout<AuthorizationExternalForm>.size else { return false }
        var external = AuthorizationExternalForm()
        withUnsafeMutableBytes(of: &external) { _ = data.copyBytes(to: $0) }
        var authorization: AuthorizationRef?
        guard AuthorizationCreateFromExternalForm(&external, &authorization) == errAuthorizationSuccess,
              let authorization else { return false }
        defer { AuthorizationFree(authorization, [.destroyRights]) }
        return ServiceUpdateRight.name.withCString { name -> Bool in
            var item = AuthorizationItem(name: name, valueLength: 0, value: nil, flags: 0)
            return withUnsafeMutablePointer(to: &item) { pointer -> Bool in
                var rights = AuthorizationRights(count: 1, items: pointer)
                return AuthorizationCopyRights(authorization, &rights, nil, [.extendRights], nil)
                    == errAuthorizationSuccess
            }
        }
    }

    /// The calling process's App bundle on disk. Only decides what is
    /// copied: the copy itself is verified before anything runs.
    static func bundlePath(pid: pid_t) -> String? {
        var code: SecCode?
        guard SecCodeCopyGuestWithAttributes(nil, [kSecGuestAttributePid: pid] as CFDictionary, [], &code)
                == errSecSuccess, let code else { return nil }
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode else { return nil }
        var url: CFURL?
        guard SecCodeCopyPath(staticCode, [], &url) == errSecSuccess, let url else { return nil }
        let path = (url as URL).standardizedFileURL.path
        guard path.hasSuffix(".app"),
              FileManager.default.fileExists(atPath: path + "/Contents/Resources/dev-helper.sh") else { return nil }
        return path
    }

    static var installedVersion: String? {
        (try? String(contentsOfFile: RootBootstrap.installedVersionPath, encoding: .utf8))?
            .trimmingCharacters(in: .whitespacesAndNewlines).nilIfEmpty
    }

    /// The bootstrap in its own session: installing boots this service
    /// out, which ends its process group, and the install must outlive it.
    static func startDetached(_ script: String) -> Bool {
        var attributes: posix_spawnattr_t?
        guard posix_spawnattr_init(&attributes) == 0 else { return false }
        defer { posix_spawnattr_destroy(&attributes) }
        guard posix_spawnattr_setflags(&attributes, Int16(POSIX_SPAWN_SETSID)) == 0 else { return false }
        var actions: posix_spawn_file_actions_t?
        guard posix_spawn_file_actions_init(&actions) == 0 else { return false }
        defer { posix_spawn_file_actions_destroy(&actions) }
        posix_spawn_file_actions_addopen(&actions, 0, "/dev/null", O_RDONLY, 0)
        posix_spawn_file_actions_addopen(&actions, 1, logPath, O_WRONLY | O_CREAT | O_APPEND, 0o600)
        posix_spawn_file_actions_adddup2(&actions, 1, 2)
        let argv = ["/bin/bash", "-c", script]
        let environment = ["PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=en_US.UTF-8"]
        var cArgs = argv.map { strdup($0) } + [nil]
        var cEnv = environment.map { strdup($0) } + [nil]
        defer { (cArgs + cEnv).forEach { free($0) } }
        var pid: pid_t = 0
        return posix_spawn(&pid, "/bin/bash", &actions, &attributes, &cArgs, &cEnv) == 0
    }
}

private extension String {
    var nilIfEmpty: String? { isEmpty ? nil : self }
}
