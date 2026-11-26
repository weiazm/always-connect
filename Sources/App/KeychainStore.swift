import Foundation
import Security

/// Keychain storage for the App's secrets: the VPN password and the
/// proxies' passwords.
/// - All of them live in ONE generic-password item, the vault (DESIGN.md
///   §69.19): a JSON object keyed "username@server". This App is
///   self-signed, so every version has a new code identity and the
///   keychain asks once per item for each new version. One item means one
///   question per update, however many proxies have passwords (user,
///   2026-11-26: "我安装后要输入两次keychain授权？能不能简单点").
/// - Items an older version stored one per secret (account
///   "username@server") are read once more and copied into the vault.
/// - The names of the secrets present are kept in the item's unencrypted
///   generic attribute: "is there a password?" never reads a secret and
///   never asks (§21.12).
/// - Accessibility AfterFirstUnlock: launch-time auto-connect works
///   without unlocking the device first. A secret never touches a
///   plaintext file, a log, or diagnostics.
/// - Touch ID gating belongs in the Settings UI for viewing/editing; it
///   must never gate auto-login itself.
enum KeychainStore {
    private static let service = "com.alwaysconnect.app"
    /// Since servers can be switched (DESIGN.md §21.13), the password
    /// belongs to the account, not to one server: it is stored under
    /// this server key. Passwords saved per server by older builds are
    /// still found (and moved here) by the callers' fallback.
    static let accountKey = "account"
    private static let vaultAccount = "vault"

    static func name(server: String, username: String) -> String { "\(username)@\(server)" }

    static func save(server: String, username: String, password: String) -> Bool {
        SecretVault.set(name(server: server, username: username), password)
    }

    /// Whether a password is stored, WITHOUT reading it (attributes only,
    /// never a prompt). Use this for every "do we have credentials?"
    /// check; read() only when actually connecting (DESIGN.md §21.12).
    static func exists(server: String, username: String) -> Bool {
        SecretVault.contains(name(server: server, username: username))
            || SecretVault.hasLegacy(server, username)
    }

    /// Returns nil when absent or unreadable; callers treat nil as "no
    /// stored password". May prompt for keychain access: call only to
    /// connect. A secret only an older version's own item has is copied
    /// into the vault unless `moveToVault` is false.
    static func read(server: String, username: String, moveToVault: Bool = true) -> String? {
        let key = name(server: server, username: username)
        switch SecretVault.lookup(key) {
        case .found(let value): return value
        case .refused: return nil
        case .absent:
            guard let old = SecretVault.readLegacy(server, username) else { return nil }
            // The old item stays: deleting it could ask once more. The
            // vault's copy is the one read from now on.
            if moveToVault { _ = SecretVault.set(key, old) }
            return old
        }
    }

    static func delete(server: String, username: String) -> Bool {
        let vault = SecretVault.set(name(server: server, username: username), nil)
        let status = SecItemDelete(legacyQuery(server: server, username: username) as CFDictionary)
        return vault && (status == errSecSuccess || status == errSecItemNotFound)
    }

    /// Every item this App ever stored, the vault and older per-secret
    /// items alike (the uninstaller, DESIGN.md §31). Repeated because one
    /// call may remove only one item; stops at the first "nothing left"
    /// or error.
    static func deleteAll() {
        let all: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
        ]
        var rounds = 0
        while rounds < 20, SecItemDelete(all as CFDictionary) == errSecSuccess {
            rounds += 1
        }
    }

    // MARK: - The vault item

    private static var vaultQuery: [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: vaultAccount,
        ]
    }

    static func loadVault() -> SecretVault.Loaded {
        var q = vaultQuery
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &item)
        if status == errSecItemNotFound { return .missing }
        // Refused, or unreadable: never overwritten from here.
        guard status == errSecSuccess, let data = item as? Data,
              let all = try? JSONDecoder().decode([String: String].self, from: data) else { return .refused }
        return .found(all)
    }

    static func saveVault(_ all: [String: String], exists: Bool) -> Bool {
        guard let data = try? JSONEncoder().encode(all),
              let names = try? JSONEncoder().encode(all.keys.sorted()) else { return false }
        let update: [String: Any] = [kSecValueData as String: data, kSecAttrGeneric as String: names]
        if exists {
            return SecItemUpdate(vaultQuery as CFDictionary, update as CFDictionary) == errSecSuccess
        }
        var item = vaultQuery
        item[kSecValueData as String] = data
        item[kSecAttrGeneric as String] = names
        item[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlock
        var status = SecItemAdd(item as CFDictionary, nil)
        if status == errSecDuplicateItem {
            status = SecItemUpdate(vaultQuery as CFDictionary, update as CFDictionary)
        }
        return status == errSecSuccess
    }

    /// The names in the vault, from its attributes only.
    static func vaultNames() -> [String] {
        var q = vaultQuery
        q[kSecReturnAttributes as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &item) == errSecSuccess,
              let attributes = item as? [String: Any],
              let data = attributes[kSecAttrGeneric as String] as? Data,
              let names = try? JSONDecoder().decode([String].self, from: data) else { return [] }
        return names
    }

    // MARK: - Items of older versions (one per secret)

    private static func legacyQuery(server: String, username: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: name(server: server, username: username),
        ]
    }

    static func legacyExists(server: String, username: String) -> Bool {
        var q = legacyQuery(server: server, username: username)
        q[kSecReturnAttributes as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        return SecItemCopyMatching(q as CFDictionary, &item) == errSecSuccess
    }

    static func legacyRead(server: String, username: String) -> String? {
        var q = legacyQuery(server: server, username: username)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &item) == errSecSuccess,
              let data = item as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }
}

/// The one keychain item for every secret (DESIGN.md §69.19). Read and
/// written whole; the callers keep what they read for the run (§21.12),
/// so a run reads it at most once per secret and a new version asks once.
enum SecretVault {
    enum Loaded { case found([String: String]), missing, refused }
    enum Lookup: Equatable { case found(String), absent, refused }

    /// The keychain, or stand-ins (tests).
    static var load: () -> Loaded = KeychainStore.loadVault
    static var save: (_ all: [String: String], _ exists: Bool) -> Bool = KeychainStore.saveVault
    static var names: () -> [String] = KeychainStore.vaultNames
    static var readLegacy: (_ server: String, _ username: String) -> String? = KeychainStore.legacyRead
    static var hasLegacy: (_ server: String, _ username: String) -> Bool = KeychainStore.legacyExists
    private static let lock = NSLock()

    static func lookup(_ name: String) -> Lookup {
        switch load() {
        case .found(let all): return all[name].map { .found($0) } ?? .absent
        case .missing: return .absent
        case .refused: return .refused
        }
    }

    static func contains(_ name: String) -> Bool { names().contains(name) }

    /// nil removes. A vault that could not be read is never overwritten:
    /// that would lose the other secrets.
    @discardableResult
    static func set(_ name: String, _ value: String?) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        var all: [String: String]
        let exists: Bool
        switch load() {
        case .found(let current): all = current; exists = true
        case .missing: all = [:]; exists = false
        case .refused: return false
        }
        if all[name] == value { return true }
        all[name] = value
        return save(all, exists)
    }
}
