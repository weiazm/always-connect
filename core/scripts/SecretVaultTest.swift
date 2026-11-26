import Foundation

// DESIGN.md §69.19: every secret in one keychain item, older per-secret
// items copied in once. The keychain is replaced by an in-memory stand-in:
// no prompt, no real keychain item is read or written.
@main
struct SecretVaultTest {
    static var fails = 0
    static func check(_ ok: Bool, _ name: String) {
        print((ok ? "ok   " : "FAIL ") + name)
        if !ok { fails += 1 }
    }

    static func main() {
        var vault: [String: String]? = nil
        var refused = false
        var legacy: [String: String] = [:]
        var reads = 0, legacyReads = 0, writes = 0
        SecretVault.load = {
            reads += 1
            if refused { return .refused }
            return vault.map { .found($0) } ?? .missing
        }
        SecretVault.save = { all, exists in
            precondition(exists == (vault != nil), "add vs update follows what was read")
            writes += 1
            vault = all
            return true
        }
        SecretVault.names = { (vault ?? [:]).keys.sorted() }
        SecretVault.readLegacy = { server, username in
            legacyReads += 1
            return legacy["\(username)@\(server)"]
        }
        SecretVault.hasLegacy = { server, username in legacy["\(username)@\(server)"] != nil }

        // An install from before §69.19: the VPN password and a proxy
        // password each in their own item.
        legacy = ["alice@account": "vpn-secret", "proxy@proxy-1": "proxy-secret"]
        check(KeychainStore.read(server: KeychainStore.accountKey, username: "alice") == "vpn-secret"
              && vault == ["alice@account": "vpn-secret"] && writes == 1,
              "an older item is read once and copied into the vault")
        check(KeychainStore.read(server: "proxy-1", username: "proxy") == "proxy-secret"
              && vault?.count == 2 && writes == 2,
              "a second older secret joins the same vault")
        legacyReads = 0
        legacy = [:]  // the older items are not read again
        check(KeychainStore.read(server: KeychainStore.accountKey, username: "alice") == "vpn-secret"
              && KeychainStore.read(server: "proxy-1", username: "proxy") == "proxy-secret" && legacyReads == 0,
              "afterwards every secret comes from the one vault item")
        check(KeychainStore.exists(server: KeychainStore.accountKey, username: "alice"),
              "presence is answered from the vault's names, without reading secrets")

        // Saving, changing and removing go through the vault.
        check(KeychainStore.save(server: "proxy-2", username: "proxy", password: "p2") && vault?["proxy@proxy-2"] == "p2",
              "a new secret is stored in the vault")
        check(KeychainStore.save(server: KeychainStore.accountKey, username: "alice", password: "new")
              && vault?["alice@account"] == "new" && vault?["proxy@proxy-2"] == "p2",
              "changing one secret keeps the others")
        let before = writes
        check(KeychainStore.save(server: KeychainStore.accountKey, username: "alice", password: "new") && writes == before,
              "storing the same value writes nothing")
        _ = SecretVault.set("proxy@proxy-2", nil)
        check(vault?["proxy@proxy-2"] == nil && vault?["alice@account"] == "new", "removing one secret keeps the others")

        // A vault the user refused to open is never overwritten.
        refused = true
        let kept = vault
        check(!KeychainStore.save(server: "proxy-3", username: "proxy", password: "p3") && vault == kept,
              "a refused vault is not overwritten (the other secrets would be lost)")
        legacy = ["alice@account": "stale"]
        legacyReads = 0
        check(KeychainStore.read(server: KeychainStore.accountKey, username: "alice") == nil && legacyReads == 0,
              "a refused vault does not fall back to an older item (no second question)")
        refused = false

        // A per-server item of an even older build is read without being
        // copied under its own name (the caller stores it as the account's).
        legacy = ["bob@VPN-A": "per-server"]
        let count = vault?.count
        check(KeychainStore.read(server: "VPN-A", username: "bob", moveToVault: false) == "per-server" && vault?.count == count,
              "moveToVault: false reads without copying")

        // A fresh install: nothing anywhere.
        vault = nil
        legacy = [:]
        check(KeychainStore.read(server: KeychainStore.accountKey, username: "carol") == nil && vault == nil,
              "nothing stored: nothing read, no empty vault created")
        check(KeychainStore.save(server: KeychainStore.accountKey, username: "carol", password: "c") && vault == ["carol@account": "c"],
              "the first secret creates the vault")
        print("FAILS=\(fails)")
        exit(fails == 0 ? 0 : 1)
    }
}
