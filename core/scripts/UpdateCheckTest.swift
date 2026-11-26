import Foundation

// Harness for the update check (DESIGN.md §三十三): the App's
// UpdateChecker against a local HTTP server standing in for GitHub's
// releases list. Run by scripts/update-check-test.sh.

@_silgen_name("ac_string_free")
func ac_string_free(_ s: UnsafeMutablePointer<CChar>?)

@main
struct UpdateCheckTest {
    static var failures = 0

    static func expect(_ ok: Bool, _ name: String) {
        print(ok ? "PASS \(name)" : "FAIL \(name)")
        if !ok { failures += 1 }
    }

    /// One check against `path` on the local server, waited for on the main run loop.
    static func check(_ base: String, _ path: String) -> UpdateChecker.Outcome {
        setenv("ALWAYSCONNECT_UPDATE_URL", base + path, 1)
        var result: UpdateChecker.Outcome?
        UpdateChecker.shared.check { result = $0 }
        let deadline = Date().addingTimeInterval(20)
        while result == nil && Date() < deadline {
            RunLoop.main.run(until: Date().addingTimeInterval(0.05))
        }
        return result ?? .failed
    }

    static func main() {
        let args = CommandLine.arguments
        let base = args[1]          // http://127.0.0.1:<port>/
        let closed = args[2]        // a URL nothing listens on
        let suite = "com.alwaysconnect.update-check-test"
        UserDefaults().removePersistentDomain(forName: suite)
        UpdateChecker.store = UserDefaults(suiteName: suite)!
        UpdateChecker.currentVersion = "0.1.0"

        // A newer pre-release counts (user, 2026-11-06); a draft does not.
        if case .newer(let u) = check(base, "releases.json") {
            expect(u.version == "0.2.0-beta.1" && u.prerelease
                   && u.url.absoluteString == "https://github.com/o/r/releases/tag/v0.2.0-beta.1", "newer-prerelease")
        } else { expect(false, "newer-prerelease") }
        expect(UpdateChecker.shared.available?.version == "0.2.0-beta.1", "banner-shown")

        // Checked a moment ago: due checks send nothing for a day.
        UpdateChecker.shared.checkIfDue()
        expect(!UpdateChecker.shared.checking, "not-due-within-a-day")

        // The private repository's 404 and a missing server keep the last find.
        expect(check(base, "missing.json") == .unreadable, "not-found-unreadable")
        expect(check(base, "notfound.json") == .unreadable, "error-object-unreadable")
        expect(check(closed, "") == .failed, "offline-failed")
        expect(UpdateChecker.shared.available?.version == "0.2.0-beta.1", "find-kept-after-failures")
        // A failed check retries after an hour, not a day.
        let attempt = UpdateChecker.store.double(forKey: "updateLastAttempt")
        UpdateChecker.store.set(attempt - 3700, forKey: "updateLastAttempt")
        setenv("ALWAYSCONNECT_UPDATE_URL", base + "releases.json", 1)
        UpdateChecker.shared.checkIfDue()
        expect(UpdateChecker.shared.checking, "retry-after-an-hour")
        let deadline = Date().addingTimeInterval(20)
        while UpdateChecker.shared.checking && Date() < deadline {
            RunLoop.main.run(until: Date().addingTimeInterval(0.05))
        }

        // Skipping hides it; the same release stays skipped; a later one shows.
        if let u = UpdateChecker.shared.available { UpdateChecker.shared.skip(u) }
        expect(UpdateChecker.shared.available == nil, "skip-hides")
        expect(check(base, "releases.json") == .skipped("0.2.0-beta.1"), "skipped-stays-hidden")
        if case .newer(let u) = check(base, "later.json") {
            expect(u.version == "0.3.0" && !u.prerelease, "later-release-shows")
        } else { expect(false, "later-release-shows") }

        // "更新" looks once more and installs the newest, not the find
        // shown (§69.12): a stand-in script reports the tag it was given.
        let stub = NSTemporaryDirectory() + "update-tag-\(getpid()).sh"
        try? "echo \"错误：TAG=$2\"; exit 1\n".write(toFile: stub, atomically: true, encoding: .utf8)
        UpdateChecker.installScript = stub
        UpdateChecker.store.removeObject(forKey: "updateSkippedVersion")
        let shown = UpdateChecker.Available(version: "0.2.0-beta.1", tag: "v0.2.0-beta.1",
                                            url: URL(string: "https://github.com/o/r/releases/tag/v0.2.0-beta.1")!,
                                            prerelease: true)
        setenv("ALWAYSCONNECT_UPDATE_URL", base + "later.json", 1)
        UpdateChecker.shared.install(shown)
        let installDeadline = Date().addingTimeInterval(20)
        while UpdateChecker.shared.installing && Date() < installDeadline {
            RunLoop.main.run(until: Date().addingTimeInterval(0.05))
        }
        expect(UpdateChecker.shared.installError == "TAG=v0.3.0", "update-installs-the-newest-release")
        // Offline: the release shown.
        setenv("ALWAYSCONNECT_UPDATE_URL", closed, 1)
        UpdateChecker.shared.install(shown)
        while UpdateChecker.shared.installing && Date() < installDeadline.addingTimeInterval(20) {
            RunLoop.main.run(until: Date().addingTimeInterval(0.05))
        }
        expect(UpdateChecker.shared.installError == "TAG=v0.2.0-beta.1", "offline-update-installs-the-shown-release")
        try? FileManager.default.removeItem(atPath: stub)

        // Once this version is installed, the stored find no longer shows.
        UpdateChecker.currentVersion = "0.3.0"
        UpdateChecker.shared.checkIfDue()
        expect(UpdateChecker.shared.available == nil, "installed-version-hides")
        expect(check(base, "later.json") == .current, "current")

        // Several newer releases: the newest at once (user, 2026-11-26:
        // "直接检查到最新版本，不是一个一个版本升").
        if case .newer(let u) = check(base, "several.json") {
            expect(u.version == "0.9.0", "several-newer-offers-the-newest")
        } else { expect(false, "several-newer-offers-the-newest") }
        // Asked again unchanged: a 304, which keeps the find (and costs
        // nothing against GitHub's limit).
        let log = ProcessInfo.processInfo.environment["AC_REQUEST_LOG"] ?? ""
        let before = (try? String(contentsOfFile: log, encoding: .utf8)) ?? ""
        if case .newer(let u) = check(base, "several.json") {
            expect(u.version == "0.9.0" && UpdateChecker.shared.available?.version == "0.9.0", "unchanged-list-keeps-the-find")
        } else { expect(false, "unchanged-list-keeps-the-find") }
        let after = (try? String(contentsOfFile: log, encoding: .utf8)) ?? ""
        expect(after.dropFirst(before.count).contains("/several.json 304"), "unchanged-list-answers-304")
        // The panel asks on every opening, at most every 30 s.
        UpdateChecker.shared.checkOnPanelOpen()
        expect(!UpdateChecker.shared.checking, "panel-open-right-after-a-check-asks-nothing")
        UpdateChecker.store.set(Date().timeIntervalSince1970 - 31, forKey: "updateLastAttempt")
        UpdateChecker.shared.checkOnPanelOpen()
        expect(UpdateChecker.shared.checking, "panel-open-after-30-s-asks-again")
        let openDeadline = Date().addingTimeInterval(20)
        while UpdateChecker.shared.checking && Date() < openDeadline {
            RunLoop.main.run(until: Date().addingTimeInterval(0.05))
        }

        UserDefaults().removePersistentDomain(forName: suite)
        print(failures == 0 ? "update-check: all passed" : "update-check: \(failures) failed")
        exit(failures == 0 ? 0 : 1)
    }
}
