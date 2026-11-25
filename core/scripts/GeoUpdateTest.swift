// Site-list updates (DESIGN.md §66.30), compiled with the App's sources by
// scripts/geo-update-test.sh against a local feed: never the user's files,
// preferences or the real publisher.
import Foundation

@main
struct GeoUpdateTest {
    static var fails = 0
    static func check(_ ok: Bool, _ name: String) {
        print("\(ok ? "PASS" : "FAIL") \(name)")
        if !ok { fails += 1 }
    }

    static func run(_ updater: GeoUpdater) -> String? {
        var finished = false
        var outcome: String?
        updater.check { error in outcome = error; finished = true }
        let deadline = Date().addingTimeInterval(30)
        while !finished && Date() < deadline { RunLoop.main.run(until: Date().addingTimeInterval(0.05)) }
        if !finished { return "timeout" }
        return outcome
    }

    static func main() {
        let feed = CommandLine.arguments[1]
        let suite = "geo-update-test-\(getpid())"
        GeoUpdater.store = UserDefaults(suiteName: suite)!
        defer { UserDefaults().removePersistentDomain(forName: suite) }
        var installs = 0
        GeoUpdater.installed = { installs += 1 }
        var used: [String] = ["example"]
        GeoUpdater.usedLists = { used }
        let updater = GeoUpdater.shared
        let target = GeoUpdater.target

        check(updater.version == nil && updater.versionText.contains("App 自带"), "starts on the bundled lists")
        check(run(updater) == nil && FileManager.default.fileExists(atPath: target.path), "a new release is downloaded, checked and put in place")
        check(updater.version == "20261124090120" && updater.versionText == "2026-11-24 版" && installs == 1,
              "the version shows and the rules are re-sent once")
        check(GeoData.hasList("example") && ListRule.parse("geosite:example")?.expanded == ["domain:example.com", "full:www.example.net"],
              "rules read the new lists at once")

        // The same tag again: no download (the files are gone from the feed).
        try? FileManager.default.removeItem(atPath: feed + "/download/20261124090120/dlc.dat")
        check(run(updater) == nil && installs == 1, "an unchanged release downloads nothing and re-sends nothing")

        let before = try? Data(contentsOf: target)
        func release(_ tag: String) {
            try? #"{"tag_name":"\#(tag)"}"#.write(toFile: feed + "/api", atomically: true, encoding: .utf8)
        }
        release("20261125000000")
        check(run(updater) == "清单校验不通过" && updater.version == "20261124090120" && (try? Data(contentsOf: target)) == before,
              "a download that does not match its published hash changes nothing")
        release("20261126000000")
        used = ["example", "needed"]
        check(run(updater) == "新清单里没有 geosite:needed，先不更新" && updater.version == "20261124090120"
              && (try? Data(contentsOf: target)) == before, "a release without a list the rules name is not taken")
        used = ["example"]
        check(run(updater) == nil && updater.version == "20261126000000" && installs == 2, "the next good release is taken")
        release("../../etc")
        check(run(updater) == "GitHub 没有给出清单版本", "a tag that is not the project's kind is refused")
        release("20261127000000")
        check(run(updater) == "清单内容不完整", "a file that is not a full catalogue is refused")

        // A try that found no network (launch while the VPN connects) is
        // repeated as soon as the VPN is up, not an hour later.
        let store = GeoUpdater.store
        store.set(GeoUpdater.unreachable, forKey: "siteListsLastError")
        let failedAt = Date().timeIntervalSince1970
        store.set(failedAt, forKey: "siteListsLastAttempt")
        updater.checkIfDue()
        check(store.double(forKey: "siteListsLastAttempt") == failedAt, "right after a no-network failure nothing is tried")
        updater.checkIfDue(networkReady: true)
        let deadline = Date().addingTimeInterval(30)
        while updater.checking && Date() < deadline { RunLoop.main.run(until: Date().addingTimeInterval(0.05)) }
        check(store.double(forKey: "siteListsLastAttempt") > failedAt && updater.lastError == "清单内容不完整",
              "the VPN coming up retries a no-network failure at once")

        updater.useBundled()
        check(!FileManager.default.fileExists(atPath: target.path) && updater.version == nil && installs == 3,
              "going back to the bundled lists removes the download")
        print("geo-update FAILS=\(fails)")
        exit(fails == 0 ? 0 : 1)
    }
}
