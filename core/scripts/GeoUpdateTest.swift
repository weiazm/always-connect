// Site-list download and updates (DESIGN.md §66.30), compiled with the App's
// sources by scripts/geo-update-test.sh against a local feed: never the
// user's files, preferences or the real publisher.
import Foundation

@_silgen_name("ac_egress_config_valid")
private func ac_egress_config_valid(_ json: UnsafePointer<CChar>) -> Bool

func egressConfigValid(_ config: EgressProtection) -> Bool {
    guard let data = try? JSONEncoder().encode(config) else { return false }
    return ac_egress_config_valid(String(decoding: data, as: UTF8.self))
}

@main
struct GeoUpdateTest {
    static var fails = 0
    static func check(_ ok: Bool, _ name: String) {
        print("\(ok ? "PASS" : "FAIL") \(name)")
        if !ok { fails += 1 }
    }

    static func wait(_ updater: GeoUpdater) {
        let deadline = Date().addingTimeInterval(30)
        while updater.checking && Date() < deadline { RunLoop.main.run(until: Date().addingTimeInterval(0.05)) }
    }

    static func run(_ updater: GeoUpdater) -> String? {
        var finished = false
        var outcome: String?
        updater.check { error in outcome = error; finished = true }
        let deadline = Date().addingTimeInterval(30)
        while !finished && Date() < deadline { RunLoop.main.run(until: Date().addingTimeInterval(0.05)) }
        return finished ? outcome : "timeout"
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
        func release(_ tag: String) {
            try? #"{"tag_name":"\#(tag)"}"#.write(toFile: feed + "/api", atomically: true, encoding: .utf8)
        }
        func drop(_ tag: String) { try? FileManager.default.removeItem(atPath: feed + "/download/\(tag)/dlc.dat") }

        // Nothing bundled: rules keep their geosite: lines until the download.
        check(!GeoData.available && updater.version == nil && updater.versionText == "还没下载",
              "a fresh install has no site lists")
        check(ListRule.parse("geosite:example") == .geosite("example", attribute: nil)
              && ListRule.parse("geosite:example")?.expanded == [] && ListRule.parse("geosite:example")?.kind.contains("还没下载") == true,
              "geosite: rules are kept as written before the first download and match nothing yet")

        // A rule made only of site lists must not stop the VPN from connecting
        // before the download (real Mac, 2026-11-25): the background service
        // accepts it and it protects nothing yet.
        let onlyLists = EgressProtection(enabled: true, groups: [
            .init(id: 9, name: "lists", enabled: true, sites: ["geosite:example"], expect: ["ZZ"], unverified: .whenWrong)])
        let sent = onlyLists.forBackgroundService
        check(sent.groups[0].matches == [] && egressConfigValid(sent),
              "before the download a list-only rule goes out with no matches and is accepted")

        updater.checkIfDue()  // missing lists: due at once
        wait(updater)
        check(GeoData.available && updater.version == "20261124090120" && updater.versionText == "2026-11-24 版" && installs == 1,
              "the first check downloads at once, puts the lists in place and re-sends the rules")
        check(onlyLists.forBackgroundService.groups[0].matches == ["domain:example.com", "full:www.example.net"],
              "after the download the same rule carries the list's names")
        check(GeoData.hasList("example") && ListRule.parse("geosite:example")?.expanded == ["domain:example.com", "full:www.example.net"]
              && ListRule.parse("geosite:nosuchlist") == nil, "rules read the downloaded lists; unknown names are refused again")
        check(GeoUpdater.stamp()?.tag == "20261124090120", "the version sits in a file beside the lists")

        drop("20261124090120")
        check(run(updater) == nil && installs == 1, "an unchanged tag downloads nothing and re-sends nothing")

        let before = try? Data(contentsOf: target)
        release("20261125000000"); drop("20261125000000")
        check(run(updater) == nil && updater.version == "20261125000000" && installs == 1 && (try? Data(contentsOf: target)) == before,
              "a new tag with the same published hash downloads nothing")
        release("20261126000000")
        check(run(updater) == "清单校验不通过" && updater.version == "20261125000000" && (try? Data(contentsOf: target)) == before,
              "a download that does not match its published hash changes nothing")
        release("20261127000000")
        check(run(updater) == nil && updater.version == "20261127000000" && installs == 1 && GeoData.hasList("unused"),
              "new content in lists no rule uses is stored without re-sending the rules")
        release("20261128000000")
        used = ["example", "needed"]
        check(run(updater) == "新清单里没有 geosite:needed，先不更新" && updater.version == "20261127000000",
              "a release without a list the rules name is not taken")
        used = ["example"]
        check(run(updater) == nil && updater.version == "20261128000000" && installs == 2
              && ListRule.parse("geosite:example")?.expanded.contains("domain:added.example") == true,
              "a change in a list the rules use is taken and the rules are re-sent")
        release("../../etc")
        check(run(updater) == "GitHub 没有给出清单版本", "a tag that is not the project's kind is refused")
        release("20261129000000")
        check(run(updater) == "清单内容不完整", "a file that is not a full catalogue is refused")

        // A try that found no network (launch while the VPN connects) is
        // repeated as soon as the VPN is up, not hours later.
        let store = GeoUpdater.store
        store.set(GeoUpdater.unreachable, forKey: "siteListsLastError")
        let failedAt = Date().timeIntervalSince1970
        store.set(failedAt, forKey: "siteListsLastAttempt")
        updater.checkIfDue()
        check(store.double(forKey: "siteListsLastAttempt") == failedAt, "right after a no-network failure nothing is tried")
        updater.checkIfDue(networkReady: true)
        wait(updater)
        check(store.double(forKey: "siteListsLastAttempt") > failedAt && updater.lastError == "清单内容不完整",
              "the VPN coming up retries a no-network failure at once")
        print("geo-update FAILS=\(fails)")
        exit(fails == 0 ? 0 : 1)
    }
}
