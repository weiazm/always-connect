// The split list's rule syntax (DESIGN.md §26.13), compiled with
// Sources/App/ListRules.swift, DirectSites.swift, ProfileStore.swift and
// Sources/Shared by scripts/list-rules-test.sh; data from Sources/App/GeoData.
import Foundation

@main
struct ListRulesTest {
    static func main() {
        var fails = 0
        func check(_ name: String, _ ok: Bool) {
            print("\(ok ? "PASS" : "FAIL") \(name)")
            if !ok { fails += 1 }
        }
        let oldSettings = Data(#"{"notificationAggregation":true,"globalHotkeyEnabled":false}"#.utf8)
        let migrated = try! JSONDecoder().decode(AppSettings.self, from: oldSettings)
        check("old settings decode with on-demand disabled", migrated.onDemandEnabled == nil && migrated.onDemandRules == nil)
        check("a web address becomes its domain", ListRule.parse("https://www.Example.com/path") == .domain("www.example.com"))
        check("geosite list by name", ListRule.parse("geosite:GitHub") == .geosite("github", attribute: nil))
        check("geosite with an attribute", ListRule.parse("geosite:google@cn") == .geosite("google", attribute: "cn"))
        check("unknown geosite refused with a reason", ListRule.parse("geosite:nosuchlist") == nil
              && ListRule.problem("geosite:nosuchlist") == "没有叫这个名字的网站清单")
        check("geoip:cn accepted, other countries explained", ListRule.parse("geoip:CN") == .geoip("cn")
              && ListRule.problem("geoip:us") == "目前只支持 geoip:cn")
        check("network and single address", ListRule.parse("10.1.0.0/16") == .network("10.1.0.0/16")
              && ListRule.parse("192.168.1.5") == .network("192.168.1.5/32"))
        check("junk explained", ListRule.problem("not a rule") != nil && ListRule.problem("") == nil)
        // One syntax for the split list and exit protection (§66.30).
        check("domain: is the plain form", ListRule.parse("domain:Example.com") == .domain("example.com")
              && ListRule.parse("domain:example.com")?.text == "example.com")
        check("full, keyword and regexp", ListRule.parse("full:WWW.example.com") == .full("www.example.com")
              && ListRule.parse("keyword:Example") == .keyword("example")
              && ListRule.parse(#"regexp:^a\d+\.Example\.com$"#) == .regexp(#"^a\d+\.Example\.com$"#))
        check("a regexp the background service cannot compile is refused",
              ListRule.parse("regexp:(") == nil && ListRule.problem("regexp:(") == "正则表达式写得不对")
        check("a pasted Clash line is converted, its policy dropped",
              ListRule.parse("GEOSITE,github,PROXY")?.text == "geosite:github"
              && ListRule.parse("DOMAIN-SUFFIX,Example.com")?.text == "example.com"
              && ListRule.parse("DOMAIN,a.example.com,X")?.text == "full:a.example.com"
              && ListRule.parse("IP-CIDR,10.0.0.0/8,DIRECT,no-resolve")?.text == "10.0.0.0/8"
              && ListRule.parse("GEOIP,CN")?.text == "geoip:cn"
              && ListRule.parse("PROCESS-NAME,example") == nil)
        check("a malformed network is not read as a domain", ListRule.parse("192.0.2.0/33") == nil
              && ListRule.parse("full:192.0.2.1") == nil && ListRule.parse("IP-CIDR,192.0.2.0/33") == nil)
        check("an attribute nothing carries is refused", ListRule.parse("geosite:github@nosuchattr") == nil)
        check("full/keyword/regexp go to the forwarder as written",
              ListRule.full("a.example.com").expanded == ["full:a.example.com"]
              && ListRule.keyword("example").expanded == ["keyword:example"])

        let gh = ListRule.geosite("github", attribute: nil).expanded
        check("geosite:github brings its related names", gh.contains("domain:github.com") && gh.contains("domain:ghcr.io"))
        let cn = ListRule.geosite("cn", attribute: nil).expanded
        check("geosite:cn is a large resolved list (\(cn.count))", cn.count > 1000 && cn.allSatisfy {
            $0.hasPrefix("domain:") || $0.hasPrefix("full:") || $0.hasPrefix("keyword:") || $0.hasPrefix("regexp:") })
        let googleCN = ListRule.geosite("google", attribute: "cn").expanded
        let google = ListRule.geosite("google", attribute: nil).expanded
        check("an attribute filters (\(googleCN.count) of \(google.count))", !googleCN.isEmpty && googleCN.count < google.count)
        let ip = ListRule.geoip("cn").expanded
        check("geoip:cn expands to IP ranges (\(ip.count))", ip.count > 1000 && ip.allSatisfy { $0.hasPrefix("ipcidr:") })
        check("networks are not sent to the forwarder", ListRule.network("10.0.0.0/8").expanded.isEmpty)

        // The split page's examples (SplitPage.examples) must all be valid
        // and the attribute example must select something.
        for example in ["example.com", "full:www.example.com", "keyword:example", "10.0.0.5", "192.168.50.0/24", "geosite:apple", "geosite:microsoft",
                        "geosite:github", "geosite:apple@cn"] {
            check("example \(example) is valid", ListRule.parse(example) != nil)
        }
        check("geosite:apple@cn selects rules", !ListRule.geosite("apple", attribute: "cn").expanded.isEmpty)

        var legacy = AppSettings()
        legacy.directGroups = ["preset-a"]
        legacy.directCustom = ["example.org"]
        check("old groups are not migrated, own names are",
              DirectSites.sites(legacy) == [DirectSite(name: "example.org", domains: ["example.org"])])

        var settings = AppSettings()
        settings.directSites = [DirectSite(name: "x", domains: ["example.com"]),
                                DirectSite(name: "10.9.0.0/16", domains: ["10.9.0.0/16"]),
                                DirectSite(name: "geosite:github", domains: ["geosite:github"])]
        settings.autoLAN = false
        // One newline-joined text from the Rust core (§66.30).
        let direct = settings.directRuleText.split(separator: "\n").map(String.init)
        check("the forwarder gets names and lists, not networks, without repeats",
              direct.contains("example.com") && direct.contains("domain:ghcr.io") && !direct.contains("10.9.0.0/16")
              && direct.count == Set(direct).count)
        check("the allowlist gets the list's networks", settings.effectiveAllowNetworks == ["10.9.0.0/16"])
        settings.autoLAN = nil
        let local = LocalNetwork.current()
        check("local network on by default (\(local.joined(separator: ",")))",
              settings.effectiveAllowNetworks == ["10.9.0.0/16"] + local.filter { $0 != "10.9.0.0/16" })
        check("local networks are real CIDRs no wider than /16", local.allSatisfy { isValidCIDR($0)
              && (Int($0.split(separator: "/")[1]) ?? 0) >= 16 })
        // Adding from the 连接 page (DESIGN.md §四十四).
        check("site of a name", DirectSites.site(of: "www.example.com") == "example.com"
              && DirectSites.site(of: "a.b.example.com.cn") == "example.com.cn"
              && DirectSites.site(of: "files.example.co.uk") == "example.co.uk"
              && DirectSites.site(of: "example.com") == "example.com")
        let menu = DirectSites.choices(host: "a.b.example.com", address: "93.184.215.14")
        check("menu: whole site first, each level, the name, then the address",
              menu.map(\.rule) == ["example.com", "b.example.com", "full:a.b.example.com", "93.184.215.14/32"]
              && menu.first?.label.contains("整个网站") == true && menu[2].label.contains("只这一个"))
        check("menu for a bare site has no duplicate",
              DirectSites.choices(host: "example.com", address: "93.184.215.14").map(\.rule) == ["example.com", "93.184.215.14/32"])
        check("a full: line covers only that name",
              DirectSites.covering([DirectSite(name: "full:a.example.com", domains: ["full:a.example.com"])],
                                   host: "a.example.com", address: "203.0.113.1") == "full:a.example.com"
              && DirectSites.covering([DirectSite(name: "full:a.example.com", domains: ["full:a.example.com"])],
                                      host: "b.a.example.com", address: "203.0.113.1") == nil)
        check("menu without a name offers only the address",
              DirectSites.choices(host: nil, address: "203.0.113.10").map(\.rule) == ["203.0.113.10/32"])
        check("every menu line is a valid list line", menu.allSatisfy { ListRule.parse($0.rule) != nil })
        let list = [DirectSite(name: "example.com", domains: ["example.com"]),
                    DirectSite(name: "198.51.100.0/24", domains: ["198.51.100.0/24"]),
                    DirectSite(name: "geosite:github", domains: ["geosite:github"])]
        check("a name under a list domain is covered",
              DirectSites.covering(list, host: "mail.example.com", address: "203.0.113.1") == "example.com")
        check("a look-alike name is not covered",
              DirectSites.covering(list, host: "badexample.com", address: "203.0.113.1") == nil)
        check("an address in a list network is covered",
              DirectSites.covering(list, host: nil, address: "198.51.100.77") == "198.51.100.0/24")
        check("site lists are not looked into", DirectSites.covering(list, host: "github.com", address: "203.0.113.1") == nil)
        let added = DirectSites.adding("203.0.113.10/32", to: list)
        check("adding appends once", added.count == 4 && DirectSites.adding("203.0.113.10/32", to: added) == added
              && DirectSites.adding("example.com", to: list) == list)
        check("removing takes out only that line", DirectSites.removing("example.com", from: list) == Array(list.dropFirst()))
        let group = [DirectSite(name: "Old group", domains: ["example.com", "example.org"])]
        check("removing from a migrated group keeps the rest",
              DirectSites.removing("example.org", from: group) == [DirectSite(name: "Old group", domains: ["example.com"])])

        // Proxied sites (DESIGN.md §69): old settings have none; the lines
        // ride in the split list after the direct rules, in the user's order.
        check("old settings have no proxies and send no proxy lines",
              migrated.proxyRoutes == nil && migrated.proxyLines.isEmpty)
        var proxied = AppSettings()
        proxied.directSites = [DirectSite(name: "d", domains: ["direct.example"])]
        proxied.proxyRoutes = [
            ProxyRoute(name: "off", kind: .http, host: "10.0.0.9", port: 3128, sites: ["off.example"], enabled: false),
            ProxyRoute(name: "a", kind: .socks5, host: "127.0.0.1", port: 1080, sites: ["Example.com", "full:api.example.org", "geosite:github", "10.0.0.0/8"]),
            ProxyRoute(name: "bad", kind: .http, host: "bad host", port: 99999, sites: ["bad.example"]),
            ProxyRoute(name: "empty", kind: .http, host: "proxy.lan", port: 8080, sites: []),
        ]
        let lines = proxied.directRuleText.split(separator: "\n").map(String.init)
        check("direct rules first, then the proxies", lines.first == "direct.example" && lines[1] == "proxy:0 socks5 127.0.0.1 1080")
        check("a proxy's rules are expanded by the same parser",
              lines.contains("via:0:example.com") && lines.contains("via:0:full:api.example.org") && lines.contains("via:0:domain:github.com"))
        check("a written network is routed to its proxy", lines.contains("vianet:0:10.0.0.0/8") && !lines.contains { $0.hasPrefix("via:") && $0.contains("10.0.0.0") })
        check("a switched-off or empty proxy is not sent", !lines.contains { $0.contains("off.example") || $0.contains("proxy.lan") })
        check("an invalid address is still declared, so its sites are refused, not freed",
              lines.contains("proxy:1 http invalid 0") && lines.contains("via:1:bad.example"))
        // The panel's 分流直连 switch (§69.9): the list rests, names and
        // networks alike; the proxies and the local network are untouched.
        var restingDirect = proxied
        restingDirect.directSites = [DirectSite(name: "d", domains: ["direct.example"]), DirectSite(name: "n", domains: ["10.9.0.0/16"])]
        restingDirect.directPaused = true
        let restingLines = restingDirect.directRuleText.split(separator: "\n").map(String.init)
        check("paused direct list sends no direct rule and keeps the proxies",
              !restingLines.contains("direct.example") && restingLines.first == "proxy:0 socks5 127.0.0.1 1080")
        check("paused direct list frees no network", !restingDirect.effectiveAllowNetworks.contains("10.9.0.0/16")
              && DirectSites.sites(restingDirect).count == 2)
        restingDirect.directPaused = nil
        check("the direct list applies again when switched on", restingDirect.effectiveAllowNetworks.contains("10.9.0.0/16"))
        // The panel's 代理 switch (§69.8): paused sends no proxy at all; the
        // rules stay, and the old settings (no key) count as on.
        var paused = proxied
        paused.proxiesPaused = true
        check("paused proxies send no proxy lines and keep their rules",
              paused.proxyLines.isEmpty && paused.activeProxyRoutes.isEmpty && paused.proxyRoutes?.count == 4)
        check("settings without the switch have proxies on", proxied.proxiesOn && proxied.activeProxyRoutes.map(\.name) == ["a", "bad"])
        check("the check uses the same server line", proxied.proxyRoutes![1].serverLine(password: nil) == "socks5 127.0.0.1 1080")
        // Username and password: percent-encoded, the password from the keychain stand-in.
        ProxyPasswords.read = { _ in "p@ss word" }
        var withLogin = AppSettings()
        withLogin.proxyRoutes = [ProxyRoute(name: "l", kind: .socks5, host: "127.0.0.1", port: 1080, sites: ["geoip:cn", "x.example"],
                                            username: "alice", passwordStamp: "s1")]
        let login = withLogin.proxyLines
        check("credentials ride encoded on the proxy line", login.first == "proxy:0 socks5 127.0.0.1 1080 alice p%40ss%20word")
        check("geoip becomes address rules of the proxy", login.contains { $0.hasPrefix("via:0:ipcidr:") } && login.contains("via:0:x.example"))
        ProxyPasswords.read = { _ in nil }
        withLogin.proxyRoutes![0].passwordStamp = "s2"
        check("a missing password still names the user (refused there, not dropped)",
              withLogin.proxyLines.first == "proxy:0 socks5 127.0.0.1 1080 alice %00")
        // One-line proxy addresses (the 添加代理 window).
        func link(_ text: String) -> ProxyLink? { ProxyLink.parse(text).link }
        let full = link("socks5://al%40ice:p%3Ass@1.2.3.4:1080")
        check("socks5 URL with percent-encoded login", full?.kind == .socks5 && full?.host == "1.2.3.4" && full?.port == 1080
              && full?.username == "al@ice" && full?.password == "p:ss" && full?.assumedKind == false)
        check("http URL, path and name ignored or kept", link("http://proxy.example.net:8080/#家里")?.kind == .http
              && link("http://proxy.example.net:8080/#家里")?.name == "家里")
        check("socks5h and socks mean SOCKS5", link("socks5h://h:1")?.kind == .socks5 && link("socks://h:1")?.kind == .socks5)
        check("bare host:port is SOCKS5, said so", link("127.0.0.1:7891")?.assumedKind == true && link("user:pw@h:2")?.username == "user")
        check("IPv6 in brackets", link("socks5://[::1]:1080")?.host == "::1")
        let surge = link("VPS = socks5, 203.0.113.7, 443, bob, secret, udp-relay=true")
        check("Surge / Clash comma form with a name", surge?.name == "VPS" && surge?.host == "203.0.113.7" && surge?.port == 443
              && surge?.username == "bob" && surge?.password == "secret")
        check("bad lines say why", ProxyLink.parse("https://h:443").problem?.contains("HTTPS") == true
              && ProxyLink.parse("socks4://h:1").problem?.contains("SOCKS4") == true
              && ProxyLink.parse("1.2.3.4").problem?.contains("端口") == true
              && ProxyLink.parse("socks5://h:99999").problem?.contains("端口") == true
              && ProxyLink.parse("").problem != nil)
        let shown = ProxyLink.display(ProxyRoute(name: "n", kind: .http, host: "h", port: 8080, sites: [], username: "u", passwordStamp: "s"))
        check("editing shows the line without the password", shown == "http://u@h:8080")
        let roundTrip = try! JSONDecoder().decode(AppSettings.self, from: JSONEncoder().encode(proxied))
        check("proxies survive saving", roundTrip.proxyRoutes == proxied.proxyRoutes)
        let sparse = try! JSONDecoder().decode(ProxyRoute.self, from: Data(#"{"name":"x","host":"h","port":1}"#.utf8))
        check("a proxy saved without newer fields still reads", sparse.kind == .socks5 && sparse.enabled && sparse.sites.isEmpty)

        print("list-rules FAILS=\(fails)")
        exit(fails == 0 ? 0 : 1)
    }
}
