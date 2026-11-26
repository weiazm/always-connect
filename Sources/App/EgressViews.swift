import SwiftUI

// Shared pieces of the exit protection screens (UI-DESIGN.md「出口保护页」).
// Plain words only: a website, the country it leaves from, what is
// blocked and what the user can do about it.

/// One website's way out, in the words the list and the detail share.
struct EgressRuleBadge: Equatable {
    enum Tone { case neutral, active, good, warning, bad }
    let text: String
    let tone: Tone
    let problem: String?

    var color: Color {
        switch tone {
        case .neutral: return .secondary
        case .active: return .accentColor
        case .good: return .green
        case .warning: return .orange
        case .bad: return .red
        }
    }

    static func of(_ group: EgressProtection.Group, config: EgressProtection,
                   state: EgressProtection.GroupState?, connected: Bool) -> Self {
        if !group.enabled { return .init(text: "已暂停", tone: .neutral, problem: nil) }
        if group.expect.isEmpty {
            return .init(text: "要处理", tone: .bad, problem: "还没选允许的国家或地区")
        }
        if group.sites.isEmpty {
            return .init(text: "要处理", tone: .bad, problem: "还没填要保护的网站")
        }
        guard connected else { return .init(text: "待命", tone: .neutral, problem: nil) }
        guard let state else { return .init(text: "核实中", tone: .active, problem: nil) }
        switch state.displayLevel {
        case .ok: return .init(text: "正常", tone: .good, problem: nil)
        case .partial:
            let count = state.blockedCount ?? 0
            return .init(text: count > 0 ? "拦下 \(count) 次" : "部分拦截", tone: .warning, problem: state.blockCaption)
        case .unknown: return .init(text: "核实中", tone: .active, problem: nil)
        }
    }
}

struct EgressStatusPill: View {
    let badge: EgressRuleBadge
    var body: some View {
        Text(badge.text)
            .font(.caption.weight(.medium))
            .foregroundStyle(badge.tone == .neutral ? Color.secondary : badge.color)
            .padding(.horizontal, 8).padding(.vertical, 2)
            .background(Capsule().fill(badge.color.opacity(badge.tone == .neutral ? 0.12 : 0.16)))
            .fixedSize()
    }
}

/// A letter tile for a website, tinted from its name so rows are told
/// apart at a glance without fetching any icon.
struct EgressSiteAvatar: View {
    let name: String
    var size: CGFloat = 30

    private static let tints: [Color] = [.blue, .teal, .indigo, .purple, .pink, .orange, .green, .cyan]

    var body: some View {
        let letter = name.first { $0.isLetter || $0.isNumber }.map { String($0).uppercased() } ?? "·"
        let tint = Self.tints[Int(name.unicodeScalars.reduce(0) { ($0 &* 31 &+ $1.value) % 9973 }) % Self.tints.count]
        RoundedRectangle(cornerRadius: size * 0.26, style: .continuous)
            .fill(tint.gradient)
            .frame(width: size, height: size)
            .overlay(Text(letter).font(.system(size: size * 0.48, weight: .semibold, design: .rounded)).foregroundStyle(.white))
            .accessibilityHidden(true)
    }
}

/// An inline notice with its actions on the right.
struct EgressCallout<Actions: View>: View {
    let icon: String
    let tint: Color
    let text: String
    var caption: String? = nil
    @ViewBuilder var actions: () -> Actions

    var body: some View {
        HStack(alignment: .center, spacing: 10) {
            Image(systemName: icon).foregroundStyle(tint).font(.body.weight(.semibold))
            VStack(alignment: .leading, spacing: 2) {
                Text(text).fixedSize(horizontal: false, vertical: true)
                if let caption {
                    Text(caption).font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                }
            }
            Spacer(minLength: 8)
            HStack(spacing: 8) { actions() }.controlSize(.small)
        }
        .padding(.vertical, 8).padding(.horizontal, 10)
        .background(RoundedRectangle(cornerRadius: 8, style: .continuous).fill(tint.opacity(0.10)))
    }
}

struct EgressChangeNotice: Identifiable {
    let id = UUID()
    let text: String
    let change: EgressRuleChange
}

struct EgressChangeBanner: View {
    let notice: EgressChangeNotice
    let undo: () -> Void
    var body: some View {
        EgressCallout(icon: "checkmark.circle.fill", tint: .green, text: notice.text) {
            Button("撤销", action: undo)
        }
    }
}

struct EgressReconnectPrompt: View {
    let change: EgressRuleChange
    let cancel: () -> Void
    var canConfirm = true
    let confirm: () -> Void
    var body: some View {
        EgressCallout(icon: "arrow.triangle.2.circlepath", tint: .accentColor,
                      text: change.after.isActive ? "开启出口保护要重连一次 Cisco" : "关掉最后一个保护要重连一次 Cisco",
                      caption: "通常不用在手机上确认；已打开的网页可能要刷新。") {
            Button("取消", action: cancel)
            Button(change.confirmationTitle, action: confirm).disabled(!canConfirm).keyboardShortcut(.defaultAction)
        }
    }
}

/// Allowed countries as chips; the last one cannot be removed.
struct EgressCountryChips: View {
    let countries: [String]
    var removable = true
    let remove: (String) -> Void
    let add: (String) -> Void
    @State private var picking = false
    @State private var search = ""

    private var choices: [String] {
        Locale.Region.isoRegions.map(\.identifier).filter {
            $0.utf8.count == 2 && !countries.contains($0)
                && (search.isEmpty || egressCountryName($0).localizedCaseInsensitiveContains(search)
                    || $0.localizedCaseInsensitiveContains(search))
        }.sorted { egressCountryName($0).localizedCompare(egressCountryName($1)) == .orderedAscending }
    }

    var body: some View {
        HStack(spacing: 6) {
            ForEach(countries, id: \.self) { code in
                HStack(spacing: 4) {
                    Text(egressCountryLabel(code))
                    if removable && countries.count > 1 {
                        Button { remove(code) } label: {
                            Image(systemName: "xmark.circle.fill").foregroundStyle(.secondary)
                        }
                        .buttonStyle(.borderless)
                        .accessibilityLabel("不再允许 " + egressCountryName(code))
                    }
                }
                .padding(.horizontal, 8).padding(.vertical, 3)
                .background(Capsule().fill(Color.secondary.opacity(0.14)))
            }
            Button { search = ""; picking = true } label: {
                Label(countries.isEmpty ? "选国家或地区" : "添加", systemImage: "plus")
            }
            .buttonStyle(.borderless)
            .popover(isPresented: $picking, arrowEdge: .bottom) {
                VStack(alignment: .leading, spacing: 8) {
                    TextField("搜索国家或地区", text: $search).textFieldStyle(.roundedBorder)
                    List(choices, id: \.self) { code in
                        Button(egressCountryLabel(code)) {
                            add(code)
                            picking = false
                        }.buttonStyle(.plain)
                    }
                }
                .padding(12).frame(width: 260, height: 320)
            }
        }
    }
}

/// The "blocked first, ask the user" step made visible: a wrong exit
/// country the background service can prove, with its answer buttons.
struct EgressDecision: Identifiable {
    let approval: EgressCountryApproval
    let ruleName: String
    /// DNS steering is on, so the site usually recovers by itself (§66.28).
    var steering = true
    var id: String { approval.id }
    var rule: UInt32 { approval.group }
}

extension EgressProtection.Status {
    func decisions(config: EgressProtection) -> [EgressDecision] {
        guard running else { return [] }
        return config.groups.filter(\.enabled).flatMap { rule -> [EgressDecision] in
            approvals(for: rule.id).filter { approval in
                records.first { $0.group == rule.id && $0.started == approval.started }?.expected == rule.expect
            }.map { EgressDecision(approval: $0, ruleName: rule.name, steering: config.steer ?? true) }
        }
    }
}

struct EgressDecisionList: View {
    @ObservedObject private var manager = HelperClient.shared
    let decisions: [EgressDecision]
    let refresh: () -> Void
    var open: ((UInt32) -> Void)? = nil
    @State private var pending: Pending?
    @State private var busy = false
    @State private var message: String?

    private enum Pending {
        case country(EgressCountryApproval)

        var title: String {
            switch self {
            case .country(let approval): return "以后也允许从\(egressCountryName(approval.country))出去？"
            }
        }
        var caption: String {
            switch self {
            case .country(let approval):
                return "已确认 \(approval.observation.host) 现在从 \(egressCountryLabel(approval.country)) 出去。允许后，这个国家的出口也算正常。"
            }
        }
        var button: String {
            switch self {
            case .country(let approval): return "允许" + egressCountryName(approval.country)
            }
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            ForEach(decisions) { decision in row(decision) }
            if let message {
                Text(message).font(.caption).foregroundStyle(.secondary)
            }
        }
        .padding(.vertical, 2)
        .confirmationDialog(pending?.title ?? "确认", isPresented: Binding(
            get: { pending != nil }, set: { if !$0 { pending = nil } }
        ), titleVisibility: .visible, presenting: pending) { choice in
            Button(choice.button) { confirm(choice) }
            Button("继续拦着", role: .cancel) {}
        } message: { choice in Text(choice.caption) }
    }

    private func row(_ decision: EgressDecision) -> some View {
        let approval = decision.approval
        // The site first, in words (user, 2026-11-25: "ip我怎么看懂是哪个域名");
        // the server and exit addresses only on hover.
        let site = approval.observation.displayedHost
        let fix = decision.steering ? "正在换到同一网站出口正确的服务器，通常一分钟内恢复。" : ""
        return EgressCallout(icon: "exclamationmark.shield.fill", tint: .orange,
                             text: "\(site) 这台服务器走了 \(egressCountryLabel(approval.country)) 出口，已拦住",
                             caption: "它属于「\(decision.ruleName)」这条保护。" + fix) {
            if let open { Button("详情") { open(approval.group) } }
            Button(busy ? "正在检查…" : "重新检查") { recheck(approval.group) }
            Button("允许" + egressCountryName(approval.country)) { pending = .country(approval) }
        }
        .help("服务器 \(approval.observation.peerAddress ?? "—")"
              + (approval.observation.ip.map { "，出口地址 \($0)" } ?? ""))
        .disabled(busy || !manager.showsConnected)
    }

    private func recheck(_ id: UInt32) {
        busy = true
        manager.recheckEgressRule(id) { ok in
            busy = false
            message = ok ? nil : "这次没能重新检查。请稍后再试。"
            refresh()
        }
    }

    private func confirm(_ choice: Pending) {
        pending = nil
        busy = true
        switch choice {
        case .country(let approval):
            manager.allowEgressCountry(approval) { ok in
                busy = false
                message = ok ? "已允许" + egressCountryName(approval.country) : "出口刚刚又变了，没能确认。请看最新状态。"
                refresh()
            }
        }
    }
}

extension EgressProtection.Level {
    var color: Color {
        switch self {
        case .ok, .unknown: return .secondary
        case .partial: return .orange
        }
    }
}
