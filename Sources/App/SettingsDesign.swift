import AppKit
import SwiftUI

// The settings window's design language (UI-DESIGN.md 设置, DESIGN.md §69.14;
// user, 2026-11-26: "可以有点自己的设计语言跟思路吗？别搞得这么糙"):
// - every page opens with a status card in the page's own colour: what the
//   page is about and how it is right now, its main control on the right
//   (the panel's VPN card, same idea);
// - rows carry a small coloured icon, one plain line under the name at most;
// - colour means the route, here, on the panel and on the 流量 page alike:
//   green VPN, orange 直连, purple 代理, teal 出口保护.

enum SettingsTone {
    static let vpn = Color.green
    static let direct = Color.orange
    static let proxy = Color.purple
    static let shield = Color.teal
    static let account = Color.blue
    static let traffic = Color.indigo
    static let diagnostics = Color.pink
    static let neutral = Color.gray
}

/// The seven pages, in order (user, 2026-11-26: "可以优化成7页").
enum SettingsPages {
    static let all: [(tag: String, title: String, symbol: String)] = [
        ("general", "通用", "gearshape"),
        ("credentials", "账号", "person.crop.circle"),
        ("connect", "连接", "power"),
        ("split", "分流", "arrow.triangle.branch"),
        ("egress", "出口保护", "checkmark.shield"),
        ("traffic", "流量", "chart.bar.xaxis"),
        ("diagnostics", "诊断", "stethoscope"),
    ]

    /// Older names still arrive from links and stored choices: 分流代理 is
    /// a part of 分流 (§69.9); the connection list was the 连接 tab
    /// before it became 流量 (§69.14).
    static func resolve(_ tag: String) -> String {
        switch tag {
        case "proxy": return "split"
        case "connections": return "traffic"
        default: return all.contains { $0.tag == tag } ? tag : "general"
        }
    }

    /// The row height that lines up with the window's buttons: the
    /// title bar is see-through and holds the tab row (§69.14).
    static let tabRowHeight: CGFloat = 52
}

/// The tab row, in the window's title bar beside the close button: icon
/// over name, the selected one tinted with a soft background.
struct SettingsTabBar: View {
    @Binding var tab: String

    var body: some View {
        let current = SettingsPages.resolve(tab)
        HStack(spacing: 2) {
            ForEach(SettingsPages.all, id: \.tag) { page in
                SettingsTabButton(title: page.title, symbol: page.symbol, selected: page.tag == current) {
                    tab = page.tag
                }
            }
        }
        .frame(maxWidth: .infinity)
        .frame(height: SettingsPages.tabRowHeight)
        // Empty parts of the bar move the window, as a title bar does.
        .background(WindowDragArea())
    }
}

/// One page in the tab row.
struct SettingsTabButton: View {
    var title: String
    var symbol: String
    var selected: Bool
    var action: () -> Void
    @State private var hovering = false

    var body: some View {
        Button(action: action) {
            VStack(spacing: 2) {
                Image(systemName: symbol).font(.system(size: 15, weight: .regular))
                    .frame(height: 19)
                Text(title).font(.system(size: 10.5))
            }
            .frame(width: 62, height: 42)
            .foregroundStyle(selected ? Color.accentColor : Color.secondary)
            .background(RoundedRectangle(cornerRadius: 8, style: .continuous)
                .fill(Color.primary.opacity(selected ? 0.09 : (hovering ? 0.045 : 0))))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .onHover { hovering = $0 }
        .accessibilityLabel(title)
        .accessibilityAddTraits(selected ? .isSelected : [])
    }
}

/// Lets a drag on an empty part of the see-through title bar move the
/// window.
private struct WindowDragArea: NSViewRepresentable {
    final class DragView: NSView {
        override var mouseDownCanMoveWindow: Bool { true }
        override func mouseDown(with event: NSEvent) { window?.performDrag(with: event) }
    }
    func makeNSView(context: Context) -> NSView { DragView() }
    func updateNSView(_ nsView: NSView, context: Context) {}
}

/// A small rounded square with a white symbol, coloured by meaning.
struct IconTile: View {
    var symbol: String
    var color: Color
    var size: CGFloat = 22

    var body: some View {
        Image(systemName: symbol)
            .font(.system(size: size * 0.5, weight: .semibold))
            .foregroundStyle(.white)
            .frame(width: size, height: size)
            .background(RoundedRectangle(cornerRadius: size * 0.27, style: .continuous).fill(color.gradient))
            .accessibilityHidden(true)
    }
}

/// A row's label: icon, name, and at most one plain line under it.
struct IconLabel: View {
    var title: String
    var subtitle: String? = nil
    var symbol: String
    var color: Color

    var body: some View {
        HStack(spacing: 10) {
            IconTile(symbol: symbol, color: color)
            VStack(alignment: .leading, spacing: 1) {
                Text(title)
                if let subtitle {
                    Text(subtitle)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
    }
}

/// The page's status card. Put it in the first section's header: it
/// scrolls with the page and lines up with the cards below.
struct PageHero<Trailing: View>: View {
    var symbol: String
    var color: Color
    var title: String
    var status: String
    /// The dot before the status line; nil for none.
    var dot: Color? = nil
    /// A letter in a circle instead of the symbol (the account).
    var letter: String? = nil
    /// The card's wash when it differs from the icon's colour (a page
    /// whose colour would read as a warning, like 诊断's).
    var wash: Color? = nil
    @ViewBuilder var trailing: () -> Trailing

    var body: some View {
        HStack(spacing: 14) {
            if let letter {
                Text(letter)
                    .font(.system(size: 19, weight: .semibold))
                    .foregroundStyle(.white)
                    .frame(width: 42, height: 42)
                    .background(Circle().fill(LinearGradient(colors: [color, color.opacity(0.7)],
                                                             startPoint: .topLeading, endPoint: .bottomTrailing)))
                    .accessibilityHidden(true)
            } else {
                IconTile(symbol: symbol, color: color, size: 42)
            }
            VStack(alignment: .leading, spacing: 4) {
                Text(title)
                    .font(.system(size: 18, weight: .bold))
                    .foregroundStyle(.primary)
                HStack(alignment: .center, spacing: 6) {
                    if let dot { Circle().fill(dot).frame(width: 7, height: 7) }
                    Text(status)
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            Spacer(minLength: 12)
            trailing()
        }
        .padding(14)
        .background(RoundedRectangle(cornerRadius: 12, style: .continuous)
            .fill(LinearGradient(colors: [(wash ?? color).opacity(0.22), (wash ?? color).opacity(0.05)],
                                 startPoint: .topLeading, endPoint: .bottomTrailing)))
        .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous)
            .strokeBorder((wash ?? color).opacity(0.28), lineWidth: 1))
        // A section header is inset like the rows: reach the card edges.
        .padding(.horizontal, -10)
        .padding(.bottom, 6)
        .textCase(nil)
        .accessibilityElement(children: .contain)
    }
}

extension PageHero where Trailing == EmptyView {
    init(symbol: String, color: Color, title: String, status: String, dot: Color? = nil, letter: String? = nil,
         wash: Color? = nil) {
        self.init(symbol: symbol, color: color, title: title, status: status, dot: dot, letter: letter, wash: wash) {
            EmptyView()
        }
    }
}

/// Which list wins when a site is in several, drawn as a short road
/// instead of a sentence.
struct SplitOrderStrip: View {
    var body: some View {
        HStack(spacing: 6) {
            Text("同一网站命中多处时").foregroundStyle(.secondary)
            step("出口保护", SettingsTone.shield)
            arrow
            step("分流代理", SettingsTone.proxy)
            arrow
            step("分流直连", SettingsTone.direct)
            arrow
            step("其余走 VPN", SettingsTone.vpn)
        }
        .font(.caption)
        .accessibilityElement(children: .combine)
    }

    private var arrow: some View {
        Image(systemName: "chevron.right").font(.system(size: 8, weight: .bold)).foregroundStyle(.tertiary)
    }

    private func step(_ title: String, _ color: Color) -> some View {
        HStack(spacing: 4) {
            Circle().fill(color).frame(width: 6, height: 6)
            Text(title)
        }
    }
}

/// A first-time card: what goes here, and the one button that starts it.
struct EmptyGuide<Action: View>: View {
    var symbol: String
    var color: Color
    var title: String
    var text: String
    @ViewBuilder var action: () -> Action

    var body: some View {
        VStack(spacing: 8) {
            IconTile(symbol: symbol, color: color, size: 36)
            Text(title).font(.body.weight(.semibold))
            Text(text)
                .font(.caption)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
            action()
                .padding(.top, 2)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 18)
    }
}
