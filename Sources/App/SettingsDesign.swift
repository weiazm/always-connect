import AppKit
import SwiftUI

// The settings window's design language (UI-DESIGN.md 设置, DESIGN.md §69.14;
// user, 2026-11-26: "可以有点自己的设计语言跟思路吗？别搞得这么糙"):
// - every page opens with one line: the page's icon and name, how it is
//   right now, its main control on the right (no coloured block behind it);
// - one size per kind of thing (SettingsSize);
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
    var size: CGFloat = SettingsSize.rowIcon

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

/// One size for each kind of thing, on every page (user, 2026-11-26:
/// "有的大小还不协调").
enum SettingsSize {
    /// The page header's icon and the first-time guides' icon.
    static let pageIcon: CGFloat = 30
    /// The icon in front of a row's name.
    static let rowIcon: CGFloat = 22
    static let pageTitle = Font.system(size: 16, weight: .semibold)
}

/// The page's first line: its icon and name, how it is right now, and the
/// page's main action on the right. No coloured block behind it (user,
/// 2026-11-26: "每个tab页上面的渐变色块 没必要吧？"). In a Form, put it
/// in the first section's header: it scrolls with the page and starts
/// where the section titles start.
struct PageHeader<Trailing: View>: View {
    var symbol: String
    var color: Color
    var title: String
    var status: String
    /// The dot before the status line; nil for none.
    var dot: Color? = nil
    /// A letter in a circle instead of the symbol (the account).
    var letter: String? = nil
    @ViewBuilder var trailing: () -> Trailing

    var body: some View {
        HStack(spacing: 12) {
            if let letter {
                Text(letter)
                    .font(.system(size: SettingsSize.pageIcon * 0.45, weight: .semibold))
                    .foregroundStyle(.white)
                    .frame(width: SettingsSize.pageIcon, height: SettingsSize.pageIcon)
                    .background(Circle().fill(color.gradient))
                    .accessibilityHidden(true)
            } else {
                IconTile(symbol: symbol, color: color, size: SettingsSize.pageIcon)
            }
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(SettingsSize.pageTitle)
                    .foregroundStyle(.primary)
                HStack(alignment: .center, spacing: 5) {
                    if let dot { Circle().fill(dot).frame(width: 6, height: 6) }
                    Text(status)
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            Spacer(minLength: 12)
            trailing()
        }
        .padding(.bottom, 6)
        .textCase(nil)
        .accessibilityElement(children: .contain)
    }
}

extension PageHeader where Trailing == EmptyView {
    init(symbol: String, color: Color, title: String, status: String, dot: Color? = nil, letter: String? = nil) {
        self.init(symbol: symbol, color: color, title: title, status: status, dot: dot, letter: letter) { EmptyView() }
    }
}

/// Parts of one page, as wide as the card they sit in (the system's
/// segmented control keeps its own width and sat small in a wide card).
struct SettingsSegments: View {
    var items: [(tag: String, title: String)]
    @Binding var selection: String

    var body: some View {
        HStack(spacing: 2) {
            ForEach(items, id: \.tag) { item in
                let selected = item.tag == selection
                Button { selection = item.tag } label: {
                    Text(item.title)
                        .font(.callout.weight(selected ? .semibold : .regular))
                        .foregroundStyle(selected ? Color.primary : Color.secondary)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 5)
                        .background(RoundedRectangle(cornerRadius: 6, style: .continuous)
                            .fill(selected ? Color.primary.opacity(0.12) : Color.clear))
                        .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .accessibilityLabel(item.title)
                .accessibilityAddTraits(selected ? .isSelected : [])
            }
        }
        .padding(2)
        .background(RoundedRectangle(cornerRadius: 8, style: .continuous).fill(Color.primary.opacity(0.06)))
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
            step("其余走 Cisco", SettingsTone.vpn)
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
            IconTile(symbol: symbol, color: color, size: SettingsSize.pageIcon)
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
