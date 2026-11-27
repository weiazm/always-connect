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
/// instead of a sentence (DESIGN §69.9, §71 D1-A).
struct SplitOrderStrip: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 3) {
            HStack(spacing: 6) {
                Text("同一网站命中多处时").foregroundStyle(.secondary)
                step("分流代理", SettingsTone.proxy)
                arrow
                step("分流直连", SettingsTone.direct)
                arrow
                step("其余走 Cisco", SettingsTone.vpn)
            }
            HStack(spacing: 4) {
                Circle().fill(SettingsTone.shield).frame(width: 6, height: 6)
                Text("受出口保护的网站不会走分流直连；命中代理时经代理并先检查出口。")
                    .foregroundStyle(.secondary)
            }
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

// MARK: - Unified inputs & auto-trim (DESIGN §71)

/// Whitespace cleanup for single-line and multi-line inputs without fighting
/// normal typing.
enum TextTrim {
    /// Trims leading/trailing whitespace and collapses embedded newlines.
    static func singleLine(_ text: String) -> String {
        text.replacingOccurrences(of: "\r\n", with: " ")
            .replacingOccurrences(of: "\n", with: " ")
            .replacingOccurrences(of: "\r", with: " ")
            .trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// Applied while typing: trims immediately when pasted text contains
    /// newlines or leading/trailing whitespace (delta > 1), leaving single
    /// spaces typed mid-input untouched until blur/submit.
    static func liveSingleLine(old: String, new: String) -> String {
        if new.contains(where: \.isNewline) {
            return singleLine(new)
        }
        let delta = abs(new.count - old.count)
        if delta > 1 {
            return new.trimmingCharacters(in: .whitespacesAndNewlines)
        }
        // Leading spaces at the start of an empty field are always accidental.
        if old.isEmpty, new.first?.isWhitespace == true {
            return new.trimmingCharacters(in: .whitespaces)
        }
        return new
    }

    /// Trims each line's leading/trailing spaces and drops leading/trailing
    /// blank lines while keeping internal line breaks intact.
    static func ruleLines(_ text: String) -> String {
        let normalized = text.replacingOccurrences(of: "\r\n", with: "\n")
            .replacingOccurrences(of: "\r", with: "\n")
        var lines = normalized.split(omittingEmptySubsequences: false, whereSeparator: \.isNewline)
            .map { $0.trimmingCharacters(in: .whitespaces) }
        while lines.first?.isEmpty == true { lines.removeFirst() }
        while lines.last?.isEmpty == true { lines.removeLast() }
        return lines.joined(separator: "\n")
    }

    /// Applied on paste into a multi-line rule box (delta > 1): cleans pasted
    /// indentation and outer blank lines without disrupting normal Enter keys.
    static func liveRuleLines(old: String, new: String) -> String {
        guard abs(new.count - old.count) > 1 else { return new }
        return ruleLines(new)
    }
}

/// Shared visual frame for single-line and multi-line inputs across Settings
/// and sheets so every text box shares the same corner radius, surface fill,
/// border and focus accent.
struct AlwaysInputChrome: ViewModifier {
    var focused: Bool
    var paddingH: CGFloat = 10
    var paddingV: CGFloat = 7

    func body(content: Content) -> some View {
        content
            .padding(.horizontal, paddingH)
            .padding(.vertical, paddingV)
            .background(
                RoundedRectangle(cornerRadius: 8, style: .continuous)
                    .fill(Color.primary.opacity(0.055))
            )
            .overlay(
                RoundedRectangle(cornerRadius: 8, style: .continuous)
                    .strokeBorder(
                        focused ? Color.accentColor.opacity(0.75) : Color.primary.opacity(0.14),
                        lineWidth: focused ? 1.5 : 1
                    )
                    .allowsHitTesting(false)
            )
    }
}

/// Single-line input matching `SettingsDesign` with automatic trim on paste,
/// blur and submit.
struct AlwaysTextField: View {
    var prompt: String
    @Binding var text: String
    var monospaced: Bool = false
    var onSubmit: (() -> Void)? = nil
    @FocusState private var focused: Bool
    @State private var lastValue: String

    init(_ prompt: String, text: Binding<String>, monospaced: Bool = false, onSubmit: (() -> Void)? = nil) {
        self.prompt = prompt
        self._text = text
        self.monospaced = monospaced
        self.onSubmit = onSubmit
        self._lastValue = State(initialValue: text.wrappedValue)
    }

    var body: some View {
        TextField("", text: $text, prompt: Text(prompt))
            .textFieldStyle(.plain)
            .font(monospaced ? .system(.body, design: .monospaced) : .body)
            .focused($focused)
            .modifier(AlwaysInputChrome(focused: focused))
            .onChange(of: text) { updated in
                let cleaned = TextTrim.liveSingleLine(old: lastValue, new: updated)
                if cleaned != updated {
                    text = cleaned
                    lastValue = cleaned
                } else {
                    lastValue = updated
                }
            }
            .onChange(of: focused) { isFocused in
                if !isFocused {
                    let cleaned = TextTrim.singleLine(text)
                    if cleaned != text { text = cleaned }
                    lastValue = text
                }
            }
            .onSubmit {
                let cleaned = TextTrim.singleLine(text)
                if cleaned != text { text = cleaned }
                lastValue = text
                onSubmit?()
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
