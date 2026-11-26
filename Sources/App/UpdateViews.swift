import SwiftUI

/// The update notice in the menu-bar panel (UI-DESIGN.md §四, DESIGN.md
/// §三十三): only while a newer release is known; nothing otherwise.
/// One click on 更新 starts it (user, 2026-11-26: "我点了更新为什么下面
/// 还要再点一遍"); what happens is said before the click, in the tooltip
/// and the line under it.
struct UpdateBanner: View {
    @ObservedObject var updates = UpdateChecker.shared
    /// Close the panel (the browser takes the focus anyway).
    var onOpen: () -> Void = {}

    var body: some View {
        if let update = updates.available {
            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 6) {
                    Label("有新版本 \(update.version)\(update.prerelease ? "（预发布）" : "")",
                          systemImage: "arrow.down.circle")
                        .font(.caption)
                        .foregroundStyle(Color.accentColor)
                    Spacer()
                    if !updates.installing {
                        Button("跳过") { updates.skip(update) }
                            .buttonStyle(.borderless)
                            .font(.caption)
                            .help("这个版本不再提示，更新的版本出来时照常提示")
                        Button("查看") {
                            updates.openReleasePage(update)
                            onOpen()
                        }
                        .buttonStyle(.borderless)
                        .font(.caption)
                        .help("在浏览器里打开这个版本的发布页")
                        Button("更新") { updates.install(update) }
                            .font(.caption)
                            .help(UpdateSteps.what)
                    }
                }
                UpdateProgress(update: update)
            }
        }
    }
}

/// The line under "有新版本": the download, or why it stopped. Shared by
/// the panel and Settings.
struct UpdateProgress: View {
    @ObservedObject var updates = UpdateChecker.shared
    let update: UpdateChecker.Available

    var body: some View {
        if updates.installing {
            VStack(alignment: .leading, spacing: 4) {
                if case .downloading(let done, let total) = updates.installStep, total > 0 {
                    ProgressView(value: Double(min(done, total)), total: Double(total))
                        .progressViewStyle(.linear)
                        .controlSize(.small)
                }
                HStack(spacing: 6) {
                    ProgressView().controlSize(.small)
                    Text(Self.stepText(updates.installStep, version: update.version))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        } else if let error = updates.installError {
            Text("更新没有完成：\(error)。原来的版本没有改动，可以再试一次或打开发布页手动下载。")
                .font(.caption)
                .foregroundStyle(.orange)
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}

extension UpdateProgress {
    /// One line per step of a running update (DESIGN.md §38.5).
    static func stepText(_ step: UpdateChecker.InstallStep?, version: String) -> String {
        func mb(_ bytes: Int64) -> String { String(format: "%.1f", Double(bytes) / 1_000_000) }
        switch step {
        case .downloading(let done, let total) where total > 0:
            return "正在下载 \(version)：\(mb(min(done, total))) / \(mb(total)) MB（Cisco 照常可用）"
        case .downloading(let done, _):
            return "正在下载 \(version)：已下载 \(mb(done)) MB（Cisco 照常可用）"
        case .checking:
            return "正在校验新版…"
        case .restarting:
            return "校验通过，正在退出并换上新版，几秒后自动打开…"
        case .finding, .none:
            return "正在查找 \(version) 的安装包…"
        }
    }
}

enum UpdateSteps {
    /// Said before the click, so the click itself needs no confirmation.
    static let what = "下载并校验新版，然后自动退出、换上新版并重新打开；Cisco 断开几秒后自动重连。"
}

/// Settings → 通用 → 关于 AlwaysConnect (UI-DESIGN.md §六, §69.14): this
/// version with a button that checks now, and what it found; 更新 starts
/// at once. Rows only: the card is AboutSection's.
struct UpdateRows: View {
    @ObservedObject private var updates = UpdateChecker.shared
    @State private var message: String?
    @State private var startedFromSettings = false

    var body: some View {
        LabeledContent {
            HStack(spacing: 8) {
                Text(UpdateChecker.currentVersion)
                    .foregroundStyle(.secondary)
                Button(updates.checking ? "正在检查…" : "检查更新") { checkNow() }
                    .disabled(updates.checking || updates.installing)
            }
        } label: {
            IconLabel(title: "当前版本", subtitle: schedule, symbol: "arrow.down.circle.fill", color: SettingsTone.account)
        }
        if let update = updates.available {
            LabeledContent {
                HStack(spacing: 8) {
                    Menu("更多") {
                        Button("跳过这个版本") {
                            updates.skip(update)
                            message = "已跳过 \(update.version)，更新的版本出来时会再提示"
                        }
                        Button("打开发布页") { updates.openReleasePage(update) }
                    }
                    .fixedSize()
                    Button("更新到 \(update.version)") { start(update) }
                        .buttonStyle(.borderedProminent)
                        .disabled(updates.installing || startedFromSettings)
                }
                .disabled(updates.installing)
            } label: {
                IconLabel(title: "有新版本 \(update.version)\(update.prerelease ? "（预发布）" : "")",
                          subtitle: UpdateSteps.what, symbol: "sparkles", color: SettingsTone.account)
            }
            if startedFromSettings && !updates.installing {
                Text("正在更新：下载并校验好后会自动退出并打开新版；出了问题会在菜单栏面板里说明。")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                UpdateProgress(update: update)
            }
        }
        if let message {
            Text(message)
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    /// The menu-bar App does it: it is the one that quits and its panel
    /// shows a failure (§32.15).
    private func start(_ update: UpdateChecker.Available) {
        message = nil
        if AppRole.isSettings {
            SettingsLink.shared.send("installUpdate")
            startedFromSettings = true
        } else {
            updates.install(update)
        }
    }

    /// When it looks (no notification, no switch: user's choice, §33).
    private var schedule: String {
        guard let last = updates.lastSuccess else { return "打开菜单栏面板时自动检查" }
        let f = DateFormatter()
        f.locale = Locale(identifier: "zh_CN")
        f.dateFormat = "M月d日 HH:mm"
        return "打开菜单栏面板时自动检查 · 上次 \(f.string(from: last))"
    }

    private func checkNow() {
        message = nil
        updates.check { outcome in
            switch outcome {
            case .newer: message = nil  // the row above says it
            case .skipped(let version): message = "最新的是 \(version)，你之前选了跳过它"
            case .current: message = "已是最新版本"
            case .unreadable: message = "暂时无法检查：发布页不可访问（仓库未公开或访问次数受限），过一会儿再试"
            case .failed: message = "检查失败：连不上 GitHub，请检查网络后再试"
            }
        }
    }
}
