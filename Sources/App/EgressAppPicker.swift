import AppKit
import SwiftUI

/// Choosing the apps to protect (UI-DESIGN「出口保护页」, §66.24): tick
/// running programs or pick an app from disk, choose the allowed
/// countries, start. Opened from the page, a rule's detail (adds to that
/// rule) and the Connections page (with its program ticked).
struct EgressAppPicker: View {
    @Environment(\.dismiss) private var dismiss
    @ObservedObject private var manager = HelperClient.shared
    let rule: EgressProtection.Group?
    let preview: [EgressAppCandidate]?
    let save: (_ apps: [String], _ countries: [String], _ done: @escaping (Bool) -> Void) -> Void
    private let preselectedProcess: String?

    @State private var candidates: [EgressAppCandidate] = []
    @State private var extra: [EgressAppCandidate] = []
    @State private var chosen = Set<String>()
    @State private var search = ""
    @State private var countries: [String]
    @State private var saving = false
    @State private var error: String?

    init(rule: EgressProtection.Group? = nil, process: String? = nil, countries: [String] = [],
         preview: [EgressAppCandidate]? = nil,
         save: @escaping ([String], [String], @escaping (Bool) -> Void) -> Void) {
        self.rule = rule
        self.preselectedProcess = process
        self.preview = preview
        self.save = save
        _countries = State(initialValue: rule?.expect ?? countries)
    }

    private var all: [EgressAppCandidate] {
        let taken = Set(rule?.apps ?? [])
        var seen = Set<String>()
        return (extra + candidates).filter { !taken.contains($0.pattern) && seen.insert($0.pattern).inserted }
    }

    private var shown: [EgressAppCandidate] {
        let query = search.trimmingCharacters(in: .whitespaces)
        guard !query.isEmpty else { return all }
        return all.filter { $0.name.localizedCaseInsensitiveContains(query) || $0.pattern.localizedCaseInsensitiveContains(query) }
    }

    private var canSave: Bool { !chosen.isEmpty && (rule != nil || !countries.isEmpty) && !saving }

    var body: some View {
        VStack(spacing: 0) {
            VStack(alignment: .leading, spacing: 4) {
                Text(rule.map { "往「\($0.name)」里加 App" } ?? "添加要保护的 App").font(.title3.weight(.semibold))
                Text("勾选正在运行的程序，或从「应用程序」里选。它们经 VPN 的每条新连接都会先确认从哪个国家出去，不对就拦下。")
                    .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding([.horizontal, .top], 20).padding(.bottom, 12)
            HStack(spacing: 8) {
                HStack(spacing: 6) {
                    Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                    TextField("", text: $search, prompt: Text("筛选程序"))
                        .textFieldStyle(.plain)
                }
                .padding(.horizontal, 8).padding(.vertical, 6)
                .background(RoundedRectangle(cornerRadius: 7).fill(Color.primary.opacity(0.06)))
                Button("从「应用程序」选…", action: chooseFromDisk)
                Button { load() } label: { Image(systemName: "arrow.clockwise") }.help("重新读取正在运行的程序")
            }
            .padding(.horizontal, 20).padding(.bottom, 10)
            List {
                ForEach(shown) { candidate in row(candidate) }
                if shown.isEmpty {
                    Text(search.isEmpty ? "没有找到正在运行的程序。可以从「应用程序」里选。" : "没有匹配的程序。")
                        .foregroundStyle(.secondary).frame(maxWidth: .infinity, alignment: .center).padding(.vertical, 30)
                }
            }
            .listStyle(.inset)
            if rule == nil {
                Divider()
                HStack(alignment: .firstTextBaseline) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("只从这里出去")
                        Text("出口在别的国家或地区时拦下").font(.caption).foregroundStyle(.secondary)
                    }
                    Spacer(minLength: 12)
                    EgressCountryChips(countries: countries,
                                       remove: { code in countries.removeAll { $0 == code } },
                                       add: { code in if !countries.contains(code) { countries.append(code) } })
                }
                .padding(.horizontal, 20).padding(.vertical, 12)
            }
            Divider()
            HStack(spacing: 12) {
                if let error {
                    Label(error, systemImage: "exclamationmark.triangle.fill").font(.caption).foregroundStyle(.orange)
                } else if rule == nil && countries.isEmpty && !chosen.isEmpty {
                    Text("再选一个允许的国家或地区").font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
                Button("取消") { dismiss() }.keyboardShortcut(.cancelAction)
                Button(rule == nil ? "开始保护" : "加进去") { commit() }
                    .keyboardShortcut(.defaultAction)
                    .disabled(!canSave)
            }
            .padding(16)
        }
        .frame(width: 560, height: 560)
        .disabled(saving)
        .onAppear(perform: load)
    }

    private func row(_ candidate: EgressAppCandidate) -> some View {
        Toggle(isOn: Binding(get: { chosen.contains(candidate.pattern) }, set: { on in
            if on { chosen.insert(candidate.pattern) } else { chosen.remove(candidate.pattern) }
        })) {
            HStack(spacing: 10) {
                Image(nsImage: EgressApps.icon(candidate.path)).resizable().frame(width: 24, height: 24)
                VStack(alignment: .leading, spacing: 1) {
                    Text(candidate.name).lineLimit(1)
                    Text(candidate.isBundle ? candidate.pattern + "（含其中的辅助程序）" : "命令行程序 · " + candidate.path)
                        .font(.caption).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                }
            }
        }
        .toggleStyle(.checkbox)
        .padding(.vertical, 2)
    }

    private func load() {
        candidates = preview ?? EgressApps.running()
        if let process = preselectedProcess, chosen.isEmpty,
           let match = EgressApps.matching(process: process, in: all) {
            chosen.insert(match.pattern)
        }
    }

    private func chooseFromDisk() {
        let panel = NSOpenPanel()
        panel.directoryURL = URL(fileURLWithPath: "/Applications")
        panel.allowedContentTypes = [.application]
        panel.allowsMultipleSelection = true
        panel.canChooseDirectories = false
        guard panel.runModal() == .OK else { return }
        for url in panel.urls {
            guard let candidate = EgressApps.candidate(forPath: url.path) else { continue }
            if !extra.contains(candidate) { extra.insert(candidate, at: 0) }
            chosen.insert(candidate.pattern)
        }
    }

    private func commit() {
        let apps = all.map(\.pattern).filter(chosen.contains)
        guard !apps.isEmpty else { return }
        saving = true
        error = nil
        save(apps, countries) { ok in
            saving = false
            if ok { dismiss() } else { error = "没有保存。请稍后再试。" }
        }
    }
}
