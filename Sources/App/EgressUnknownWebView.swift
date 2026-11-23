import SwiftUI

struct EgressUnknownWebView: View {
    @ObservedObject private var manager = HelperClient.shared
    @Environment(\.dismiss) private var dismiss
    let config: EgressProtection
    let status: EgressProtection.Status?
    let refresh: () -> Void

    @State private var pending: Decision?
    @State private var busy = false
    @State private var message: String?

    private enum Decision {
        case turnOff
        case exception(EgressUnknownWebChange)

        var title: String {
            switch self {
            case .turnOff: return "关闭无名网页连接拦截？"
            case .exception(let change): return change.allow ? "确认放行这个地址和端口？" : "撤回此例外？"
            }
        }

        var caption: String {
            switch self {
            case .turnOff: return EgressUnknownWebText.turnOff
            case .exception(let change):
                return change.allow ? EgressUnknownWebText.allow(change.endpoint) : EgressUnknownWebText.revoke(change.endpoint)
            }
        }

        var button: String {
            switch self {
            case .turnOff: return "关闭拦截"
            case .exception(let change): return change.allow ? "放行" : "撤回例外"
            }
        }
    }

    var body: some View {
        Form {
            if config.isActive {
                Section("认不出网站的连接") {
                    Toggle("拦截认不出网站的公网网页连接", isOn: Binding(
                        get: { config.blocksUnidentifiedWeb },
                        set: { on in
                            if on { saveBlocking(true) }
                            else { pending = .turnOff }
                        }))
                    Text("按浏览器查过的网址认，不保证认出所有程序。仍认不出网站时，会拦截发往公网网页端口的连接。")
                        .font(.caption).foregroundStyle(.secondary)
                }
                Section("本次连接的拦截记录") {
                    if !manager.showsConnected {
                        Text("连接 VPN 后可查看这一会话的记录。").foregroundStyle(.secondary)
                    } else if let status, status.running, let records = status.unknownWeb {
                        if records.isEmpty {
                            Text("本次连接还没有这类拦截记录。").foregroundStyle(.secondary)
                        }
                        ForEach(records, id: \.endpoint) { record in
                            row(record, status: status)
                        }
                    } else {
                        Text("尚未取得后台记录。").foregroundStyle(.secondary)
                    }
                    if let message { Text(message).font(.caption).foregroundStyle(.secondary) }
                    Button("刷新", action: refresh)
                }
            } else {
                Text("请先启用一条出口保护规则。").foregroundStyle(.secondary)
            }
            Button("完成") { dismiss() }.keyboardShortcut(.defaultAction)
        }
        .formStyle(.grouped).frame(width: 570, height: 470)
        .disabled(busy)
        .onAppear(perform: refresh)
        .confirmationDialog(pending?.title ?? "确认修改", isPresented: Binding(
            get: { pending != nil }, set: { if !$0 { pending = nil } }
        ), titleVisibility: .visible, presenting: pending) { decision in
            Button(decision.button) { apply(decision) }
            Button("取消", role: .cancel) {}
        } message: { decision in Text(decision.caption) }
    }

    private func row(_ record: EgressProtection.UnknownWebRecord, status: EgressProtection.Status) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(record.endpoint.label).font(.body.monospaced())
            Text("未知应用 · 已拦截 \(record.count) 次")
                .font(.caption).foregroundStyle(.secondary)
            if let explanation = record.identityExplanation {
                Text(explanation).font(.caption).foregroundStyle(.secondary)
            }
            if record.allowed {
                Text("本次 VPN 会话已添加此地址和端口的例外").font(.caption).foregroundStyle(.secondary)
            }
            if let change = record.change, status.permits(change, config: config) {
                Button(change.allow ? "放行这个地址和端口" : "撤回例外") { pending = .exception(change) }
                    .buttonStyle(.borderless)
            }
        }
    }

    private func apply(_ decision: Decision) {
        pending = nil
        switch decision {
        case .turnOff: saveBlocking(false)
        case .exception(let change):
            busy = true
            manager.changeUnknownWebException(change) { ok in
                busy = false
                message = ok
                    ? (change.allow ? "本次 VPN 会话已添加 \(change.endpoint.label) 的例外。" : "已撤回 \(change.endpoint.label) 的例外。")
                    : EgressUnknownWebText.rejected
                refresh()
            }
        }
    }

    private func saveBlocking(_ value: Bool) {
        guard config.isActive, config.blocksUnidentifiedWeb != value else { return }
        var updated = config
        updated.blockUnidentifiedWeb = value
        busy = true
        manager.saveEgress(updated, replacing: config) { ok in
            busy = false
            message = ok ? nil : EgressUnknownWebText.rejected
            refresh()
        }
    }
}
