import Foundation

/// Build the trusted bootstrap itself in the running App. The root shell
/// copies first and verifies that private snapshot before executing code.
enum PrivilegedBundle {
    static func shellQuoted(_ text: String) -> String { RootBootstrap.shellQuoted(text) }

    static func appleScriptString(_ text: String) -> String {
        "\"" + text.replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"") + "\""
    }

    static func source(resource: String, arguments: [String], helper: Bool = false, prompt: String) -> String? {
        guard ["dev-helper.sh", "reset-network.sh", "uninstall.sh"].contains(resource),
              let requirement = AppIdentity.leafRequirement else { return nil }
        let command = bootstrap(bundle: Bundle.main.bundlePath, requirement: requirement,
                                resource: resource, arguments: arguments, helper: helper)
        return "do shell script \(appleScriptString("/bin/bash -c " + shellQuoted(command))) "
            + "with prompt \(appleScriptString(prompt)) with administrator privileges"
    }

    static let unsignedMessage = "此开发构建没有可验证的签名证书，不能通过密码框运行管理脚本。请使用已有开发证书重新构建；手动终端安装或恢复仍可用。"

    static func bootstrap(bundle: String, requirement: String, resource: String,
                          arguments: [String], helper: Bool) -> String {
        RootBootstrap.script(bundle: bundle, requirement: requirement, resource: resource,
                             arguments: arguments, helper: helper)
    }

    static func run(resource: String, arguments: [String], helper: Bool = false, prompt: String,
                    completion: @escaping (AdminScript.Result) -> Void) {
        guard let source = source(resource: resource, arguments: arguments, helper: helper, prompt: prompt) else {
            completion(AdminScript.Result(output: "", errorNumber: 1, errorMessage: unsignedMessage))
            return
        }
        AdminScript.run(source, completion: completion)
    }
}
