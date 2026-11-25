import Foundation

/// The root shell that installs from an App bundle (DESIGN.md §36.3,
/// §69.11): copy the bundle into a root-private snapshot, refuse links
/// out of it, verify the copy against the certificate pin, and only then
/// run the snapshot's own script. Shared by the App's administrator
/// password path (PrivilegedBundle) and the background service's own
/// update (ServiceUpdate), so both run exactly the same checks.
enum RootBootstrap {
    static func shellQuoted(_ text: String) -> String {
        "'" + text.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    /// Where the installed App version is kept (root-private), for the
    /// service's own update to refuse older versions.
    static let installedVersionPath = "/Library/Application Support/AlwaysConnect/installed-version"

    /// All interpolated values are quoted. `minimumVersion`: refuse a
    /// snapshot whose CFBundleShortVersionString is lower (dotted numbers).
    static func script(bundle: String, requirement: String, resource: String,
                       arguments: [String], helper: Bool, minimumVersion: String? = nil) -> String {
        let args = arguments.map(shellQuoted).joined(separator: " ")
        let floor = minimumVersion.map { "\n" + Self.versionCheck(minimum: $0) } ?? ""
        return """
        set -euo pipefail
        export PATH=/usr/bin:/bin:/usr/sbin:/sbin
        umask 077
        stage=$(/usr/bin/mktemp -d /private/tmp/alwaysconnect-root.XXXXXXXX)
        trap '/bin/rm -rf "$stage"' EXIT
        /bin/chmod 700 "$stage"
        app="$stage/AlwaysConnect.app"
        /usr/bin/ditto \(shellQuoted(bundle)) "$app"
        # Refuse links escaping the snapshot, including mutable external scripts.
        while IFS= read -r -d '' link; do
            target=$(/usr/bin/readlink "$link")
            case "$target" in
                /*|..|../*|*/../*|*/..) echo 'App 包含不安全的外部链接，已停止' >&2; exit 1 ;;
            esac
        done < <(/usr/bin/find "$app" -type l -print0)
        /usr/sbin/chown -R root:wheel "$app"
        /bin/chmod -R go-w "$app"
        /usr/bin/codesign --verify --strict --deep -R=\(shellQuoted(requirement)) "$app" 2>/dev/null || {
            echo 'App 副本签名校验失败或签名证书不符，已停止。请重新下载可信版本。' >&2
            exit 1
        }\(floor)
        /bin/bash "$app/Contents/Resources/\(resource)" \(args)\(helper ? " \"$app/Contents/Library/LaunchDaemons/AlwaysConnectHelper\"" : "")
        """
    }

    /// Shell: stop unless "$app"'s version is at least `minimum`.
    static func versionCheck(minimum: String) -> String {
        """

        new=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$app/Contents/Info.plist" 2>/dev/null || true)
        older() {
            local IFS=.
            local -a a=($1) b=($2)
            local i x y
            for ((i = 0; i < 4; i++)); do
                x=${a[i]:-0}; y=${b[i]:-0}
                [[ $x =~ ^[0-9]+$ && $y =~ ^[0-9]+$ ]] || return 0
                ((10#$x < 10#$y)) && return 0
                ((10#$x > 10#$y)) && return 1
            done
            return 1
        }
        if [ -z "$new" ] || older "$new" \(shellQuoted(minimum)); then
            echo '不能换成比已装版本更旧的版本，已停止' >&2
            exit 1
        fi
        """
    }
}
