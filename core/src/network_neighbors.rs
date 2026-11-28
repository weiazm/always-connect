//! Diagnostic names only. Do not retain or expose process paths or arguments.
use crate::split_proxy::hysteria::BUNDLED_BIN;
use std::collections::BTreeSet;
use std::path::Path;

pub(crate) fn external_daemons(processes: &str) -> BTreeSet<&str> {
    processes.lines().map(str::trim).filter(|path| *path != BUNDLED_BIN)
        .filter_map(|path| Path::new(path).file_name()?.to_str())
        .filter(|name| matches!(*name, "clash" | "mihomo" | "sing-box" | "xray" | "v2ray" | "hysteria" | "tun2socks"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn managed_client_is_not_a_foreign_proxy() {
        assert!(external_daemons(BUNDLED_BIN).is_empty());
        let paths = format!("{BUNDLED_BIN}\n/opt/tools/hysteria\n/opt/tools/sing-box\n/opt/tools/hysteria\n/bin/unrelated");
        assert_eq!(external_daemons(&paths), BTreeSet::from(["hysteria", "sing-box"]));
    }
}
