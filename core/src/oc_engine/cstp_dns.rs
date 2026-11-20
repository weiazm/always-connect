use std::net::IpAddr;

/// OpenConnect 9.21 prepares the script environment when it creates the
/// tunnel, but negotiates a new option list on each successful CSTP CONNECT.
#[derive(Default)]
pub(super) enum CstpDns {
    #[default]
    Idle,
    Request,
    Headers {
        count: u8,
        servers: Vec<String>,
    },
    Accepted(Vec<String>),
}

impl CstpDns {
    pub(super) fn accepted(&self) -> Option<&[String]> {
        match self {
            Self::Accepted(servers) => Some(servers),
            _ => None,
        }
    }

    /// Return true only after the CLI accepted the complete option set.
    pub(super) fn observe(&mut self, line: &str) -> bool {
        if line == "> CONNECT /CSCOSSLC/tunnel HTTP/1.1" {
            *self = Self::Request;
        } else if matches!(self, Self::Request)
            && line.starts_with("Got CONNECT response: HTTP/1.1 200 ")
        {
            *self = Self::Headers {
                count: 0,
                servers: Vec::new(),
            };
        } else if let Self::Headers { count, servers } = self {
            if let Some(value) = line.strip_prefix("X-CSTP-DNS: ") {
                // libopenconnect consumes at most three options in wire order.
                if *count < 3 {
                    *count += 1;
                    if let Ok(ip) = value.trim().parse::<IpAddr>() {
                        servers.push(ip.to_string());
                    }
                }
            } else if line.starts_with("CSTP connected. DPD ") {
                *self = Self::Accepted(std::mem::take(servers));
                return true;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_complete_negotiations_supply_dns_and_withdrawal_is_explicit() {
        let mut state = CstpDns::default();
        let request = "> CONNECT /CSCOSSLC/tunnel HTTP/1.1";
        let response = "Got CONNECT response: HTTP/1.1 200 OK";
        let accepted = "CSTP connected. DPD 30, Keepalive 20";
        for line in [response, "X-CSTP-DNS: 192.0.2.9", accepted] {
            state.observe(line);
        }
        assert!(state.accepted().is_none());
        for line in [
            request,
            response,
            "X-CSTP-DNS: 192.0.2.10",
            request,
            response,
            "X-CSTP-DNS: 192.0.2.11",
            "X-CSTP-DNS: invalid",
            "X-CSTP-DNS: 192.0.2.13",
            "X-CSTP-DNS: 192.0.2.14",
        ] {
            state.observe(line);
        }
        assert!(state.accepted().is_none());
        assert!(state.observe(accepted));
        assert_eq!(state.accepted().unwrap(), ["192.0.2.11", "192.0.2.13"]);
        for line in [request, response, accepted] {
            state.observe(line);
        }
        assert!(state.accepted().unwrap().is_empty());
    }
}
