use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use url::Url;

use crate::error::SandboxError;

pub fn validate_url_for_sandbox(raw: &str) -> Result<Url, SandboxError> {
    let url = Url::parse(raw).map_err(|e| SandboxError::Validation(format!("invalid URL: {e}")))?;
    match url.scheme() {
        "http" | "https" => {}
        _ => {
            return Err(SandboxError::Validation(
                "only http/https URLs are allowed".to_string(),
            ))
        }
    }

    let host = url
        .host_str()
        .ok_or_else(|| SandboxError::Validation("URL host is missing".to_string()))?
        .to_ascii_lowercase();

    if host == "localhost" || host.ends_with(".local") {
        return Err(SandboxError::Validation(
            "local hosts are blocked".to_string(),
        ));
    }

    if let Ok(ip) = host.parse::<IpAddr>() {
        if is_blocked_ip(ip) {
            return Err(SandboxError::Validation(
                "URL points to blocked internal address".to_string(),
            ));
        }
    }

    Ok(url)
}

fn is_blocked_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_blocked_ipv4(v4),
        IpAddr::V6(v6) => is_blocked_ipv6(v6),
    }
}

fn is_blocked_ipv4(ip: Ipv4Addr) -> bool {
    ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.octets() == [169, 254, 169, 254]
}

fn is_blocked_ipv6(ip: Ipv6Addr) -> bool {
    ip.is_loopback() || ip.is_unique_local() || ip.is_unicast_link_local()
}

#[cfg(test)]
mod tests {
    use super::validate_url_for_sandbox;

    #[test]
    fn blocks_private_and_metadata_targets() {
        assert!(validate_url_for_sandbox("http://127.0.0.1").is_err());
        assert!(validate_url_for_sandbox("http://169.254.169.254").is_err());
        assert!(validate_url_for_sandbox("http://10.10.10.10").is_err());
    }

    #[test]
    fn accepts_public_https() {
        assert!(validate_url_for_sandbox("https://example.com").is_ok());
    }
}
