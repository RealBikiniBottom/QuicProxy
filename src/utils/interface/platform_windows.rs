use super::InterfaceInfo;
use crate::utils::new_io_other_error;
use std::io;
use std::net::IpAddr;
use std::process::Command;

#[allow(dead_code)]
pub(super) struct ListContext;

impl ListContext {
    pub(super) fn new() -> Self {
        Self
    }
}

#[allow(dead_code)]
pub(super) fn enhance_interface(
    _ctx: &ListContext,
    _iface_name: &str,
    _friendly_name: &mut Option<String>,
    _gateway: &mut Option<String>,
) {
}

pub(super) fn set_dns(iface: &InterfaceInfo, dns: &[IpAddr]) -> io::Result<()> {
    let interface_name = iface.friendly_name.as_ref().unwrap_or(&iface.name);

    // IPv4
    let v4_dns: Vec<IpAddr> = dns.iter().filter(|ip| ip.is_ipv4()).cloned().collect();
    if !v4_dns.is_empty() {
        let primary = v4_dns[0].to_string();
        let output = Command::new("netsh")
            .args(&[
                "interface",
                "ip",
                "set",
                "dns",
                interface_name,
                "static",
                &primary,
            ])
            .output()?;
        if !output.status.success() {
            return Err(new_io_other_error(
                String::from_utf8_lossy(&output.stderr).to_string(),
            ));
        }

        for (i, ip) in v4_dns.iter().enumerate().skip(1) {
            let _ = Command::new("netsh")
                .args(&[
                    "interface",
                    "ip",
                    "add",
                    "dns",
                    interface_name,
                    &ip.to_string(),
                    &format!("index={}", i + 2),
                ])
                .output();
        }
    }

    // IPv6
    let v6_dns: Vec<IpAddr> = dns.iter().filter(|ip| ip.is_ipv6()).cloned().collect();
    if !v6_dns.is_empty() {
        let primary = v6_dns[0].to_string();
        let _ = Command::new("netsh")
            .args(&[
                "interface",
                "ipv6",
                "set",
                "dns",
                interface_name,
                "static",
                &primary,
            ])
            .output();

        for (i, ip) in v6_dns.iter().enumerate().skip(1) {
            let _ = Command::new("netsh")
                .args(&[
                    "interface",
                    "ipv6",
                    "add",
                    "dns",
                    interface_name,
                    &ip.to_string(),
                    &format!("index={}", i + 2),
                ])
                .output();
        }
    } else {
        // If no IPv6 DNS is provided, we should probably clear existing ones
        // to prevent IPv6 DNS from bypassing our IPv4 DNS hijacking.
        // On Windows, setting it to a dummy static address or loopback can work.
        // Here we try to set it to loopback to force fallback to IPv4.
        let _ = Command::new("netsh")
            .args(&[
                "interface",
                "ipv6",
                "set",
                "dns",
                interface_name,
                "static",
                "::1",
            ])
            .output();
    }
    Ok(())
}

pub(super) fn set_metric(iface: &InterfaceInfo, metric: u32) -> io::Result<()> {
    let interface_name = iface.friendly_name.as_ref().unwrap_or(&iface.name);

    // Set IPv4 metric
    let output = Command::new("netsh")
        .args(&[
            "interface",
            "ip",
            "set",
            "interface",
            interface_name,
            &format!("metric={}", metric),
        ])
        .output()?;
    if !output.status.success() {
        return Err(new_io_other_error(
            String::from_utf8_lossy(&output.stderr).to_string(),
        ));
    }

    // Set IPv6 metric
    let _ = Command::new("netsh")
        .args(&[
            "interface",
            "ipv6",
            "set",
            "interface",
            interface_name,
            &format!("metric={}", metric),
        ])
        .output();

    Ok(())
}

pub(super) fn get_dns(iface: &InterfaceInfo) -> io::Result<Vec<IpAddr>> {
    let interface_name = iface.friendly_name.as_ref().unwrap_or(&iface.name);
    let ps_cmd = format!(
        "(Get-DnsClientServerAddress -InterfaceAlias '{}').ServerAddresses | ConvertTo-Json -Compress",
        interface_name.replace('\'', "''")
    );
    let ps_output = Command::new("powershell")
        .args(&["-NoProfile", "-Command", &ps_cmd])
        .output();
    if let Ok(output) = ps_output {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !stdout.is_empty() {
                let mut dns_servers = Vec::new();
                if let Ok(list) = serde_json::from_str::<Vec<String>>(&stdout) {
                    for s in list {
                        if let Ok(ip) = s.parse::<IpAddr>() {
                            dns_servers.push(ip);
                        }
                    }
                    if !dns_servers.is_empty() {
                        return Ok(dns_servers);
                    }
                } else if let Ok(single) = serde_json::from_str::<String>(&stdout) {
                    if let Ok(ip) = single.parse::<IpAddr>() {
                        return Ok(vec![ip]);
                    }
                }
            }
        }
    }
    let output = Command::new("netsh")
        .args(&["interface", "ip", "show", "config", interface_name])
        .output()?;
    if !output.status.success() {
        return Err(new_io_other_error(
            String::from_utf8_lossy(&output.stderr).to_string(),
        ));
    }
    let output_str = String::from_utf8_lossy(&output.stdout);
    let mut dns_servers = Vec::new();
    let mut parsing_dns = false;
    for line in output_str.lines() {
        let line_trim = line.trim();
        let lower = line_trim.to_ascii_lowercase();
        if lower.contains("dns") {
            parsing_dns = true;
            if let Some(idx) = line_trim.find(':') {
                let val = line_trim[idx + 1..].trim();
                if !val.is_empty() && val != "None" && val != "(null)" {
                    for part in val.split_whitespace() {
                        if let Ok(ip) = part.parse::<IpAddr>() {
                            dns_servers.push(ip);
                        }
                    }
                }
            }
            continue;
        }
        if parsing_dns {
            if line_trim.is_empty() || line_trim.contains(':') {
                parsing_dns = false;
                continue;
            }
            if let Ok(ip) = line_trim.parse::<IpAddr>() {
                dns_servers.push(ip);
            }
        }
    }
    Ok(dns_servers)
}

pub(super) fn restore_dns(iface: &InterfaceInfo) -> io::Result<()> {
    let interface_name = iface.friendly_name.as_ref().unwrap_or(&iface.name);

    // Restore IPv4
    let _ = Command::new("netsh")
        .args(&["interface", "ip", "set", "dns", interface_name, "dhcp"])
        .output();

    // Restore IPv6
    let _ = Command::new("netsh")
        .args(&["interface", "ipv6", "set", "dns", interface_name, "dhcp"])
        .output();

    Ok(())
}
