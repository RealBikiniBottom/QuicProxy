use super::InterfaceInfo;
use crate::utils::new_io_other_error;
use std::io;
use std::net::IpAddr;
use std::process::Command;

#[allow(dead_code)]
pub(super) struct ListContext;

#[allow(dead_code)]
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
    let dns_strings: Vec<String> = dns.iter().map(|ip| ip.to_string()).collect();
    let interface_name = &iface.name;

    if Command::new("resolvectl").arg("--version").output().is_ok() {
        let mut args = vec!["dns", interface_name];
        for dns in &dns_strings {
            args.push(dns);
        }
        let output = Command::new("resolvectl").args(&args).output()?;
        if !output.status.success() {
            return Err(new_io_other_error(
                String::from_utf8_lossy(&output.stderr).to_string(),
            ));
        }
        return Ok(());
    }

    if Command::new("nmcli").arg("--version").output().is_ok() {
        let dns_joined = dns_strings.join(" ");
        let output = Command::new("nmcli")
            .args(&["dev", "modify", interface_name, "ipv4.dns", &dns_joined])
            .output()?;
        if !output.status.success() {
            return Err(new_io_other_error(
                String::from_utf8_lossy(&output.stderr).to_string(),
            ));
        }
        return Ok(());
    }

    Err(new_io_other_error(
        "No supported DNS management tool found (resolvectl, nmcli)",
    ))
}

pub(super) fn restore_dns(iface: &InterfaceInfo) -> io::Result<()> {
    let interface_name = &iface.name;
    if Command::new("resolvectl").arg("--version").output().is_ok() {
        let output = Command::new("resolvectl")
            .args(&["revert", interface_name])
            .output()?;
        if !output.status.success() {
            return Err(new_io_other_error(
                String::from_utf8_lossy(&output.stderr).to_string(),
            ));
        }
        return Ok(());
    }

    if Command::new("nmcli").arg("--version").output().is_ok() {
        let output = Command::new("nmcli")
            .args(&["dev", "modify", interface_name, "ipv4.dns", ""])
            .output()?;
        if !output.status.success() {
            return Err(new_io_other_error(
                String::from_utf8_lossy(&output.stderr).to_string(),
            ));
        }
        return Ok(());
    }

    Err(new_io_other_error(
        "No supported DNS management tool found (resolvectl, nmcli)",
    ))
}
