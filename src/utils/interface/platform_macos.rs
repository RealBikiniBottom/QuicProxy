use super::InterfaceInfo;
use crate::utils::new_io_other_error;
use hashbrown::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::process::Command;

#[allow(dead_code)]
pub(super) struct ListContext {
    #[allow(dead_code)]
    friendly_names: HashMap<String, String>,
    #[allow(dead_code)]
    default_route: Option<(String, String)>,
}

#[allow(dead_code)]
impl ListContext {
    pub(super) fn new() -> Self {
        Self {
            friendly_names: get_macos_friendly_names(),
            default_route: get_macos_default_route(),
        }
    }
}

#[allow(dead_code)]
pub(super) fn enhance_interface(
    ctx: &ListContext,
    iface_name: &str,
    friendly_name: &mut Option<String>,
    gateway: &mut Option<String>,
) {
    if let Some(name) = ctx.friendly_names.get(iface_name) {
        *friendly_name = Some(name.clone());
    }
    if gateway.is_none() {
        if let Some((default_iface_name, default_gateway)) = ctx.default_route.as_ref() {
            if iface_name == default_iface_name {
                *gateway = Some(default_gateway.clone());
            }
        }
    }
}

pub(super) fn set_dns(iface: &InterfaceInfo, dns: &[IpAddr]) -> io::Result<()> {
    let service_name = get_macos_service_name(&iface.name)
        .ok_or_else(|| new_io_other_error(format!("Service name for {} not found", iface.name)))?;

    let mut args = vec!["-setdnsservers", &service_name];
    let dns_strings: Vec<String> = dns.iter().map(|ip| ip.to_string()).collect();
    for dns in &dns_strings {
        args.push(dns);
    }

    let output = Command::new("networksetup").args(&args).output()?;

    if !output.status.success() {
        return Err(new_io_other_error(
            String::from_utf8_lossy(&output.stderr).to_string(),
        ));
    }
    Ok(())
}

pub(super) fn restore_dns(iface: &InterfaceInfo) -> io::Result<()> {
    let service_name = get_macos_service_name(&iface.name)
        .ok_or_else(|| new_io_other_error(format!("Service name for {} not found", iface.name)))?;

    let output = Command::new("networksetup")
        .args(&["-setdnsservers", &service_name, "Empty"])
        .output()?;

    if !output.status.success() {
        return Err(new_io_other_error(
            String::from_utf8_lossy(&output.stderr).to_string(),
        ));
    }
    Ok(())
}

fn get_macos_service_name(device: &str) -> Option<String> {
    let map = get_macos_friendly_names();
    map.get(device).cloned()
}

fn get_macos_friendly_names() -> HashMap<String, String> {
    let mut map = HashMap::new();
    if let Ok(output) = Command::new("networksetup")
        .arg("-listallhardwareports")
        .output()
    {
        let output_str = String::from_utf8_lossy(&output.stdout);
        let mut current_port = None;

        for line in output_str.lines() {
            if line.starts_with("Hardware Port: ") {
                current_port = Some(line["Hardware Port: ".len()..].trim().to_string());
            } else if line.starts_with("Device: ") {
                if let Some(port) = current_port.take() {
                    let device = line["Device: ".len()..].trim().to_string();
                    map.insert(device, port);
                }
            }
        }
    }
    map
}

#[allow(dead_code)]
fn get_macos_default_route() -> Option<(String, String)> {
    let output = Command::new("route")
        .arg("-n")
        .arg("get")
        .arg("default")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut iface = None;
    let mut gateway = None;

    for line in stdout.lines() {
        let line = line.trim();
        if let Some(v) = line.strip_prefix("interface:") {
            let value = v.trim();
            if !value.is_empty() {
                iface = Some(value.to_string());
            }
        }
        if let Some(v) = line.strip_prefix("gateway:") {
            let value = v.trim();
            if value.parse::<Ipv4Addr>().is_ok() {
                gateway = Some(value.to_string());
            }
        }
    }

    match (iface, gateway) {
        (Some(i), Some(g)) => Some((i, g)),
        _ => None,
    }
}
