use super::InterfaceInfo;
use crate::utils::new_io_other_error;
use std::io;
use std::net::IpAddr;

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

pub(super) fn set_dns(_iface: &InterfaceInfo, _dns: &[IpAddr]) -> io::Result<()> {
    Err(new_io_other_error("Platform not supported"))
}

pub(super) fn restore_dns(_iface: &InterfaceInfo) -> io::Result<()> {
    Err(new_io_other_error("Platform not supported"))
}
