use crate::Result;
use std::fs::File;
use std::io::Read;

#[cfg(unix)]
use std::os::fd::FromRawFd;

#[cfg(unix)]
const AF_NETLINK: i32 = 16;
#[cfg(unix)]
const SOCK_RAW: i32 = 3;
#[cfg(unix)]
const NETLINK_ROUTE: i32 = 0;
#[cfg(unix)]
const RTMGRP_LINK: u32 = 1;
#[cfg(unix)]
const RTMGRP_IPV4_IFADDR: u32 = 0x10;
#[cfg(unix)]
const RTMGRP_IPV4_ROUTE: u32 = 0x40;
#[cfg(unix)]
const RTMGRP_IPV6_IFADDR: u32 = 0x100;
#[cfg(unix)]
const RTMGRP_IPV6_ROUTE: u32 = 0x400;

#[cfg(unix)]
#[repr(C)]
struct SockAddrNl {
    nl_family: u16,
    nl_pad: u16,
    nl_pid: u32,
    nl_groups: u32,
}

#[cfg(unix)]
unsafe extern "C" {
    fn bind(fd: i32, addr: *const SockAddrNl, len: u32) -> i32;
    fn close(fd: i32) -> i32;
    fn socket(domain: i32, socket_type: i32, protocol: i32) -> i32;
}

#[cfg(unix)]
pub(super) fn open_route_event_socket() -> Result<File> {
    let fd = unsafe { socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE) };
    if fd < 0 {
        return Err(format!(
            "open route netlink socket failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    let address = SockAddrNl {
        nl_family: AF_NETLINK as u16,
        nl_pad: 0,
        nl_pid: 0,
        nl_groups: RTMGRP_LINK
            | RTMGRP_IPV4_IFADDR
            | RTMGRP_IPV4_ROUTE
            | RTMGRP_IPV6_IFADDR
            | RTMGRP_IPV6_ROUTE,
    };
    let bound = unsafe { bind(fd, &address, std::mem::size_of::<SockAddrNl>() as u32) };
    if bound < 0 {
        let err = std::io::Error::last_os_error();
        unsafe {
            close(fd);
        }
        return Err(format!("bind route netlink socket failed: {err}"));
    }

    Ok(unsafe { File::from_raw_fd(fd) })
}

#[cfg(not(unix))]
pub(super) fn open_route_event_socket() -> Result<File> {
    Err("route netlink monitoring requires a Unix-like target".to_string())
}

pub(super) fn wait_for_route_event(socket: &mut File, buffer: &mut [u8]) -> Result<()> {
    loop {
        let read = socket
            .read(buffer)
            .map_err(|err| format!("read route netlink event failed: {err}"))?;
        if read > 0 {
            return Ok(());
        }
    }
}
