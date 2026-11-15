//! Ping through Windows' ICMP API (`IcmpSendEcho2`, `Icmp6SendEcho2`): no admin rights and no
//! raw socket. Synchronous; the round trip is timed around the call with the performance counter
//! (the API's own `RoundTripTime` is whole milliseconds). VibeTrace's audited prober, cut down
//! to echoes.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Instant;
use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::NetworkManagement::IpHelper::*;
use windows_sys::Win32::Networking::WinSock::{AF_INET6, SOCKADDR_IN6};

/// An open ICMP handle for one address family.
pub struct Pinger {
    handle: HANDLE,
    v6: bool,
    reply: Vec<u64>,
    payload: Vec<u8>,
}

// SAFETY: the handle belongs to this pinger alone and is used by one thread at a time.
unsafe impl Send for Pinger {}

impl Drop for Pinger {
    fn drop(&mut self) {
        // SAFETY: opened in `open`, closed once.
        unsafe { IcmpCloseHandle(self.handle) };
    }
}

/// An echo from the address asked (a router's "unreachable" for it is not the host answering).
pub fn echoed(replies: u32, status: u32, from: IpAddr, asked: IpAddr) -> bool {
    replies > 0 && status == IP_SUCCESS && from == asked
}

impl Pinger {
    pub fn open(v6: bool) -> Result<Pinger, String> {
        // SAFETY: no arguments; INVALID_HANDLE_VALUE on failure.
        let handle = unsafe { if v6 { Icmp6CreateFile() } else { IcmpCreateFile() } };
        if handle == INVALID_HANDLE_VALUE || handle.is_null() {
            return Err(format!("Windows' ICMP service did not open ({})", std::io::Error::last_os_error()));
        }
        // 32 bytes of payload, as Windows' own ping; room for the reply, an ICMP error and the
        // quoted header.
        let payload: Vec<u8> = (0..32u8).map(|i| b'a' + i % 23).collect();
        let reply = if v6 { size_of::<ICMPV6_ECHO_REPLY_LH>() } else { size_of::<ICMP_ECHO_REPLY>() };
        let bytes = reply + payload.len() + 8 + 64 + 64;
        Ok(Pinger { handle, v6, reply: vec![0u64; bytes.div_ceil(8)], payload })
    }

    /// One echo request: Ok(Some(round trip in µs)) when `ip` itself echoed in time, Ok(None)
    /// when not, Err when the family does not match the handle.
    pub fn ping(&mut self, ip: IpAddr, timeout_ms: u32) -> Result<Option<u32>, String> {
        if ip.is_ipv6() != self.v6 {
            return Err("the wrong address family for this handle".into());
        }
        self.reply.fill(0);
        let size = (self.reply.len() * 8) as u32;
        let buf = self.reply.as_mut_ptr().cast::<core::ffi::c_void>();
        let opt = IP_OPTION_INFORMATION { Ttl: 64, ..Default::default() };
        let (data, len) = (self.payload.as_ptr().cast(), self.payload.len() as u16);
        let t0 = Instant::now();
        let (n, from, status) = match ip {
            IpAddr::V4(d) => {
                // SAFETY: a synchronous call (no event, no APC): it writes at most `size` bytes
                // into `buf` and returns when a reply came or the timeout passed.
                let n = unsafe { IcmpSendEcho2(self.handle, std::ptr::null_mut(), None, std::ptr::null(), u32::from_ne_bytes(d.octets()), data, len, &opt, buf, size, timeout_ms) };
                // SAFETY: the buffer is zeroed, aligned and at least one ICMP_ECHO_REPLY long.
                let r = unsafe { &*(buf as *const ICMP_ECHO_REPLY) };
                (n, IpAddr::V4(Ipv4Addr::from(r.Address.to_ne_bytes())), r.Status)
            }
            IpAddr::V6(d) => {
                let mut src: SOCKADDR_IN6 = unsafe { std::mem::zeroed() };
                src.sin6_family = AF_INET6;
                let mut dst: SOCKADDR_IN6 = unsafe { std::mem::zeroed() };
                dst.sin6_family = AF_INET6;
                dst.sin6_addr.u.Byte = d.octets();
                // SAFETY: as above; the source is "any" (the system picks the address).
                let n = unsafe { Icmp6SendEcho2(self.handle, std::ptr::null_mut(), None, std::ptr::null(), &src, &dst, data, len, &opt, buf, size, timeout_ms) };
                if n > 0 {
                    // SAFETY: the reply buffer as the API filled it.
                    unsafe { Icmp6ParseReplies(buf, size) };
                }
                // SAFETY: zeroed, aligned, at least one ICMPV6_ECHO_REPLY_LH long.
                let r = unsafe { &*(buf as *const ICMPV6_ECHO_REPLY_LH) };
                let words = r.Address.sin6_addr.map(u16::from_be);
                (n, IpAddr::V6(Ipv6Addr::from(words)), r.Status)
            }
        };
        let rtt = t0.elapsed().as_micros().min(u32::MAX as u128) as u32;
        Ok(echoed(n, status, from, ip).then_some(rtt))
    }
}
