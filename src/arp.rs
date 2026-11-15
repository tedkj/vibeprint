//! ARP through Windows' own neighbour resolution (`SendARP`, iphlpapi): no admin rights, no raw
//! socket. The call blocks until the address answers or the OS gives up (about three seconds:
//! its own retries), so the scan runs many at once on their own threads. Used only for
//! addresses on a local segment: an address behind a router never answers ARP.

use crate::net::Mac;
use std::net::Ipv4Addr;

/// What one ARP request found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Arp {
    Answered(Mac),
    /// Nobody has the address (or it does not answer: on a segment, that means it is not there).
    Silent,
}

/// Ask the segment who has `ip`, from this computer's address `src` on it (which picks the
/// adapter). Errors other than "no answer" are said in words.
pub fn send_arp(ip: Ipv4Addr, src: Ipv4Addr) -> Result<Arp, String> {
    use windows_sys::Win32::NetworkManagement::IpHelper::SendARP;
    let mut mac = [0u64; 1];
    let mut len: u32 = 6;
    // SAFETY: an 8-byte buffer and its length; the call writes at most `len` bytes.
    let r = unsafe { SendARP(u32::from_ne_bytes(ip.octets()), u32::from_ne_bytes(src.octets()), mac.as_mut_ptr().cast(), &mut len) };
    outcome(r, &mac[0].to_ne_bytes(), len)
}

/// The call's result as an `Arp`: NO_ERROR with six bytes is an answer; ERROR_BAD_NET_NAME (67,
/// the timeout) is silence; ERROR_GEN_FAILURE (31) also comes back for an address that does not
/// answer on some adapters. ERROR_NOT_FOUND (1168) is not silence: measured, it comes back at
/// once when `src` is not an address of this PC (the network changed under the scan), so it says
/// nothing about the address asked for.
pub fn outcome(code: u32, buf: &[u8], len: u32) -> Result<Arp, String> {
    match code {
        0 if len == 6 => {
            let mut m = [0u8; 6];
            m.copy_from_slice(&buf[..6]);
            if m == [0; 6] { Ok(Arp::Silent) } else { Ok(Arp::Answered(m)) }
        }
        0 => Ok(Arp::Silent),
        67 | 31 => Ok(Arp::Silent),
        1168 => Err("This PC does not have the address it scans from any more (the network changed): scan again".into()),
        87 => Err("ARP was refused for that address (invalid parameter)".into()),
        50 => Err("This adapter does not do ARP".into()),
        e => Err(format!("ARP failed (error {e})")),
    }
}
