//! Adapters, subnets and the neighbour cache (VibeScan's `net.rs`, cut down): what Find searches
//! and which subnet an address is on. The arithmetic is plain Rust; the adapters and the cache
//! come from iphlpapi, read-only, no admin rights.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// A 48-bit hardware address.
pub type Mac = [u8; 6];

/// "00:00:5E:00:53:01".
pub fn mac_text(m: &Mac) -> String {
    m.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(":")
}

/// "00:00:5e:00:53:01", "00-00-5E-00-53-01" or "0000.5e00.5301".
pub fn parse_mac(s: &str) -> Option<Mac> {
    let hex: String = s.chars().filter(|c| !matches!(c, ':' | '-' | '.' | ' ')).collect();
    if hex.len() != 12 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let mut m = [0u8; 6];
    for (i, b) in m.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(m)
}

/// A MAC that belongs to a card (unicast, not all zeros).
pub fn is_card_mac(m: &Mac) -> bool {
    m[0] & 0x01 == 0 && m.iter().any(|&b| b != 0)
}

pub fn winsock() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        use windows_sys::Win32::Networking::WinSock::{WSADATA, WSAStartup};
        let mut d: WSADATA = unsafe { std::mem::zeroed() };
        // SAFETY: version 2.2 into a zeroed WSADATA; never cleaned up (process lifetime).
        unsafe { WSAStartup(0x0202, &mut d) };
    });
}

/// An IPv4 network: a base address with its host bits cleared and a prefix length.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Net4 {
    pub base: u32,
    pub prefix: u8,
}

fn mask(prefix: u8) -> u32 {
    if prefix == 0 { 0 } else { u32::MAX << (32 - prefix.min(32) as u32) }
}

impl Net4 {
    pub fn new(ip: Ipv4Addr, prefix: u8) -> Net4 {
        let prefix = prefix.min(32);
        Net4 { base: u32::from(ip) & mask(prefix), prefix }
    }

    pub fn contains(&self, ip: u32) -> bool {
        ip & mask(self.prefix) == self.base
    }

    pub fn broadcast(&self) -> u32 {
        self.base | !mask(self.prefix)
    }

    /// The addresses hosts may have (no network or broadcast address below /31).
    pub fn hosts(&self) -> (u32, u32) {
        match self.prefix {
            32 => (self.base, self.base),
            31 => (self.base, self.base + 1),
            _ => (self.base + 1, self.broadcast() - 1),
        }
    }
}

impl std::fmt::Display for Net4 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", Ipv4Addr::from(self.base), self.prefix)
    }
}

/// One IPv4 address of an adapter that is up.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Adapter {
    pub index: u32,
    pub name: String,
    pub addr: Ipv4Addr,
    pub prefix: u8,
    pub metric: u32,
}

impl Adapter {
    pub fn net(&self) -> Net4 {
        Net4::new(self.addr, self.prefix)
    }

    /// Link-local (169.254/16: no DHCP answered): Find asks mDNS only there.
    pub fn link_local(&self) -> bool {
        self.addr.is_link_local()
    }
}

/// What Find sweeps on an adapter: its subnet when it is a /24 or smaller, else the /24 around
/// this PC's address (and the words saying so). None: no sweep (a /32, link-local, loopback).
pub fn sweep_net(a: &Adapter) -> Option<(Net4, String)> {
    if a.prefix >= 31 || a.link_local() || a.addr.is_loopback() || a.addr.is_unspecified() {
        return None;
    }
    if a.prefix >= 24 {
        let n = a.net();
        Some((n, format!("searched {n}")))
    } else {
        let n = Net4::new(a.addr, 24);
        Some((n, format!("searched {n} of a /{}", a.prefix)))
    }
}

/// The adapter whose subnet holds `ip` (the longest prefix wins).
pub fn on_link(adapters: &[Adapter], ip: Ipv4Addr) -> Option<&Adapter> {
    let v = u32::from(ip);
    adapters.iter().filter(|a| a.prefix < 32 && a.net().contains(v)).max_by(|a, b| a.prefix.cmp(&b.prefix).then(b.metric.cmp(&a.metric)))
}

/// Text from the system as it may be shown.
fn clean(s: &str) -> String {
    crate::text::clean(s)
}

/// Windows' adapters (GetAdaptersAddresses): every IPv4 unicast address of every adapter that is
/// up, loopback left out.
pub fn system_adapters() -> Result<Vec<Adapter>, String> {
    use windows_sys::Win32::NetworkManagement::IpHelper::*;
    use windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp;
    use windows_sys::Win32::Networking::WinSock::AF_INET;
    let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    let mut size: u32 = 32 * 1024;
    let mut buf: Vec<u64>;
    let mut tries = 0;
    loop {
        buf = vec![0u64; (size as usize).div_ceil(8)];
        // SAFETY: an 8-byte aligned buffer of `size` bytes; the API fills a linked list inside it.
        let r = unsafe { GetAdaptersAddresses(AF_INET as u32, flags, std::ptr::null(), buf.as_mut_ptr().cast(), &mut size) };
        match r {
            0 => break,
            111 if tries < 4 => tries += 1,
            232 => return Ok(Vec::new()),
            e => return Err(format!("Windows did not list the network adapters (error {e}).")),
        }
    }
    let mut out = Vec::new();
    let mut p = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
    while !p.is_null() {
        // SAFETY: a node of the list GetAdaptersAddresses wrote into `buf`, which outlives this loop.
        let a = unsafe { &*p };
        p = a.Next;
        if a.OperStatus != IfOperStatusUp || a.IfType == IF_TYPE_SOFTWARE_LOOPBACK {
            continue;
        }
        let index = unsafe { a.Anonymous1.Anonymous.IfIndex };
        let name = clean(&unsafe { wide_str(a.FriendlyName) });
        let mut u = a.FirstUnicastAddress;
        while !u.is_null() {
            // SAFETY: as above.
            let ua = unsafe { &*u };
            if let Some(IpAddr::V4(v4)) = unsafe { sockaddr_ip(ua.Address.lpSockaddr) } {
                out.push(Adapter { index, name: name.clone(), addr: v4, prefix: ua.OnLinkPrefixLength.min(32), metric: a.Ipv4Metric });
            }
            u = ua.Next;
        }
    }
    out.sort_by(|a, b| (a.metric, a.index, u32::from(a.addr)).cmp(&(b.metric, b.index, u32::from(b.addr))));
    Ok(out)
}

/// The neighbour cache (GetIpNetTable2): (address, MAC) for entries with a card's MAC.
pub fn system_neighbours() -> Vec<(IpAddr, Mac)> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{FreeMibTable, GetIpNetTable2, MIB_IPNET_ROW2, MIB_IPNET_TABLE2};
    use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC, NlnsIncomplete, NlnsUnreachable};
    let mut table: *mut MIB_IPNET_TABLE2 = std::ptr::null_mut();
    // SAFETY: an out pointer; the table is ours to free with FreeMibTable.
    if unsafe { GetIpNetTable2(AF_UNSPEC, &mut table) } != 0 || table.is_null() {
        return Vec::new();
    }
    let mut out = Vec::new();
    // SAFETY: the table the API returned: NumEntries rows follow its header.
    unsafe {
        let n = (*table).NumEntries as usize;
        let rows = std::slice::from_raw_parts((*table).Table.as_ptr() as *const MIB_IPNET_ROW2, n);
        for r in rows {
            if r.PhysicalAddressLength != 6 || r.State == NlnsUnreachable || r.State == NlnsIncomplete {
                continue;
            }
            let mut mac = [0u8; 6];
            mac.copy_from_slice(&r.PhysicalAddress[..6]);
            if !is_card_mac(&mac) {
                continue;
            }
            let ip = match r.Address.si_family {
                AF_INET => IpAddr::V4(Ipv4Addr::from(r.Address.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes())),
                AF_INET6 => IpAddr::V6(Ipv6Addr::from(r.Address.Ipv6.sin6_addr.u.Byte)),
                _ => continue,
            };
            out.push((ip, mac));
        }
        FreeMibTable(table as *const _);
    }
    out
}

/// A NUL-terminated wide string from the system.
unsafe fn wide_str(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    // SAFETY: the caller hands a NUL-terminated string.
    unsafe {
        let len = (0..).take_while(|&i| *p.add(i) != 0).count();
        String::from_utf16_lossy(std::slice::from_raw_parts(p, len))
    }
}

/// The address in a SOCKADDR (IPv4 or IPv6).
unsafe fn sockaddr_ip(sa: *const windows_sys::Win32::Networking::WinSock::SOCKADDR) -> Option<IpAddr> {
    use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6, SOCKADDR_IN, SOCKADDR_IN6};
    if sa.is_null() {
        return None;
    }
    // SAFETY: a sockaddr of the family it says.
    unsafe {
        match (*sa).sa_family {
            AF_INET => Some(IpAddr::V4(Ipv4Addr::from((*(sa as *const SOCKADDR_IN)).sin_addr.S_un.S_addr.to_ne_bytes()))),
            AF_INET6 => Some(IpAddr::V6(Ipv6Addr::from((*(sa as *const SOCKADDR_IN6)).sin6_addr.u.Byte))),
            _ => None,
        }
    }
}
