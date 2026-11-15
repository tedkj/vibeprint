//! What a printer's port is and where it points. The kind comes from the port's monitor
//! (`EnumPortsW` level 2) and its name; a Standard TCP/IP port's real address from its registry
//! key (`HostName`, else `IPAddress`; never from the port's name: `IP_192.168.1.50` may point
//! elsewhere); a WSD port's device address from its PnP-X properties; an IPP port's host and path
//! from its URL. The rules are plain Rust; `sys` reads.
//!
//! The WSD walk, as measured on Ted's 26200 (DECISIONS.md): the port's own devnode is
//! `SWD\PRINTENUM\<port name>`; its parent (`SWD\IPP\<uuid>` on 24H2 and later, else the
//! `SWD\DAFWSDProvider\urn:uuid:<uuid>` device) carries `PKEY_PNPX_IpAddress`
//! ({656A3BB3-ECC0-43FD-8477-4AE0404A96CD} 12297, a string list) and `PKEY_PNPX_PhysicalAddress`
//! (same GUID, 12294, 6 bytes). The walk goes up at most five parents; failing that, the WSD
//! monitor's `Printer UUID` names the two devices directly.

use std::net::IpAddr;

/// A port's kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Kind {
    /// Web Services for Devices (monitor "WSD Port", a `WSD-` name).
    Wsd,
    /// Standard TCP/IP (RAW or LPR).
    Tcp,
    /// IPP: an `http(s)://` port, or the WSD monitor's IPP ports.
    Ipp,
    /// USB (`USBnnn`, the USB monitor).
    Usb,
    /// LPT and COM ports, DOT4.
    Cable,
    /// A printer shared by another PC (`\\server\printer`).
    Shared,
    /// Files and nothing: Print to PDF, XPS, OneNote, Fax, `PORTPROMPT:`, `nul:`, `FILE:`.
    Virtual,
    /// Universal Print.
    Cloud,
    /// A monitor no rule knows: the port's name and monitor are shown, nothing is guessed.
    Other,
}

impl Kind {
    pub fn words(self) -> &'static str {
        match self {
            Kind::Wsd => "WSD",
            Kind::Tcp => "TCP/IP",
            Kind::Ipp => "IPP",
            Kind::Usb => "USB",
            Kind::Cable => "cable",
            Kind::Shared => "shared",
            Kind::Virtual => "virtual",
            Kind::Cloud => "cloud",
            Kind::Other => "other",
        }
    }

    /// Ports that reach a device on the network (probed).
    pub fn network(self) -> bool {
        matches!(self, Kind::Wsd | Kind::Tcp | Kind::Ipp)
    }
}

pub const MONITOR_TCP: &str = "Standard TCP/IP Port";
pub const MONITOR_WSD: &str = "WSD Port";
pub const MONITOR_USB: &str = "USB Monitor";
pub const MONITOR_LOCAL: &str = "Local Port";

/// The monitor's name as the registry keys it. `EnumPortsW` level 2 reports some by their DLL or
/// another name (measured on 26200: "TCPMON.DLL" with the description "Standard TCP/IP Port",
/// "WSD Port Monitor", "Local Monitor").
pub fn canonical_monitor(monitor: &str, description: &str) -> String {
    let m = monitor.trim().to_ascii_lowercase();
    let d = description.trim().to_ascii_lowercase();
    if m == "tcpmon.dll" || m == MONITOR_TCP.to_ascii_lowercase() || d == MONITOR_TCP.to_ascii_lowercase() {
        MONITOR_TCP.into()
    } else if m == "wsd port monitor" || m == MONITOR_WSD.to_ascii_lowercase() || m == "apmon.dll" {
        MONITOR_WSD.into()
    } else if m == "local monitor" || m == "localspl.dll" || m == MONITOR_LOCAL.to_ascii_lowercase() {
        MONITOR_LOCAL.into()
    } else if m == "usbmon.dll" || m == MONITOR_USB.to_ascii_lowercase() {
        MONITOR_USB.into()
    } else {
        monitor.trim().to_string()
    }
}

/// A port's kind from its name, its monitor and the printer's driver (Universal Print shares the
/// virtual monitor with other virtual printers; its driver tells them apart).
pub fn classify(name: &str, monitor: &str, driver: &str) -> Kind {
    let n = name.trim();
    let lower = n.to_ascii_lowercase();
    let m = monitor.trim().to_ascii_lowercase();
    let d = driver.to_ascii_lowercase();
    if n.starts_with("\\\\") {
        return Kind::Shared;
    }
    if lower.starts_with("http://") || lower.starts_with("https://") {
        return Kind::Ipp;
    }
    if m == MONITOR_TCP.to_ascii_lowercase() {
        return Kind::Tcp;
    }
    if m == MONITOR_WSD.to_ascii_lowercase() || lower.starts_with("wsd-") {
        return if lower.starts_with("ipp") { Kind::Ipp } else { Kind::Wsd };
    }
    if m.contains("universal print") || d.contains("universal print") {
        return Kind::Cloud;
    }
    if m == MONITOR_USB.to_ascii_lowercase() || is_numbered(&lower, "usb") {
        return Kind::Usb;
    }
    if is_numbered(&lower, "dot4") || is_numbered(&lower, "lpt") || is_numbered(&lower, "com") || is_numbered(&lower, "tspt") {
        return Kind::Cable;
    }
    if matches!(lower.as_str(), "portprompt:" | "nul:" | "file:" | "xpsport:" | "shrfax:" | "onenote:" | "nul" | "pdf:")
        || lower.ends_with(".pdf")
        || m.contains("virtual")
        || m.contains("pdf")
        || m.contains("fax")
        || m.contains("onenote")
        || d.contains("pdf")
        || d.contains("xps document writer")
        || d.contains("onenote")
        || d.contains("fax")
    {
        return Kind::Virtual;
    }
    Kind::Other
}

/// "USB001", "LPT1:", "COM3:": the prefix and digits (and an optional colon).
fn is_numbered(lower: &str, prefix: &str) -> bool {
    let Some(rest) = lower.strip_prefix(prefix) else { return false };
    let rest = rest.trim_end_matches(':');
    !rest.is_empty() && rest.len() <= 4 && rest.bytes().all(|b| b.is_ascii_digit())
}

/// A Standard TCP/IP port's configuration, as its registry key holds it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TcpConfig {
    /// `HostName`: what Windows (Settings, `Add-PrinterPort`) writes the address into, an IP
    /// address or a host name.
    pub host_name: String,
    /// `IPAddress`: the older field; empty on ports made by Windows 10 and 11.
    pub ip_address: String,
    /// 1 RAW, 2 LPR.
    pub protocol: u32,
    pub port_number: u32,
    /// The LPR queue.
    pub queue: String,
    pub snmp: bool,
    pub community: String,
    pub snmp_index: u32,
}

impl TcpConfig {
    /// The address the port really sends to: `HostName` when set, else `IPAddress`.
    pub fn target(&self) -> &str {
        let h = self.host_name.trim();
        if h.is_empty() { self.ip_address.trim() } else { h }
    }

    pub fn protocol_words(&self) -> String {
        match self.protocol {
            1 => format!("RAW {}", self.port_number),
            2 => format!("LPR queue '{}'", crate::text::clean_max(&self.queue, 40)),
            p => format!("protocol {p}"),
        }
    }
}

/// What PnP-X knows of a WSD device.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WsdDevice {
    pub ips: Vec<IpAddr>,
    pub mac: Option<crate::net::Mac>,
    /// The printer's UUID (the WSD monitor's `Printer UUID`).
    pub uuid: String,
    /// The IPP URL Windows keeps for it, if any ("http://192.168.1.142:631/ipp/print").
    pub ipp_url: Option<String>,
    /// The devnode is present now (else these are the last known values).
    pub present: bool,
}

/// One port.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Port {
    pub name: String,
    pub monitor: String,
    pub description: String,
    pub tcp: Option<TcpConfig>,
    pub wsd: Option<WsdDevice>,
}

/// Where a port points, as the window says it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Address {
    /// An IP address.
    Ip(IpAddr),
    /// A host name (resolved on a worker; both shown).
    Host(String),
    /// A network port whose address is not known: why.
    Unknown(String),
    /// Not a network port.
    None,
}

impl Address {
    pub fn ip(&self) -> Option<IpAddr> {
        match self {
            Address::Ip(a) => Some(*a),
            _ => None,
        }
    }
}

/// An IP address as typed or stored ("192.168.1.50", "fe80::1", "[fe80::1]").
pub fn parse_ip(s: &str) -> Option<IpAddr> {
    let t = s.trim().trim_start_matches('[').trim_end_matches(']');
    let t = t.split('%').next().unwrap_or(t);
    t.parse().ok()
}

/// An IPP URL's host and path: "http://192.168.1.50:631/ipp/print" -> ("192.168.1.50",
/// Some(631), "ipp/print").
pub fn ipp_url(url: &str) -> Option<(String, Option<u16>, String)> {
    let u = url.trim();
    let i = u.find("://")?;
    let rest = &u[i + 3..];
    let (authority, path) = match rest.find('/') {
        Some(j) => (&rest[..j], &rest[j + 1..]),
        None => (rest, ""),
    };
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    let (host, port) = if let Some(end) = authority.strip_prefix('[').and_then(|a| a.find(']').map(|e| (a, e))) {
        let (a, e) = end;
        let h = &a[..e];
        let p = a[e + 1..].strip_prefix(':').and_then(|p| p.parse().ok());
        (h.to_string(), p)
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) if !h.contains(':') => (h.to_string(), p.parse().ok()),
            _ => (authority.to_string(), None),
        }
    };
    Some((host, port, path.to_string()))
}

/// Where a port of `kind` points.
pub fn address(kind: Kind, port: &Port) -> Address {
    match kind {
        Kind::Tcp => match &port.tcp {
            Some(c) if !c.target().is_empty() => match parse_ip(c.target()) {
                Some(ip) => Address::Ip(ip),
                None => Address::Host(crate::text::clean_max(c.target(), 200)),
            },
            Some(_) => Address::Unknown("the port has no address set".into()),
            None => Address::Unknown("the port's settings could not be read".into()),
        },
        Kind::Wsd => match &port.wsd {
            Some(w) => match w.ips.iter().find(|a| a.is_ipv4()).or(w.ips.first()) {
                Some(ip) => Address::Ip(*ip),
                None => Address::Unknown("WSD device, address unknown".into()),
            },
            None => Address::Unknown("WSD device, address unknown".into()),
        },
        Kind::Ipp => match ipp_url(&port.name).or_else(|| port.wsd.as_ref().and_then(|w| w.ipp_url.as_deref()).and_then(ipp_url)) {
            Some((h, _, _)) => match parse_ip(&h) {
                Some(ip) => Address::Ip(ip),
                None => Address::Host(crate::text::clean_max(&h, 200)),
            },
            None => match port.wsd.as_ref().and_then(|w| w.ips.first()) {
                Some(ip) => Address::Ip(*ip),
                None => Address::Unknown("IPP device, address unknown".into()),
            },
        },
        _ => Address::None,
    }
}

/// The IPP path to ask a printer behind this port ("ipp/print" when nothing better is known).
pub fn ipp_path(kind: Kind, port: &Port) -> String {
    let from = match kind {
        Kind::Ipp => ipp_url(&port.name).map(|x| x.2),
        _ => None,
    }
    .or_else(|| port.wsd.as_ref().and_then(|w| w.ipp_url.as_deref()).and_then(ipp_url).map(|x| x.2));
    from.and_then(|p| crate::ipp::path_of(&p)).unwrap_or_else(|| crate::ipp::DEFAULT_PATH.into())
}

/// A name for a new TCP/IP port to `ip`: `IP_<ip>`, or `IP_<ip>_2`... when that name exists with
/// another address; an existing one with the same address is reused. (name, reused)
pub fn port_name_for(ip: std::net::Ipv4Addr, existing: &[(String, String)]) -> (String, bool) {
    let target = ip.to_string();
    let base = format!("IP_{ip}");
    for n in 1..=99u32 {
        let name = if n == 1 { base.clone() } else { format!("{base}_{n}") };
        match existing.iter().find(|(e, _)| e.eq_ignore_ascii_case(&name)) {
            None => return (name, false),
            Some((_, addr)) if addr.trim() == target => return (name, true),
            Some(_) => {}
        }
    }
    (format!("{base}_{}", existing.len() + 100), false)
}

#[cfg(windows)]
pub mod sys {
    use super::*;
    use windows_sys::Win32::Foundation::*;
    use windows_sys::Win32::Graphics::Printing::*;
    use windows_sys::Win32::System::Registry::*;

    unsafe fn wstr(p: *const u16) -> String {
        if p.is_null() {
            return String::new();
        }
        // SAFETY: the caller hands a NUL-terminated string inside its own buffer.
        unsafe {
            let len = (0..).take_while(|&i| *p.add(i) != 0).count();
            String::from_utf16_lossy(std::slice::from_raw_parts(p, len))
        }
    }

    /// Every port of the local server (`EnumPortsW` level 2): name, monitor, description.
    pub fn list() -> Result<Vec<Port>, u32> {
        let mut need = 0u32;
        let mut count = 0u32;
        // SAFETY: a size query.
        unsafe { EnumPortsW(std::ptr::null(), 2, std::ptr::null_mut(), 0, &mut need, &mut count) };
        if need == 0 {
            return Err(unsafe { GetLastError() });
        }
        let mut buf = vec![0u64; (need as usize).div_ceil(8)];
        // SAFETY: a buffer of at least `need` bytes, 8-aligned.
        if unsafe { EnumPortsW(std::ptr::null(), 2, buf.as_mut_ptr().cast(), (buf.len() * 8) as u32, &mut need, &mut count) } == 0 {
            return Err(unsafe { GetLastError() });
        }
        // SAFETY: `count` PORT_INFO_2W records at the start of `buf`; strings inside it.
        let rows = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const PORT_INFO_2W, count as usize) };
        Ok(rows
            .iter()
            .take(4096)
            .map(|r| unsafe {
                let description = wstr(r.pDescription);
                Port { name: wstr(r.pPortName), monitor: canonical_monitor(&wstr(r.pMonitorName), &description), description, tcp: None, wsd: None }
            })
            .collect())
    }

    /// The installed port monitors (`EnumMonitorsW` level 2): (name, DLL).
    pub fn monitors() -> Vec<(String, String)> {
        let mut need = 0u32;
        let mut count = 0u32;
        // SAFETY: a size query, then a buffer of that size.
        unsafe { EnumMonitorsW(std::ptr::null(), 2, std::ptr::null_mut(), 0, &mut need, &mut count) };
        if need == 0 {
            return Vec::new();
        }
        let mut buf = vec![0u64; (need as usize).div_ceil(8)];
        if unsafe { EnumMonitorsW(std::ptr::null(), 2, buf.as_mut_ptr().cast(), (buf.len() * 8) as u32, &mut need, &mut count) } == 0 {
            return Vec::new();
        }
        // SAFETY: `count` MONITOR_INFO_2W records.
        let rows = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const MONITOR_INFO_2W, count as usize) };
        rows.iter().map(|r| unsafe { (wstr(r.pName), wstr(r.pDLLName)) }).collect()
    }

    /// An open registry key, closed on drop.
    struct Key(HKEY);
    impl Drop for Key {
        fn drop(&mut self) {
            // SAFETY: opened below, closed once.
            unsafe { RegCloseKey(self.0) };
        }
    }

    fn open_key(path: &str) -> Option<Key> {
        let p = crate::host::wide(path);
        let mut h: HKEY = std::ptr::null_mut();
        // SAFETY: a NUL-terminated path; read access only.
        (unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, p.as_ptr(), 0, KEY_READ, &mut h) } == 0).then_some(Key(h))
    }

    fn reg_string(k: &Key, name: &str) -> Option<String> {
        let n = crate::host::wide(name);
        let mut buf = vec![0u16; 1024];
        let mut size = (buf.len() * 2) as u32;
        // SAFETY: a buffer and its size in bytes; strings only.
        let r = unsafe { RegGetValueW(k.0, std::ptr::null(), n.as_ptr(), RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ | RRF_NOEXPAND, std::ptr::null_mut(), buf.as_mut_ptr().cast(), &mut size) };
        if r != 0 {
            return None;
        }
        let len = (size as usize / 2).min(buf.len());
        let s = &buf[..len];
        let end = s.iter().position(|&c| c == 0).unwrap_or(s.len());
        Some(String::from_utf16_lossy(&s[..end]))
    }

    fn reg_dword(k: &Key, name: &str) -> Option<u32> {
        let n = crate::host::wide(name);
        let mut v = 0u32;
        let mut size = 4u32;
        // SAFETY: a DWORD out.
        (unsafe { RegGetValueW(k.0, std::ptr::null(), n.as_ptr(), RRF_RT_REG_DWORD, std::ptr::null_mut(), (&mut v as *mut u32).cast(), &mut size) } == 0).then_some(v)
    }

    /// A Standard TCP/IP port's registry key, read-only.
    pub fn tcp_config(port: &str) -> Option<TcpConfig> {
        if port.contains('\\') || port.len() > 200 {
            return None;
        }
        let k = open_key(&format!("SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors\\Standard TCP/IP Port\\Ports\\{port}"))?;
        Some(TcpConfig {
            host_name: reg_string(&k, "HostName").unwrap_or_default(),
            ip_address: reg_string(&k, "IPAddress").unwrap_or_default(),
            protocol: reg_dword(&k, "Protocol").unwrap_or(0),
            port_number: reg_dword(&k, "PortNumber").unwrap_or(0),
            queue: reg_string(&k, "Queue").unwrap_or_default(),
            snmp: reg_dword(&k, "SNMP Enabled").unwrap_or(0) != 0,
            community: reg_string(&k, "SNMP Community").unwrap_or_default(),
            snmp_index: reg_dword(&k, "SNMP Index").unwrap_or(0),
        })
    }

    /// The WSD monitor's `Printer UUID` for a port.
    fn wsd_uuid(port: &str) -> Option<String> {
        if port.contains('\\') || port.len() > 200 {
            return None;
        }
        let k = open_key(&format!("SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors\\WSD Port\\Ports\\{port}"))?;
        reg_string(&k, "Printer UUID").filter(|u| u.len() <= 64 && u.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-'))
    }

    // ---------- PnP-X ----------

    use windows_sys::Win32::Devices::DeviceAndDriverInstallation::*;
    use windows_sys::core::GUID;

    const PNPX: GUID = GUID::from_u128(0x656a3bb3_ecc0_43fd_8477_4ae0404a96cd);
    const IP_ADDRESS: u32 = 12297;
    const PHYSICAL_ADDRESS: u32 = 12294;
    /// The IPP printer's URL Windows keeps on the SWD\IPP device (measured on 26200).
    const IPP_URL: (GUID, u32) = (GUID::from_u128(0xa35996ab_11cf_4935_8b61_a6761081ecdf), 12);

    fn locate(id: &str) -> Option<(u32, bool)> {
        let w = crate::host::wide(id);
        let mut dn = 0u32;
        // SAFETY: a NUL-terminated id; present devices first, then phantoms (last known values).
        if unsafe { CM_Locate_DevNodeW(&mut dn, w.as_ptr(), CM_LOCATE_DEVNODE_NORMAL) } == CR_SUCCESS {
            return Some((dn, true));
        }
        (unsafe { CM_Locate_DevNodeW(&mut dn, w.as_ptr(), CM_LOCATE_DEVNODE_PHANTOM) } == CR_SUCCESS).then_some((dn, false))
    }

    /// A property's raw bytes and type.
    fn prop(dn: u32, guid: GUID, pid: u32) -> Option<(u32, Vec<u8>)> {
        let key = DEVPROPKEY { fmtid: guid, pid };
        let mut ty = 0u32;
        let mut size = 0u32;
        // SAFETY: a size query, then a buffer of that size.
        unsafe { CM_Get_DevNode_PropertyW(dn, &key, &mut ty, std::ptr::null_mut(), &mut size, 0) };
        if size == 0 || size > 64 * 1024 {
            return None;
        }
        let mut buf = vec![0u8; size as usize];
        (unsafe { CM_Get_DevNode_PropertyW(dn, &key, &mut ty, buf.as_mut_ptr(), &mut size, 0) } == CR_SUCCESS).then(|| {
            buf.truncate(size as usize);
            (ty, buf)
        })
    }

    fn strings(b: &[u8]) -> Vec<String> {
        let units: Vec<u16> = b.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect();
        units.split(|&u| u == 0).filter(|s| !s.is_empty()).take(16).map(String::from_utf16_lossy).collect()
    }

    /// What PnP-X says on devnode `dn`: (ips, mac, ipp url).
    fn pnpx(dn: u32) -> (Vec<IpAddr>, Option<crate::net::Mac>, Option<String>) {
        let ips: Vec<IpAddr> = prop(dn, PNPX, IP_ADDRESS).map(|(_, b)| strings(&b).iter().filter_map(|s| parse_ip(s)).collect()).unwrap_or_default();
        let mac = prop(dn, PNPX, PHYSICAL_ADDRESS).and_then(|(_, b)| (b.len() == 6).then(|| [b[0], b[1], b[2], b[3], b[4], b[5]]));
        let url = prop(dn, IPP_URL.0, IPP_URL.1).and_then(|(_, b)| strings(&b).into_iter().next()).filter(|u| u.starts_with("http"));
        (ips, mac, url)
    }

    fn parent(dn: u32) -> Option<u32> {
        let mut p = 0u32;
        // SAFETY: an out devnode.
        (unsafe { CM_Get_Parent(&mut p, dn, 0) } == CR_SUCCESS).then_some(p)
    }

    /// A WSD (or WSD-monitor IPP) port's device, by the walk measured on 26200.
    pub fn wsd_device(port: &str) -> Option<WsdDevice> {
        let uuid = wsd_uuid(port).unwrap_or_default();
        let mut found = WsdDevice { uuid: uuid.clone(), ..WsdDevice::default() };
        let take = |dn: u32, present: bool, f: &mut WsdDevice| {
            let (ips, mac, url) = pnpx(dn);
            if f.ips.is_empty() && !ips.is_empty() {
                f.ips = ips;
                f.present = present;
            }
            if f.mac.is_none() {
                f.mac = mac;
            }
            if f.ipp_url.is_none() {
                f.ipp_url = url;
            }
        };
        if let Some((mut dn, present)) = locate(&format!("SWD\\PRINTENUM\\{port}")) {
            for _ in 0..5 {
                take(dn, present, &mut found);
                if !found.ips.is_empty() && found.mac.is_some() {
                    break;
                }
                match parent(dn) {
                    Some(p) => dn = p,
                    None => break,
                }
            }
        }
        if !uuid.is_empty() && (found.ips.is_empty() || found.mac.is_none()) {
            for id in [format!("SWD\\IPP\\{uuid}"), format!("SWD\\DAFWSDProvider\\urn:uuid:{uuid}")] {
                if let Some((dn, present)) = locate(&id) {
                    take(dn, present, &mut found);
                }
            }
        }
        Some(found)
    }
}
