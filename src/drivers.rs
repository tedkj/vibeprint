//! A printer's driver (`GetPrinterDriverW` level 8: name, version, date, provider, maker) and the
//! installed drivers Add by IP offers (`EnumPrinterDriversW`). Microsoft's class drivers are told
//! apart from a vendor's own: they print, but not everything the printer can do. Drivers are
//! never installed or deleted here.

/// One driver.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Driver {
    pub name: String,
    /// "10.0.26100.1" (from the 64-bit version).
    pub version: Option<String>,
    /// The driver's own date, unix seconds (UTC midnight as Windows stores it).
    pub date: Option<i64>,
    pub provider: String,
    pub maker: String,
}

impl Driver {
    pub fn class(&self) -> bool {
        is_class_driver(&self.name, &self.provider)
    }

    /// "Microsoft class driver" or "Canon's own driver".
    pub fn kind_words(&self) -> String {
        if self.class() {
            "Microsoft class driver (prints, but without the maker's extras)".into()
        } else if !self.maker.trim().is_empty() {
            format!("the maker's own ({})", crate::text::clean_max(&self.maker, 40))
        } else if !self.provider.trim().is_empty() {
            format!("from {}", crate::text::clean_max(&self.provider, 40))
        } else {
            "unknown provider".into()
        }
    }
}

/// Microsoft's class drivers: the named ones, and any driver whose provider is Microsoft and
/// whose name ends "Class Driver".
pub fn is_class_driver(name: &str, provider: &str) -> bool {
    let n = name.trim().to_ascii_lowercase();
    const NAMED: [&str; 5] = ["microsoft ipp class driver", "microsoft pcl6 class driver", "microsoft ps class driver", "universal print class driver", "microsoft virtual print class driver"];
    NAMED.contains(&n.as_str()) || (provider.trim().eq_ignore_ascii_case("microsoft") && n.ends_with("class driver"))
}

/// A 64-bit driver version: "10.0.26100.1".
pub fn version_text(v: u64) -> Option<String> {
    (v != 0).then(|| format!("{}.{}.{}.{}", v >> 48, (v >> 32) & 0xFFFF, (v >> 16) & 0xFFFF, v & 0xFFFF))
}

/// A FILETIME (100 ns since 1601) as unix seconds; None for zero.
pub fn filetime_unix(ft: u64) -> Option<i64> {
    (ft != 0).then(|| (ft / 10_000_000) as i64 - 11_644_473_600)
}

/// The words a model or driver name is compared by: lower case, letters and digits, without the
/// filler words ("series", "printer", the maker's legal form) that one side writes and the other
/// leaves out.
pub fn model_words(s: &str) -> Vec<String> {
    const FILLER: [&str; 16] = ["series", "printer", "printers", "the", "inc", "co", "ltd", "corp", "corporation", "class", "driver", "pcl", "pcl6", "ps", "xl", "v4"];
    s.split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
        .map(str::to_lowercase)
        .filter(|w| !FILLER.contains(&w.as_str()))
        .collect()
}

/// Whether a driver's name fits a model: every word of the shorter is in the longer, and they
/// share a word with a digit in it (the model number). Class drivers fit nothing by name.
pub fn fits(model: &str, driver: &str) -> bool {
    if is_class_driver(driver, "") {
        return false;
    }
    let (m, d) = (model_words(model), model_words(driver));
    if m.is_empty() || d.is_empty() {
        return false;
    }
    let (short, long) = if m.len() <= d.len() { (&m, &d) } else { (&d, &m) };
    short.iter().all(|w| long.contains(w)) && short.iter().any(|w| w.chars().any(|c| c.is_ascii_digit()))
}

/// The model a device's name states, normalised so SNMP's sysDescr and IPP's make-and-model
/// compare (AUDIT-1 R-PRINT-3): a `KEY:VALUE` list gives its model field (`MDL`, `MODEL`, HP's
/// `PID`) and drops the rest (`SN:`, `FN:`, ...); without one, the free text is the model. A
/// name with no model number in it, or one that names the network card rather than the printer
/// ("HP ETHERNET MULTI-ENVIRONMENT", "EPSON Built-in 11b/g/n Print Server", "Brother NC-8300w,
/// Firmware Ver.1.25"), states no model: None, and the model is not compared.
pub fn model_of(name: &str) -> Option<String> {
    let mut free = Vec::new();
    for field in name.split([',', ';']) {
        match field.split_once(':') {
            Some((k, v)) if !k.trim().is_empty() && k.trim().len() <= 16 && k.trim().chars().all(|c| c.is_ascii_alphabetic() || c == ' ') => {
                if ["MDL", "MODEL", "PID"].iter().any(|m| k.trim().eq_ignore_ascii_case(m)) && !v.trim().is_empty() {
                    return Some(v.trim().to_string());
                }
            }
            _ => free.push(field.trim()),
        }
    }
    let m = free.join(" ");
    let words = model_words(&m);
    const CARD: [&str; 10] = ["ethernet", "jetdirect", "server", "printserver", "firmware", "nic", "network", "wireless", "wlan", "built"];
    let card = words.iter().any(|w| CARD.contains(&w.as_str()));
    let number = words.iter().any(|w| w.chars().any(|c| c.is_ascii_digit()));
    (number && !card).then(|| m.trim().to_string())
}

/// Two normalised models name the same printer: the same words, or every word of the shorter
/// in the longer with the model number among them ("GX6000 series" and "Canon GX6000 series").
pub fn same_model(a: &str, b: &str) -> bool {
    model_words(a) == model_words(b) || fits(a, b) || fits(b, a)
}

/// The maker a model or driver name names, from the makers' own words (rebadged brands as
/// their maker: UTAX and TA are Kyocera, Lanier, Savin, Gestetner and Nashuatec are Ricoh,
/// Develop is Konica Minolta). None when no known maker is named, or two are ("Fuji Xerox").
pub fn maker_of(name: &str) -> Option<&'static str> {
    const MAKERS: [(&str, &str); 31] = [
        ("canon", "Canon"),
        ("brother", "Brother"),
        ("hp", "HP"),
        ("hewlett", "HP"),
        ("epson", "Epson"),
        ("kyocera", "Kyocera"),
        ("utax", "Kyocera"),
        ("triumph", "Kyocera"),
        ("ricoh", "Ricoh"),
        ("lanier", "Ricoh"),
        ("savin", "Ricoh"),
        ("gestetner", "Ricoh"),
        ("nashuatec", "Ricoh"),
        ("xerox", "Xerox"),
        ("lexmark", "Lexmark"),
        ("samsung", "Samsung"),
        ("konica", "Konica Minolta"),
        ("minolta", "Konica Minolta"),
        ("develop", "Konica Minolta"),
        ("sharp", "Sharp"),
        ("oki", "OKI"),
        ("toshiba", "Toshiba"),
        ("dell", "Dell"),
        ("pantum", "Pantum"),
        ("zebra", "Zebra"),
        ("dymo", "Dymo"),
        ("olivetti", "Olivetti"),
        ("panasonic", "Panasonic"),
        ("fujifilm", "Fujifilm"),
        ("fuji", "Fujifilm"),
        ("sindoh", "Sindoh"),
    ];
    let lower = name.to_lowercase();
    let mut found: Option<&'static str> = None;
    for w in lower.split(|c: char| !c.is_alphanumeric()).filter(|w| !w.is_empty()) {
        if let Some((_, m)) = MAKERS.iter().find(|(k, _)| *k == w) {
            match found {
                Some(f) if f != *m => return None,
                _ => found = Some(m),
            }
        }
    }
    found
}

/// The installed driver to preselect for `model`: the fitting one with the fewest extra words.
pub fn pick(model: &str, drivers: &[String]) -> Option<usize> {
    drivers.iter().enumerate().filter(|(_, d)| fits(model, d)).min_by_key(|(i, d)| (model_words(d).len().abs_diff(model_words(model).len()), *i)).map(|(i, _)| i)
}

#[cfg(windows)]
pub mod sys {
    use super::*;
    use windows_sys::Win32::Foundation::*;
    use windows_sys::Win32::Graphics::Printing::*;

    unsafe fn wstr(p: *const u16) -> String {
        if p.is_null() {
            return String::new();
        }
        // SAFETY: a NUL-terminated string inside the caller's buffer.
        unsafe {
            let len = (0..).take_while(|&i| *p.add(i) != 0).count();
            String::from_utf16_lossy(std::slice::from_raw_parts(p, len))
        }
    }

    /// The driver of printer `name` (level 8).
    pub fn of(name: &[u16]) -> Result<Driver, u32> {
        let h = crate::printers::sys::open(name, PRINTER_ACCESS_USE)?;
        let mut need = 0u32;
        // SAFETY: a size query, then a buffer of that size (8-aligned).
        unsafe { GetPrinterDriverW(h.0, std::ptr::null(), 8, std::ptr::null_mut(), 0, &mut need) };
        if need == 0 {
            return Err(unsafe { GetLastError() });
        }
        let mut buf = vec![0u64; (need as usize).div_ceil(8)];
        if unsafe { GetPrinterDriverW(h.0, std::ptr::null(), 8, buf.as_mut_ptr().cast(), (buf.len() * 8) as u32, &mut need) } == 0 {
            return Err(unsafe { GetLastError() });
        }
        // SAFETY: a DRIVER_INFO_8W at the start of `buf`; strings inside it.
        let d = unsafe { &*(buf.as_ptr() as *const DRIVER_INFO_8W) };
        let ft = ((d.ftDriverDate.dwHighDateTime as u64) << 32) | d.ftDriverDate.dwLowDateTime as u64;
        Ok(unsafe { Driver { name: wstr(d.pName), version: version_text(d.dwlDriverVersion), date: filetime_unix(ft), provider: wstr(d.pszProvider), maker: wstr(d.pszMfgName) } })
    }

    /// The installed drivers' names (this PC's environment), each once, sorted.
    pub fn installed() -> Vec<String> {
        let mut need = 0u32;
        let mut count = 0u32;
        // SAFETY: a size query, then a buffer of that size.
        unsafe { EnumPrinterDriversW(std::ptr::null(), std::ptr::null(), 1, std::ptr::null_mut(), 0, &mut need, &mut count) };
        if need == 0 {
            return Vec::new();
        }
        let mut buf = vec![0u64; (need as usize).div_ceil(8)];
        if unsafe { EnumPrinterDriversW(std::ptr::null(), std::ptr::null(), 1, buf.as_mut_ptr().cast(), (buf.len() * 8) as u32, &mut need, &mut count) } == 0 {
            return Vec::new();
        }
        // SAFETY: `count` DRIVER_INFO_1W records.
        let rows = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const DRIVER_INFO_1W, count as usize) };
        let mut v: Vec<String> = rows.iter().map(|r| unsafe { wstr(r.pName) }).filter(|n| !n.is_empty()).collect();
        v.sort_by_key(|n| (n.to_lowercase(), n.clone()));
        v.dedup();
        v
    }
}
