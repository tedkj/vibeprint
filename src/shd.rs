//! The spooler's shadow files (`%SystemRoot%\System32\spool\PRINTERS\*.SHD`): each names the
//! printer its job belongs to. Clear queue's last resort deletes **only** that printer's
//! SHD/SPL pairs, so the header is parsed strictly, and a shadow file of a layout not measured
//! here is left alone and listed, never assumed ours.
//!
//! The layout, measured on 26100 (Windows Sandbox, three jobs on two printers; fixtures in
//! `tests/fixtures/shd/`, DECISIONS.md): a DWORD signature 0x00005123, a DWORD header size
//! (0xE0), the job id at 0x0C, then 64-bit offsets from the file's start to NUL-terminated
//! UTF-16 strings: the user at 0x20, the document at 0x28, **the printer at 0x38**, the driver at
//! 0x40; the spool file's size (DWORD) at 0x80.

pub const SIGNATURE: u32 = 0x0000_5123;
const OFF_JOB: usize = 0x0C;
const OFF_USER: usize = 0x20;
const OFF_DOCUMENT: usize = 0x28;
const OFF_PRINTER: usize = 0x38;
const OFF_SIZE: usize = 0x80;
const MIN_HEADER: u32 = 0x88;
/// No shadow file is bigger (they hold a DEVMODE, the print ticket and a security descriptor).
pub const MAX_SIZE: usize = 1024 * 1024;

/// What a shadow file says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Shadow {
    pub job: u32,
    /// The printer, exact units.
    pub printer: Vec<u16>,
    pub document: String,
    pub user: String,
    pub size: u32,
}

/// Why a shadow file was left alone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Unknown {
    /// Another signature: a layout not measured here.
    Signature(u32),
    TooSmall,
    TooBig,
    /// An offset or a string that does not fit the file.
    Malformed(&'static str),
}

fn u32_at(b: &[u8], i: usize) -> Option<u32> {
    b.get(i..i + 4).map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn u64_at(b: &[u8], i: usize) -> Option<u64> {
    b.get(i..i + 8).map(|s| u64::from_le_bytes(s.try_into().unwrap()))
}

/// The string at the offset stored at `field`: inside the file, after the header, even, NUL-
/// terminated within 512 units. A zero offset is an empty string.
fn string_at(b: &[u8], field: usize, header: usize) -> Result<Vec<u16>, Unknown> {
    let off = u64_at(b, field).ok_or(Unknown::TooSmall)?;
    if off == 0 {
        return Ok(Vec::new());
    }
    let off = usize::try_from(off).map_err(|_| Unknown::Malformed("an offset past the file"))?;
    if off < header || off % 2 != 0 || off >= b.len() {
        return Err(Unknown::Malformed("an offset outside the file's strings"));
    }
    let mut units = Vec::new();
    let mut i = off;
    loop {
        let u = b.get(i..i + 2).map(|s| u16::from_le_bytes([s[0], s[1]])).ok_or(Unknown::Malformed("a string without its end"))?;
        if u == 0 {
            return Ok(units);
        }
        units.push(u);
        if units.len() > 512 {
            return Err(Unknown::Malformed("a string too long"));
        }
        i += 2;
    }
}

/// Parse a shadow file's header.
pub fn parse(b: &[u8]) -> Result<Shadow, Unknown> {
    if b.len() > MAX_SIZE {
        return Err(Unknown::TooBig);
    }
    let sig = u32_at(b, 0).ok_or(Unknown::TooSmall)?;
    if sig != SIGNATURE {
        return Err(Unknown::Signature(sig));
    }
    let header = u32_at(b, 4).ok_or(Unknown::TooSmall)?;
    if header < MIN_HEADER || header as usize > b.len() {
        return Err(Unknown::Malformed("a header size that does not fit"));
    }
    let h = header as usize;
    let printer = string_at(b, OFF_PRINTER, h)?;
    if printer.is_empty() {
        return Err(Unknown::Malformed("no printer name"));
    }
    Ok(Shadow {
        job: u32_at(b, OFF_JOB).ok_or(Unknown::TooSmall)?,
        printer,
        document: String::from_utf16_lossy(&string_at(b, OFF_DOCUMENT, h)?),
        user: String::from_utf16_lossy(&string_at(b, OFF_USER, h)?),
        size: u32_at(b, OFF_SIZE).ok_or(Unknown::TooSmall)?,
    })
}

/// Two printer names are one printer: equal units, or equal ignoring case (Windows' printer
/// names are case-insensitive) when both are valid UTF-16.
pub fn same_printer(a: &[u16], b: &[u16]) -> bool {
    if a == b {
        return true;
    }
    match (String::from_utf16(a), String::from_utf16(b)) {
        (Ok(x), Ok(y)) => x.to_lowercase() == y.to_lowercase(),
        _ => false,
    }
}

/// A spool folder entry's stem when it is a shadow file ("00002.SHD" -> "00002"): letters and
/// digits only, at most 16, the extension any case.
pub fn shadow_stem(name: &str) -> Option<&str> {
    let (stem, ext) = name.rsplit_once('.')?;
    (ext.eq_ignore_ascii_case("shd") && !stem.is_empty() && stem.len() <= 16 && stem.bytes().all(|c| c.is_ascii_alphanumeric())).then_some(stem)
}

/// The plan for one printer over a listing of the spool folder: the stems whose shadow file
/// names `printer` (each goes with its `.SPL`), and the shadow files left alone with why.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Plan {
    pub ours: Vec<String>,
    pub left: Vec<(String, String)>,
}

/// The printer a shadow file names, or why it is not one VibePrint reads (what the spool folder
/// listing keeps of each shadow file: never its bytes).
pub fn printer_of(b: &[u8]) -> Result<Vec<u16>, String> {
    parse(b).map(|s| s.printer).map_err(|e| format!("{e:?}"))
}

/// `files`: (file name, the printer its shadow file names, or why it could not be read).
pub fn plan(printer: &[u16], files: &[(String, Result<Vec<u16>, String>)]) -> Plan {
    let mut p = Plan::default();
    for (name, named) in files {
        let Some(stem) = shadow_stem(name) else { continue };
        match named {
            Ok(n) if same_printer(n, printer) => p.ours.push(stem.to_string()),
            Ok(_) => {}
            Err(e) => p.left.push((name.clone(), e.clone())),
        }
    }
    p.ours.sort();
    p
}
