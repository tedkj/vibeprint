use std::collections::HashMap;
use std::path::PathBuf;

fn main() {
    let ui = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("ui");
    // Element debug info lets the UI tests find controls by accessible label; release builds skip it.
    let debug = std::env::var("PROFILE").as_deref() == Ok("debug");
    let config = slint_build::CompilerConfiguration::new()
        .with_library_paths(HashMap::from([("vibeware".to_string(), ui.join("vibeware").join("lib.slint"))]))
        .with_debug_info(debug);
    slint_build::compile_with_config(ui.join("all.slint"), config).unwrap();
    oui_table();
    windows_resources();
}

/// The IEEE registry (assets/oui/*.csv: MA-L, MA-M, MA-S) as a compact table for `oui.rs`
/// (VibeScan's, copied):
///
/// "OUI1", then four u32 LE: MA-L, MA-M and MA-S record counts and the names' byte length; then
/// the records of each registry, sorted by key: the assignment's hex digits as a big-endian key
/// (3, 4 and 5 bytes) and a 3-byte LE offset into the names; then the names, each a length byte
/// and that many bytes of UTF-8 (every distinct name once).
fn oui_table() {
    let dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("assets").join("oui");
    let mut names: Vec<u8> = Vec::new();
    let mut offsets: HashMap<String, u32> = HashMap::new();
    let mut out = b"OUI1".to_vec();
    let mut tables: Vec<Vec<u8>> = Vec::new();
    let mut counts = Vec::new();
    for (file, digits, key_bytes) in [("oui.csv", 6, 3), ("mam.csv", 7, 4), ("oui36.csv", 9, 5)] {
        let text = std::fs::read_to_string(dir.join(file)).unwrap_or_else(|e| panic!("assets/oui/{file}: {e}"));
        let mut rows: Vec<(u64, u32)> = Vec::new();
        for (i, rec) in csv_records(&text).into_iter().enumerate() {
            if i == 0 || rec.len() < 3 {
                continue; // the header
            }
            let hex = rec[1].trim();
            if hex.len() != digits {
                continue;
            }
            let Ok(key) = u64::from_str_radix(hex, 16) else { continue };
            let name: String = rec[2].split_whitespace().collect::<Vec<_>>().join(" ").chars().filter(|c| !c.is_control()).collect();
            if name.is_empty() {
                continue;
            }
            let off = *offsets.entry(name.clone()).or_insert_with(|| {
                let off = names.len() as u32;
                let bytes = name.as_bytes();
                let len = bytes.len().min(255);
                // Cut at a character boundary if a name ever ran past 255 bytes.
                let len = (0..=len).rev().find(|&l| name.is_char_boundary(l)).unwrap_or(0);
                names.push(len as u8);
                names.extend_from_slice(&bytes[..len]);
                off
            });
            rows.push((key, off));
        }
        rows.sort_unstable();
        rows.dedup_by_key(|r| r.0);
        let mut t = Vec::with_capacity(rows.len() * (key_bytes + 3));
        for (key, off) in &rows {
            t.extend_from_slice(&key.to_be_bytes()[8 - key_bytes..]);
            t.extend_from_slice(&off.to_le_bytes()[..3]);
        }
        counts.push(rows.len() as u32);
        tables.push(t);
    }
    assert!(names.len() < 1 << 24, "OUI names blob too large for 3-byte offsets");
    for c in &counts {
        out.extend_from_slice(&c.to_le_bytes());
    }
    out.extend_from_slice(&(names.len() as u32).to_le_bytes());
    for t in tables {
        out.extend_from_slice(&t);
    }
    out.extend_from_slice(&names);
    std::fs::write(PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("oui.bin"), out).unwrap();
    println!("cargo:rerun-if-changed=assets/oui");
}

/// RFC 4180 records: comma-separated fields, quoted fields may hold commas, line breaks and
/// doubled quotes; records end at a line break outside quotes.
fn csv_records(text: &str) -> Vec<Vec<String>> {
    let mut out = Vec::new();
    let (mut rec, mut field, mut quoted, mut chars) = (Vec::new(), String::new(), false, text.chars().peekable());
    while let Some(c) = chars.next() {
        match (quoted, c) {
            (true, '"') if chars.peek() == Some(&'"') => {
                chars.next();
                field.push('"');
            }
            (true, '"') => quoted = false,
            (true, c) => field.push(c),
            (false, '"') => quoted = true,
            (false, ',') => rec.push(std::mem::take(&mut field)),
            (false, '\r') => {}
            (false, '\n') => {
                rec.push(std::mem::take(&mut field));
                out.push(std::mem::take(&mut rec));
            }
            (false, c) => field.push(c),
        }
    }
    if !field.is_empty() || !rec.is_empty() {
        rec.push(field);
        out.push(rec);
    }
    out
}

/// Delay-loaded (the install check's network, signature and certificate DLLs).
const DELAYED: [&str; 3] = ["winhttp.dll", "wintrust.dll", "crypt32.dll"];

/// The exe's icon, version information and manifest.
fn windows_resources() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    let dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("assets");
    let version = std::env::var("CARGO_PKG_VERSION").unwrap();
    let mut n: Vec<u16> = version.split(['.', '-', '+']).take(3).map(|p| p.parse().unwrap_or(0)).collect();
    n.resize(4, 0);
    let numeric = format!("{},{},{},{}", n[0], n[1], n[2], n[3]);
    let path = |f: &str| dir.join(f).display().to_string().replace('\\', "\\\\");
    let rc = format!(
        r#"#pragma code_page(65001)
#include <winver.h>
1 ICON "{icon}"
1 24 "{manifest}"
1 VERSIONINFO
FILEVERSION {numeric}
PRODUCTVERSION {numeric}
FILEOS VOS_NT_WINDOWS32
FILETYPE VFT_APP
BEGIN
  BLOCK "StringFileInfo"
  BEGIN
    BLOCK "040904B0"
    BEGIN
      VALUE "CompanyName", "Ted K. Johansen"
      VALUE "FileDescription", "VibePrint"
      VALUE "FileVersion", "{version}"
      VALUE "InternalName", "VibePrint"
      VALUE "LegalCopyright", "Ted K. Johansen"
      VALUE "OriginalFilename", "VibePrint.exe"
      VALUE "ProductName", "VibePrint"
      VALUE "ProductVersion", "{version}"
    END
  END
  BLOCK "VarFileInfo"
  BEGIN
    VALUE "Translation", 0x409, 1200
  END
END
"#,
        icon = path("app.ico"),
        manifest = path("app.manifest"),
    );
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("app.rc");
    std::fs::write(&out, rc).unwrap();
    println!("cargo:rerun-if-changed=assets");
    // DLL hardening (VibeLink LINK-1): the loader takes the exe's static imports from System32
    // only, never from the exe's own (per-user, writable, or a USB stick's) folder, which the
    // elevated helper also starts from. LOAD_LIBRARY_SEARCH_SYSTEM32; tests/pe.rs checks the
    // load config carries it.
    if std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc") {
        println!("cargo:rustc-link-arg=/DEPENDENTLOADFLAG:0x800");
        // The DLLs only About's install check uses load when it first runs, not at every start:
        // after `main`'s SetDefaultDllDirectories, so from System32 only (tests/pe.rs checks
        // they are delay-loaded). The exe only; its unit-test build calls none of them, so the
        // linker's "nothing to delay-load" (LNK4199) is not a warning there.
        for dll in DELAYED {
            println!("cargo:rustc-link-arg-bins=/DELAYLOAD:{dll}");
        }
        println!("cargo:rustc-link-arg-bins=delayimp.lib");
        println!("cargo:rustc-link-arg-bins=/IGNORE:4199");
    }
    embed_resource::compile_for(&out, ["vibeprint"], embed_resource::NONE).manifest_required().unwrap();
}
