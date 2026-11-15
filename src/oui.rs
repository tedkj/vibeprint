//! Who made a network card: the MAC's organizationally unique identifier looked up in the IEEE
//! registry (MA-L, the 24-bit blocks, and the MA-M and MA-S blocks carved out of the IEEE's own
//! ones), bundled as a compact table built from `assets/oui/*.csv` (build.rs). Locally
//! administered addresses (a phone's private Wi-Fi address) belong to no maker and say so.

use crate::net::Mac;

static TABLE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/oui.bin"));

/// What a MAC says about its maker.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Maker {
    /// The organization's name as the IEEE registry has it.
    Vendor(&'static str),
    /// The registry lists the block as assigned privately (no name published).
    Unlisted,
    /// Locally administered (the 0x02 bit): randomized or set by software, no maker to name.
    Private,
    /// Not in the registry (or a multicast address, never a card's own).
    Unknown,
}

impl Maker {
    /// The short form the table shows ("Apple", "ASUSTek Computer", "private address").
    pub fn short(self) -> String {
        match self {
            Maker::Vendor(n) => short_name(n),
            Maker::Unlisted => "unlisted".into(),
            Maker::Private => "private address".into(),
            Maker::Unknown => String::new(),
        }
    }

    /// The registry's full name, or the words for the other cases.
    pub fn full(self) -> String {
        match self {
            Maker::Vendor(n) => n.to_string(),
            Maker::Unlisted => "Registered privately with the IEEE (no name published)".into(),
            Maker::Private => "A private (locally administered) address: no maker to look up".into(),
            Maker::Unknown => "Not in the IEEE registry".into(),
        }
    }
}

struct Registry {
    start: usize,
    count: usize,
    key_bytes: usize,
}

fn u32_at(i: usize) -> usize {
    u32::from_le_bytes(TABLE[i..i + 4].try_into().unwrap()) as usize
}

fn registries() -> ([Registry; 3], usize) {
    let (l, m, s, names_len) = (u32_at(4), u32_at(8), u32_at(12), u32_at(16));
    let a = 20;
    let b = a + l * 6;
    let c = b + m * 7;
    let names = c + s * 8;
    debug_assert_eq!(names + names_len, TABLE.len());
    ([Registry { start: a, count: l, key_bytes: 3 }, Registry { start: b, count: m, key_bytes: 4 }, Registry { start: c, count: s, key_bytes: 5 }], names)
}

fn name_at(names: usize, off: usize) -> &'static str {
    let len = TABLE[names + off] as usize;
    std::str::from_utf8(&TABLE[names + off + 1..names + off + 1 + len]).unwrap_or("")
}

impl Registry {
    fn find(&self, key: u64, names: usize) -> Option<&'static str> {
        let stride = self.key_bytes + 3;
        let key_at = |i: usize| {
            let p = self.start + i * stride;
            TABLE[p..p + self.key_bytes].iter().fold(0u64, |k, &b| (k << 8) | b as u64)
        };
        let (mut lo, mut hi) = (0usize, self.count);
        while lo < hi {
            let mid = (lo + hi) / 2;
            match key_at(mid).cmp(&key) {
                std::cmp::Ordering::Less => lo = mid + 1,
                std::cmp::Ordering::Greater => hi = mid,
                std::cmp::Ordering::Equal => {
                    let p = self.start + mid * stride + self.key_bytes;
                    let off = TABLE[p] as usize | (TABLE[p + 1] as usize) << 8 | (TABLE[p + 2] as usize) << 16;
                    return Some(name_at(names, off));
                }
            }
        }
        None
    }
}

/// The maker of `mac`: the smallest registered block that holds it (MA-S, then MA-M, then MA-L).
pub fn lookup(mac: &Mac) -> Maker {
    if mac[0] & 0x01 != 0 {
        return Maker::Unknown; // multicast: a group, never a card
    }
    if mac[0] & 0x02 != 0 {
        return Maker::Private;
    }
    let v = mac.iter().fold(0u64, |k, &b| (k << 8) | b as u64);
    let (regs, names) = registries();
    let found = regs[2].find(v >> 12, names).or_else(|| regs[1].find(v >> 20, names)).or_else(|| regs[0].find(v >> 24, names));
    match found {
        Some("Private") => Maker::Unlisted,
        Some(n) => Maker::Vendor(n),
        None => Maker::Unknown,
    }
}

/// Entries in the bundled registry: (MA-L, MA-M, MA-S).
pub fn counts() -> (usize, usize, usize) {
    let (r, _) = registries();
    (r[0].count, r[1].count, r[2].count)
}

/// A maker's name without its legal form, for a table cell: "Apple, Inc." -> "Apple",
/// "ASUSTek COMPUTER INC." -> "ASUSTek Computer", "TP-LINK TECHNOLOGIES CO.,LTD." -> "TP-Link
/// Technologies". Shouted words are put in title case unless short (an acronym: "AVM", "HP").
pub fn short_name(full: &str) -> String {
    const LEGAL: &[&str] = &[
        "co", "co.", "corp", "corp.", "corporation", "inc", "inc.", "incorporated", "ltd", "ltd.", "limited", "llc", "l.l.c.", "gmbh", "ag", "a.g.",
        "s.a.", "sa", "s.a.r.l.", "sarl", "srl", "s.r.l.", "spa", "s.p.a.", "bv", "b.v.", "nv", "n.v.", "ab", "oy", "as", "a/s", "asa", "aps", "kg",
        "plc", "pty", "pty.", "pte", "pte.", "sas", "s.l.", "sl", "kk", "k.k.", "co.,ltd", "co.,ltd.", "co.ltd", "co.ltd.", "&", "company",
    ];
    // Commas and parentheses end the useful part: "Shenzhen Foo Technology Co.,Ltd" keeps
    // "Shenzhen Foo Technology"; "(Shanghai)" and the like go.
    let head = full.split(['(', ',']).next().unwrap_or(full).trim();
    let mut words: Vec<&str> = head.split_whitespace().collect();
    while let Some(w) = words.last() {
        if LEGAL.contains(&w.to_ascii_lowercase().as_str()) || w.len() == 1 && !w.chars().all(|c| c.is_ascii_alphanumeric()) {
            words.pop();
        } else {
            break;
        }
    }
    if words.is_empty() {
        return full.trim().to_string();
    }
    // A shouted word (no lower case, more than three letters) is put in title case; mixed case
    // ("ASUSTek") and acronyms ("AVM", "HP") stay as written.
    let out: Vec<String> = words
        .iter()
        .map(|w| if w.chars().any(|c| c.is_lowercase()) { w.to_string() } else { title_word(w) })
        .collect();
    out.join(" ")
}

/// "TECHNOLOGIES" -> "Technologies", "TP-LINK" -> "TP-Link" (each part after a hyphen too; short
/// parts stay as acronyms).
fn title_word(w: &str) -> String {
    w.split('-')
        .map(|p| {
            if p.chars().filter(|c| c.is_alphabetic()).count() <= 3 {
                return p.to_string();
            }
            let mut c = p.chars();
            match c.next() {
                Some(f) => f.to_uppercase().collect::<String>() + &c.as_str().to_lowercase(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join("-")
}
