//! Text from outside (printer, port, driver and job names, server names, IPP and SNMP strings,
//! mDNS names and TXT values) as it may be shown: in the window, toasts, the status line and Copy
//! report. Cleaned at display only; what is handed to Windows stays raw. (VibeLink's, copied.)

/// Characters that change how the text around them reads without showing themselves: controls,
/// bidirectional embeddings, overrides, isolates and marks, zero-width spaces and line
/// separators, the soft hyphen and the Unicode tag characters (U+E0000..U+E007F). The joiners
/// U+200C (ZWNJ) and U+200D (ZWJ) are not among them: emoji sequences and Persian, Arabic and
/// Indic names need them (family rule, 2026-10-20).
pub fn invisible(c: char) -> bool {
    c.is_control()
        || matches!(c, '\u{00AD}' | '\u{061C}' | '\u{180E}' | '\u{200B}' | '\u{200E}' | '\u{200F}' | '\u{2028}'..='\u{202E}' | '\u{2060}'..='\u{2069}' | '\u{FEFF}' | '\u{E0000}'..='\u{E007F}')
}

/// Outside text as it may be shown: invisible characters gone, runs of whitespace (a newline
/// or tab included) one space, trimmed, at most `max` characters (an ellipsis marks a cut).
pub fn clean_max(s: &str, max: usize) -> String {
    let mut out = String::with_capacity(s.len().min(max * 4));
    let mut space = false;
    let mut n = 0usize;
    let mut cut = false;
    for c in s.chars() {
        if c.is_whitespace() || c == '\u{2028}' || c == '\u{2029}' {
            space = !out.is_empty();
            continue;
        }
        if invisible(c) {
            continue;
        }
        if space {
            if n + 1 >= max {
                cut = true;
                break;
            }
            out.push(' ');
            n += 1;
            space = false;
        }
        if n >= max {
            cut = true;
            break;
        }
        out.push(c);
        n += 1;
    }
    if cut {
        // Room for the ellipsis: drop the last character (never a byte: chars only).
        out.pop();
        out.push('…');
    }
    out
}

/// Outside text, at most 255 characters.
pub fn clean(s: &str) -> String {
    clean_max(s, 255)
}

/// UTF-16 from Windows as shown text: a lone surrogate becomes U+FFFD, then cleaned.
pub fn clean_wide(w: &[u16], max: usize) -> String {
    clean_max(&String::from_utf16_lossy(w), max)
}

/// Bytes from the network (IPP, SNMP, mDNS) as shown text: invalid UTF-8 replaced, then cleaned.
pub fn clean_bytes(b: &[u8], max: usize) -> String {
    clean_max(&String::from_utf8_lossy(b), max)
}

/// "1 printer", "5 printers".
pub fn count(n: usize, one: &str, many: &str) -> String {
    if n == 1 { format!("1 {one}") } else { format!("{n} {many}") }
}
