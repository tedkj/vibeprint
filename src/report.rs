//! Copy report: plain text of every printer, its port, driver, what the device said, its queue
//! and the real-status line, for the ticket. Built from the same fields the detail panel shows
//! (a report reads everything: no field is left out because the window had no room), ending
//! "VibePrint 0.1.0".

/// One printer's part of the report.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Printer {
    pub name: String,
    pub group: String,
    pub default: bool,
    pub line: String,
    /// (section title, rows of (key, value)).
    pub sections: Vec<(String, Vec<(String, String)>)>,
}

/// The report: a heading, the PC's lines, each printer, the footer.
pub fn text(pc: &[(String, String)], printers: &[Printer]) -> String {
    let mut out = String::from("VibePrint report\n");
    for (k, v) in pc {
        out.push_str(&format!("{k}: {}\n", one_line(v)));
    }
    if printers.is_empty() {
        out.push_str("\nNo printers.\n");
    }
    for p in printers {
        out.push('\n');
        out.push_str(&format!("== {}{} ({})\n", one_line(&p.name), if p.default { " [default]" } else { "" }, p.group));
        out.push_str(&format!("Status: {}\n", one_line(&p.line)));
        for (title, rows) in &p.sections {
            if rows.is_empty() {
                continue;
            }
            out.push_str(&format!("-- {title}\n"));
            for (k, v) in rows {
                out.push_str(&format!("  {k}: {}\n", one_line(v)));
            }
        }
    }
    out.push_str(&format!("\nVibePrint {}\n", crate::VERSION));
    out
}

/// A value on one line (it was cleaned already; line breaks a wrapped value had become spaces).
fn one_line(s: &str) -> String {
    s.replace(['\r', '\n'], " ")
}
