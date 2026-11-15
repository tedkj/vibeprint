//! Live checks for the developer, in a dev-hooks build only (never shipped): the spooler layer
//! and the helper's jobs run for real inside Windows Sandbox, on throwaway printers the check
//! makes itself (never on Ted's own printers or spooler).
//!
//! `--dev-read <out>`: what VibePrint reads (printers, ports, drivers, queues, monitors).
//! `--dev-job <job> <out> <param>=<value>...`: the app's side of one admin step, end to end
//! (pipe, relaunch, identity checks, request, decoder), as a fix runs it.
//! `--dev-page <printer> <out>`: the GDI test page.

use crate::helper::{Job, Outcome, Params, Protocol};
use std::fmt::Write as _;

fn units(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

/// A file `dev-no-purge` beside the exe (only ever made inside Windows Sandbox): queue-clear
/// skips the spooler's purge, so its spool-file path runs.
pub fn no_purge() -> bool {
    std::env::current_exe().ok().and_then(|e| e.parent().map(|d| d.join("dev-no-purge"))).is_some_and(|p| p.is_file())
}

pub fn run(a: &[String]) -> i32 {
    match (a.first().map(String::as_str), a.len()) {
        (Some("--dev-read"), 2) => read(&a[1]),
        (Some("--dev-job"), n) if n >= 3 => job(&a[1], &a[2], &a[3..]),
        (Some("--dev-page"), 3) => page(&a[1], &a[2]),
        _ => 2,
    }
}

fn read(out: &str) -> i32 {
    use crate::controller::System;
    let snap = crate::controller::Real.read();
    let mut s = format!("elevated={}\nspooler={:?}\n", crate::helper::elevated(), snap.spooler);
    let _ = writeln!(s, "monitors={:?}", crate::ports::sys::monitors());
    if let crate::printers::List::Printers(v) = &snap.list {
        for p in v {
            let _ = writeln!(s, "printer {:?} port={:?} driver={:?} status=0x{:x} attributes=0x{:x} jobs={}", p.name_string(), p.port, p.driver, p.status, p.attributes, p.jobs);
            if let Some(Ok(q)) = snap.queues.get(&p.name) {
                for j in q {
                    let _ = writeln!(s, "  job {} {:?} owner={:?} status=0x{:x} pages={}/{} size={} mine={}", j.id, j.document, j.owner, j.status, j.pages_printed, j.total_pages, j.size, j.mine);
                }
            }
        }
    } else {
        let _ = writeln!(s, "list={:?}", snap.list);
    }
    for p in &snap.ports {
        let _ = writeln!(s, "port {:?} monitor={:?} tcp={:?} wsd={:?}", p.name, p.monitor, p.tcp, p.wsd);
    }
    let _ = writeln!(s, "spool_dir={:?}", crate::xcv::spool_dir());
    let _ = std::fs::write(out, s);
    0
}

fn job(name: &str, out: &str, params: &[String]) -> i32 {
    let Some(job) = Job::from_name(name) else { return 2 };
    let mut p = Params::default();
    for kv in params {
        let Some((k, v)) = kv.split_once('=') else { return 2 };
        match k {
            "printer" => p.printer = Some(units(v)),
            "ipv4" => p.ipv4 = v.parse().ok(),
            "protocol" => p.protocol = Some(if v == "lpr" { Protocol::Lpr } else { Protocol::Raw }),
            "snmp" => p.snmp = Some(v == "1"),
            "port" => p.port = Some(v.into()),
            "driver" => p.driver = Some(v.into()),
            "name" => p.name = Some(units(v)),
            "enable" => p.enable = Some(v == "1"),
            "community" => p.community = Some(v.into()),
            _ => return 2,
        }
    }
    let stop = std::sync::atomic::AtomicBool::new(false);
    let t0 = std::time::Instant::now();
    let o = crate::helper::run(job, &p, 0, &stop);
    let mut s = format!("job {name} took {} ms\n", t0.elapsed().as_millis());
    match &o {
        Outcome::Done(r) => {
            let _ = writeln!(s, "outcome Done {}", serde_json::to_string(r).unwrap_or_default());
        }
        other => {
            let _ = writeln!(s, "outcome {other:?}");
        }
    }
    let _ = std::fs::OpenOptions::new().append(true).create(true).open(out).and_then(|mut f| std::io::Write::write_all(&mut f, s.as_bytes()));
    0
}

fn page(printer: &str, out: &str) -> i32 {
    let lines = crate::testpage::lines(printer, "driver", "port", "", &crate::host::computer_name(), "now");
    let r = crate::testpage::print(&units(printer), &lines);
    let _ = std::fs::write(out, format!("page {r:?}\n"));
    i32::from(r.is_err())
}
