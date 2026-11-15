//! The spooler calls that change things (`Spool` for real): the Standard TCP/IP monitor through
//! `XcvData` on `,XcvMonitor Standard TCP/IP Port` (`AddPort`, `ConfigPort` with `PORT_DATA_1`),
//! `SetPrinterW` level 2 (the port, the work-offline attribute), `AddPrinterW`, `DeletePrinter`,
//! the purge, the Print Spooler service, and the spool folder's shadow files. The helper runs
//! these elevated; the app tries the few a user may do (its own jobs, Use online) unelevated
//! first. No driver is loaded into this process here.

use crate::helper::{Local, PortConfig, Spool};
use crate::ports::TcpConfig;
use crate::printers::Spooler;
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Graphics::Printing::*;

/// The spooler as it is.
pub struct RealSpool;

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

fn last() -> u32 {
    // SAFETY: no arguments.
    unsafe { GetLastError() }
}

/// UTF-16 into a fixed field, NUL-terminated; false when it does not fit.
fn fill(field: &mut [u16], s: &str) -> bool {
    let units: Vec<u16> = s.encode_utf16().collect();
    if units.len() >= field.len() {
        return false;
    }
    field.fill(0);
    field[..units.len()].copy_from_slice(&units);
    true
}

/// PORT_DATA_1 for `c`.
fn port_data(c: &PortConfig) -> Option<PORT_DATA_1> {
    // SAFETY: all-zero is a valid PORT_DATA_1.
    let mut d: PORT_DATA_1 = unsafe { std::mem::zeroed() };
    d.dwVersion = 1;
    d.dwProtocol = c.protocol;
    d.cbSize = size_of::<PORT_DATA_1>() as u32;
    d.dwPortNumber = c.port_number;
    d.dwSNMPEnabled = u32::from(c.snmp);
    d.dwSNMPDevIndex = c.snmp_index;
    let ok = fill(&mut d.sztPortName, &c.name) && fill(&mut d.sztHostAddress, &c.host) && fill(&mut d.sztSNMPCommunity, &c.community) && fill(&mut d.sztQueue, &c.queue);
    ok.then_some(d)
}

/// `XcvData` `command` with `c` on the Standard TCP/IP monitor.
fn xcv(command: &str, c: &PortConfig) -> Result<(), u32> {
    let data = port_data(c).ok_or(ERROR_INVALID_PARAMETER)?;
    let h = crate::printers::sys::open(&",XcvMonitor Standard TCP/IP Port".encode_utf16().collect::<Vec<u16>>(), SERVER_ACCESS_ADMINISTER)?;
    let cmd = crate::host::wide(command);
    let mut need = 0u32;
    let mut status = 0u32;
    // SAFETY: the open monitor handle, a NUL-terminated command, PORT_DATA_1 in, nothing out.
    let ok = unsafe { XcvDataW(h.0.Value, cmd.as_ptr(), (&data as *const PORT_DATA_1).cast(), size_of::<PORT_DATA_1>() as u32, std::ptr::null_mut(), 0, &mut need, &mut status) } != 0;
    if !ok {
        return Err(last());
    }
    if status != 0 { Err(status) } else { Ok(()) }
}

/// Change printer `name`'s level 2 record with `f`, then write it back (PRINTER_ALL_ACCESS).
fn change_printer(name: &[u16], f: impl FnOnce(&mut PRINTER_INFO_2W)) -> Result<(), u32> {
    let h = crate::printers::sys::open(name, PRINTER_ALL_ACCESS)?;
    let mut buf = crate::printers::sys::get_printer(&h, 2)?;
    // SAFETY: the buffer holds a PRINTER_INFO_2W written by GetPrinterW; its strings stay inside
    // it, and the one changed points to memory that lives through SetPrinterW.
    unsafe {
        let i = &mut *(buf.as_mut_ptr() as *mut PRINTER_INFO_2W);
        // The security descriptor is left as it is (null means "unchanged").
        i.pSecurityDescriptor = std::ptr::null_mut();
        f(i);
        if SetPrinterW(h.0, 2, buf.as_mut_ptr().cast(), 0) == 0 {
            return Err(last());
        }
    }
    Ok(())
}

/// The steps of a service stop over its calls: the real ones in `service::stop`, the fake's in
/// the tests, so both take the same path. Stopped already: done. On its way down already (a stop
/// asked for before, the state the StopLate words leave the spooler in): only the wait for
/// stopped, since a stopping service takes no stop control (1061, review RVC4: the Restart
/// spooler those words send the user to failed on exactly that, and nothing started the spooler
/// once it was down). Otherwise the stop control (`control` stops the running dependents
/// first), then the wait. A refused control still goes on to the wait when the service is not
/// running (1062) or is stopping by now (1061 while it says STOP_PENDING).
pub fn stop_steps(state: &dyn Fn() -> Result<u32, u32>, control: &mut dyn FnMut() -> Result<(), u32>, wait: &mut dyn FnMut() -> Result<(), u32>) -> Result<(), u32> {
    use windows_sys::Win32::System::Services::{SERVICE_STOP_PENDING, SERVICE_STOPPED};
    match state()? {
        SERVICE_STOPPED => return Ok(()),
        SERVICE_STOP_PENDING => return wait(),
        _ => {}
    }
    if let Err(e) = control()
        && e != ERROR_SERVICE_NOT_ACTIVE
        && !(e == ERROR_SERVICE_CANNOT_ACCEPT_CTRL && state() == Ok(SERVICE_STOP_PENDING))
    {
        return Err(e);
    }
    wait()
}

/// The Print Spooler service, opened for what the jobs need.
mod service {
    use super::*;
    use windows_sys::Win32::System::Services::*;

    pub struct Svc(SC_HANDLE, SC_HANDLE);
    impl Drop for Svc {
        fn drop(&mut self) {
            // SAFETY: opened below, closed once each.
            unsafe {
                CloseServiceHandle(self.1);
                CloseServiceHandle(self.0);
            }
        }
    }

    pub fn open(name: &str, access: u32) -> Result<Svc, u32> {
        let n = crate::host::wide(name);
        // SAFETY: plain service manager calls; the handles are closed by Svc.
        unsafe {
            let scm = OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT);
            if scm.is_null() {
                return Err(last());
            }
            let s = OpenServiceW(scm, n.as_ptr(), access);
            if s.is_null() {
                let e = last();
                CloseServiceHandle(scm);
                return Err(e);
            }
            Ok(Svc(scm, s))
        }
    }

    pub fn state(s: &Svc) -> Result<u32, u32> {
        let mut st: SERVICE_STATUS = unsafe { std::mem::zeroed() };
        // SAFETY: an open service handle and a status struct.
        if unsafe { QueryServiceStatus(s.1, &mut st) } == 0 {
            return Err(last());
        }
        Ok(st.dwCurrentState)
    }

    fn wait_for(s: &Svc, want: u32, wait: Duration) -> Result<(), u32> {
        let end = Instant::now() + wait;
        loop {
            if state(s)? == want {
                return Ok(());
            }
            if Instant::now() >= end {
                return Err(ERROR_SERVICE_REQUEST_TIMEOUT);
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    }

    /// The services running that depend on `s` (Fax, on some PCs): their names.
    fn active_dependents(s: &Svc) -> Vec<String> {
        let mut need = 0u32;
        let mut count = 0u32;
        // SAFETY: a size query, then a buffer of that size.
        unsafe { EnumDependentServicesW(s.1, SERVICE_ACTIVE, std::ptr::null_mut(), 0, &mut need, &mut count) };
        if need == 0 {
            return Vec::new();
        }
        let mut buf = vec![0u64; (need as usize).div_ceil(8)];
        if unsafe { EnumDependentServicesW(s.1, SERVICE_ACTIVE, buf.as_mut_ptr().cast(), (buf.len() * 8) as u32, &mut need, &mut count) } == 0 {
            return Vec::new();
        }
        // SAFETY: `count` ENUM_SERVICE_STATUSW records.
        let rows = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const ENUM_SERVICE_STATUSW, count as usize) };
        rows.iter().map(|r| unsafe { wstr(r.lpServiceName) }).filter(|n| !n.is_empty()).take(crate::helper::MAX_DEPENDENTS).collect()
    }

    /// Stop the service (and the running services that depend on it first), wait up to `wait`.
    /// Every dependent that was running goes into `stopped` before it is stopped, so the caller
    /// starts exactly those again, on every path (AUDIT-1 PRINT-2).
    pub fn stop(name: &str, wait: Duration, stopped: &mut Vec<String>) -> Result<(), u32> {
        let s = open(name, SERVICE_STOP | SERVICE_QUERY_STATUS | SERVICE_ENUMERATE_DEPENDENTS)?;
        stop_steps(
            &|| state(&s),
            &mut || {
                let deps = active_dependents(&s);
                for d in &deps {
                    stopped.push(d.clone());
                    if let Ok(ds) = open(d, SERVICE_STOP | SERVICE_QUERY_STATUS) {
                        let mut st: SERVICE_STATUS = unsafe { std::mem::zeroed() };
                        // SAFETY: an open service handle.
                        unsafe { ControlService(ds.1, SERVICE_CONTROL_STOP, &mut st) };
                        let _ = wait_for(&ds, SERVICE_STOPPED, crate::helper::DEPENDENT_WAIT);
                    }
                }
                let mut st: SERVICE_STATUS = unsafe { std::mem::zeroed() };
                // SAFETY: an open service handle.
                if unsafe { ControlService(s.1, SERVICE_CONTROL_STOP, &mut st) } == 0 { Err(last()) } else { Ok(()) }
            },
            &mut || wait_for(&s, SERVICE_STOPPED, wait),
        )
    }

    /// Wait up to `wait` for the service to reach stopped (a stop asked for already: only its
    /// state is read).
    pub fn wait_stopped(name: &str, wait: Duration) -> Result<(), u32> {
        let s = open(name, SERVICE_QUERY_STATUS)?;
        wait_for(&s, SERVICE_STOPPED, wait)
    }

    pub fn start(name: &str, wait: Duration) -> Result<(), u32> {
        let s = open(name, SERVICE_START | SERVICE_QUERY_STATUS)?;
        if state(&s)? == SERVICE_RUNNING {
            return Ok(());
        }
        // SAFETY: an open service handle, no arguments.
        if unsafe { StartServiceW(s.1, 0, std::ptr::null()) } == 0 {
            let e = last();
            if e != ERROR_SERVICE_ALREADY_RUNNING {
                return Err(e);
            }
        }
        wait_for(&s, SERVICE_RUNNING, wait)
    }

    pub fn set_auto(name: &str) -> Result<(), u32> {
        let s = open(name, SERVICE_CHANGE_CONFIG)?;
        // SAFETY: an open service handle; only the start type changes.
        let ok = unsafe {
            ChangeServiceConfigW(s.1, SERVICE_NO_CHANGE, SERVICE_AUTO_START, SERVICE_NO_CHANGE, std::ptr::null(), std::ptr::null(), std::ptr::null_mut(), std::ptr::null(), std::ptr::null(), std::ptr::null(), std::ptr::null())
        } != 0;
        if ok { Ok(()) } else { Err(last()) }
    }
}

/// The most shadow-file bytes one clear reads (the spooler is stopped meanwhile).
pub const READ_CAP: usize = 64 * 1024 * 1024;

/// The spool folder `dir`: every file's name (10 000 at most) and, for a shadow file, the
/// printer it names or why not. Each shadow file is parsed as it is read and its bytes dropped
/// (AUDIT-1 PRINT-5); past `cap` bytes read in all, the rest are left, not read.
pub fn read_spool_dir(dir: &std::path::Path, cap: usize) -> Result<crate::helper::SpoolFiles, u32> {
    let rd = std::fs::read_dir(dir).map_err(|e| e.raw_os_error().unwrap_or(0) as u32)?;
    let mut out = Vec::new();
    let mut read = 0usize;
    for e in rd.flatten().take(10_000) {
        let Ok(name) = e.file_name().into_string() else { continue };
        if !e.file_type().is_ok_and(|t| t.is_file()) {
            continue;
        }
        let printer = if crate::shd::shadow_stem(&name).is_some() {
            match e.metadata() {
                Ok(m) if m.len() as usize > crate::shd::MAX_SIZE => Err("too big for a shadow file".to_string()),
                Ok(m) if read.saturating_add(m.len() as usize) > cap => Err("not read: the spool folder's shadow files are past what one clear reads".to_string()),
                _ => {
                    // Bounded even if the file grew since its size was read.
                    use std::io::Read;
                    let mut b = Vec::new();
                    match std::fs::File::open(e.path()).and_then(|f| f.take(crate::shd::MAX_SIZE as u64 + 1).read_to_end(&mut b)) {
                        Ok(_) if b.len() > crate::shd::MAX_SIZE => Err("too big for a shadow file".to_string()),
                        Ok(_) => {
                            read = read.saturating_add(b.len());
                            crate::shd::printer_of(&b)
                        }
                        Err(x) => Err(x.to_string()),
                    }
                }
            }
        } else {
            Ok(Vec::new())
        };
        out.push((name, printer));
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

/// The spool folder: the registry's DefaultSpoolDirectory, else `<Windows>\System32\spool\PRINTERS`
/// (from the Windows folder's own call, never an environment variable).
pub fn spool_dir() -> std::path::PathBuf {
    use windows_sys::Win32::System::Registry::*;
    let key = crate::host::wide("SYSTEM\\CurrentControlSet\\Control\\Print\\Printers");
    let name = crate::host::wide("DefaultSpoolDirectory");
    let mut buf = vec![0u16; 1024];
    let mut size = (buf.len() * 2) as u32;
    // SAFETY: a buffer and its size in bytes; a string only.
    let r = unsafe { RegGetValueW(HKEY_LOCAL_MACHINE, key.as_ptr(), name.as_ptr(), RRF_RT_REG_SZ, std::ptr::null_mut(), buf.as_mut_ptr().cast(), &mut size) };
    if r == 0 {
        let len = (size as usize / 2).saturating_sub(1).min(buf.len());
        let s = crate::host::path_from_wide(&buf[..len]);
        if s.is_absolute() {
            return s;
        }
    }
    let mut w = [0u16; 512];
    // SAFETY: a buffer and its length.
    let n = unsafe { windows_sys::Win32::System::SystemInformation::GetSystemWindowsDirectoryW(w.as_mut_ptr(), 512) } as usize;
    crate::host::path_from_wide(&w[..n.min(512)]).join("System32").join("spool").join("PRINTERS")
}

impl Spool for RealSpool {
    fn printers(&self) -> Result<Vec<Local>, u32> {
        match crate::printers::sys::list() {
            crate::printers::List::Printers(v) => Ok(v.into_iter().map(|p| Local { shared: p.connection, name: p.name, port: p.port, attributes: p.attributes }).collect()),
            crate::printers::List::NoSpooler => Err(1722),
            crate::printers::List::Failed(_) => Err(ERROR_GEN_FAILURE),
        }
    }

    fn ports(&self) -> Result<Vec<(String, String)>, u32> {
        crate::ports::sys::list().map(|v| v.into_iter().map(|p| (p.name, p.monitor)).collect())
    }

    fn tcp_config(&self, port: &str) -> Option<TcpConfig> {
        crate::ports::sys::tcp_config(port)
    }

    fn drivers(&self) -> Vec<String> {
        crate::drivers::sys::installed()
    }

    fn add_port(&self, c: &PortConfig) -> Result<(), u32> {
        xcv("AddPort", c)
    }

    fn config_port(&self, c: &PortConfig) -> Result<(), u32> {
        xcv("ConfigPort", c)
    }

    fn set_port(&self, printer: &[u16], port: &str) -> Result<(), u32> {
        let p = crate::host::wide(port);
        change_printer(printer, |i| i.pPortName = p.as_ptr() as *mut u16)
    }

    fn clear_attributes(&self, printer: &[u16], bits: u32) -> Result<(), u32> {
        change_printer(printer, |i| i.Attributes &= !bits)
    }

    fn add_printer(&self, name: &[u16], port: &str, driver: &str) -> Result<(), u32> {
        let mut n = name.to_vec();
        n.push(0);
        let (p, d, pp, dt) = (crate::host::wide(port), crate::host::wide(driver), crate::host::wide("winprint"), crate::host::wide("RAW"));
        // SAFETY: all-zero is a valid PRINTER_INFO_2W; the strings live through the call.
        let mut i: PRINTER_INFO_2W = unsafe { std::mem::zeroed() };
        i.pPrinterName = n.as_mut_ptr();
        i.pPortName = p.as_ptr() as *mut u16;
        i.pDriverName = d.as_ptr() as *mut u16;
        i.pPrintProcessor = pp.as_ptr() as *mut u16;
        i.pDatatype = dt.as_ptr() as *mut u16;
        i.Attributes = crate::printers::ATTR_LOCAL;
        i.Priority = 1;
        i.DefaultPriority = 1;
        // SAFETY: level 2 with the struct above.
        let h = unsafe { AddPrinterW(std::ptr::null(), 2, (&i as *const PRINTER_INFO_2W).cast()) };
        if h.is_null() {
            return Err(last());
        }
        drop(crate::printers::sys::Handle(PRINTER_HANDLE { Value: h }));
        Ok(())
    }

    fn delete_printer(&self, name: &[u16]) -> Result<(), u32> {
        let h = crate::printers::sys::open(name, PRINTER_ALL_ACCESS)?;
        // SAFETY: an open printer handle with delete rights.
        if unsafe { DeletePrinter(h.0) } == 0 { Err(last()) } else { Ok(()) }
    }

    fn purge(&self, printer: &[u16]) -> Result<(), u32> {
        let h = crate::printers::sys::open(printer, PRINTER_ACCESS_ADMINISTER)?;
        // SAFETY: an open printer handle; level 0 with the purge command.
        if unsafe { SetPrinterW(h.0, 0, std::ptr::null_mut(), PRINTER_CONTROL_PURGE) } == 0 { Err(last()) } else { Ok(()) }
    }

    fn job_count(&self, printer: &[u16]) -> Result<u32, u32> {
        crate::printers::sys::read_info2(printer).map(|p| p.jobs)
    }

    fn spooler(&self) -> Spooler {
        crate::printers::sys::spooler()
    }

    fn stop_spooler(&self, wait: Duration, stopped: &mut Vec<String>) -> Result<(), u32> {
        service::stop("Spooler", wait, stopped)
    }

    fn wait_spooler_stopped(&self, wait: Duration) -> Result<(), u32> {
        service::wait_stopped("Spooler", wait)
    }

    fn start_spooler(&self, wait: Duration) -> Result<(), u32> {
        service::start("Spooler", wait)
    }

    fn start_service(&self, name: &str, wait: Duration) -> Result<(), u32> {
        service::start(name, wait)
    }

    fn set_auto_start(&self) -> Result<(), u32> {
        service::set_auto("Spooler")
    }

    fn spool_files(&self) -> Result<crate::helper::SpoolFiles, u32> {
        read_spool_dir(&spool_dir(), READ_CAP)
    }

    fn delete_spool_file(&self, name: &str) -> Result<(), u32> {
        // A plain name of the folder's own (stem of letters and digits, SHD or SPL).
        let ok = name.rsplit_once('.').is_some_and(|(s, e)| (e.eq_ignore_ascii_case("shd") || e.eq_ignore_ascii_case("spl")) && !s.is_empty() && s.len() <= 16 && s.bytes().all(|c| c.is_ascii_alphanumeric()));
        if !ok {
            return Err(ERROR_INVALID_NAME);
        }
        std::fs::remove_file(spool_dir().join(name)).map_err(|e| e.raw_os_error().unwrap_or(0) as u32)
    }

    fn pause(&self, d: Duration) {
        std::thread::sleep(d);
    }
}
