//! The Windows side: the app's folders, the shell (web links, Explorer), the clipboard and the
//! system's light or dark mode. The same small set every VibeWare app carries (copied, not shared).

use std::path::{Path, PathBuf};

/// The app's own folders: settings in %APPDATA%, bulkier local state in %LOCALAPPDATA%.
#[derive(Clone, Debug)]
pub struct Paths {
    pub config: PathBuf,
    pub local_data: PathBuf,
}

pub const APP_ID: &str = "com.tedkj.vibeprint";

pub fn paths() -> Paths {
    use windows_sys::Win32::UI::Shell::{FOLDERID_LocalAppData, FOLDERID_RoamingAppData};
    let env = |k: &str| std::env::var_os(k).map(PathBuf::from).unwrap_or_default();
    Paths {
        config: known_folder(&FOLDERID_RoamingAppData).unwrap_or_else(|| env("APPDATA")).join(APP_ID),
        local_data: known_folder(&FOLDERID_LocalAppData).unwrap_or_else(|| env("LOCALAPPDATA")).join(APP_ID),
    }
}

pub fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

pub fn wide_path(p: &Path) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    p.as_os_str().encode_wide().chain(std::iter::once(0)).collect()
}

pub fn known_folder(id: &windows_sys::core::GUID) -> Option<PathBuf> {
    use windows_sys::Win32::System::Com::CoTaskMemFree;
    use windows_sys::Win32::UI::Shell::SHGetKnownFolderPath;
    unsafe {
        let mut p: windows_sys::core::PWSTR = std::ptr::null_mut();
        let ok = SHGetKnownFolderPath(id, 0, std::ptr::null_mut(), &mut p) == 0;
        let out = if ok && !p.is_null() {
            let len = (0..).take_while(|&i| *p.add(i) != 0).count();
            Some(path_from_wide(std::slice::from_raw_parts(p, len)))
        } else {
            None
        };
        CoTaskMemFree(p as *const _);
        out
    }
}

/// A web page in the default browser (About's link). https only: nothing else is ever handed
/// to the shell from here.
pub fn open_url(url: &str) -> Result<(), String> {
    if !url.starts_with("https://") {
        return Err(format!("Not a web address: {url}"));
    }
    shell_open(url)
}

/// A printer's own web page (mDNS `adminurl`): http or https, an absolute URL of plain URL
/// characters only, no user info (which hides the real host), at most 2 KiB.
pub fn safe_web_url(url: &str) -> Option<String> {
    let u = url.trim();
    let lower = u.to_ascii_lowercase();
    if !(lower.starts_with("http://") || lower.starts_with("https://")) || u.len() > 2048 {
        return None;
    }
    if !u.chars().all(|c| c.is_ascii_graphic() && !matches!(c, '"' | '<' | '>' | '\\' | '^' | '`' | '{' | '|' | '}')) {
        return None;
    }
    let after = &u[u.find("://")? + 3..];
    let host = after.split(['/', '?', '#']).next().unwrap_or("");
    (!host.is_empty() && !host.contains('@')).then(|| u.to_string())
}

/// A printer's web page in the default browser (http or https only, checked by `safe_web_url`).
pub fn open_web(url: &str) -> Result<(), String> {
    match safe_web_url(url) {
        Some(u) => shell_open(&u),
        None => Err(format!("Not a web address: {}", crate::text::clean_max(url, 80))),
    }
}

/// Windows' own Printers & scanners page (Add printer can fetch a driver there).
pub fn open_printer_settings() -> Result<(), String> {
    shell_open("ms-settings:printers")
}

/// The window the UAC prompt goes over (the app's own, when it is active).
pub fn active_window() -> isize {
    // SAFETY: no arguments.
    unsafe { windows_sys::Win32::UI::Input::KeyboardAndMouse::GetActiveWindow() as isize }
}

/// This thread's window is minimized (the timed probes wait then): one of its visible top-level
/// windows is iconic and none is shown. Call on the window's (UI) thread.
pub fn minimized() -> bool {
    use windows_sys::Win32::Foundation::{HWND, LPARAM};
    use windows_sys::Win32::System::Threading::GetCurrentThreadId;
    use windows_sys::Win32::UI::WindowsAndMessaging::{EnumThreadWindows, IsIconic, IsWindowVisible};
    // bit 0: an iconic window, bit 1: a shown one.
    unsafe extern "system" fn each(h: HWND, l: LPARAM) -> i32 {
        // SAFETY: `l` is the address of the u32 below, alive through EnumThreadWindows.
        unsafe {
            let seen = l as *mut u32;
            if IsWindowVisible(h) != 0 {
                *seen |= if IsIconic(h) != 0 { 1 } else { 2 };
            }
        }
        1
    }
    let mut seen = 0u32;
    // SAFETY: the callback above and the address of `seen`.
    unsafe { EnumThreadWindows(GetCurrentThreadId(), Some(each), &mut seen as *mut u32 as LPARAM) };
    seen == 1
}

/// Unix seconds now.
pub fn now_unix() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// The local time's offset from UTC at unix second `t` (daylight saving included).
pub fn utc_offset(t: i64) -> i64 {
    use windows_sys::Win32::Foundation::{FILETIME, SYSTEMTIME};
    use windows_sys::Win32::System::Time::{FileTimeToSystemTime, SystemTimeToFileTime, SystemTimeToTzSpecificLocalTime};
    let ft_of = |t: i64| {
        let v = ((t + 11_644_473_600) as u64) * 10_000_000;
        FILETIME { dwLowDateTime: v as u32, dwHighDateTime: (v >> 32) as u32 }
    };
    // SAFETY: plain structs; the local zone is the system's.
    unsafe {
        let ft = ft_of(t);
        let mut utc: SYSTEMTIME = std::mem::zeroed();
        let mut local: SYSTEMTIME = std::mem::zeroed();
        if FileTimeToSystemTime(&ft, &mut utc) == 0 || SystemTimeToTzSpecificLocalTime(std::ptr::null(), &utc, &mut local) == 0 {
            return 0;
        }
        let mut lf = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
        if SystemTimeToFileTime(&local, &mut lf) == 0 {
            return 0;
        }
        let l = (((lf.dwHighDateTime as u64) << 32) | lf.dwLowDateTime as u64) / 10_000_000;
        l as i64 - 11_644_473_600 - t
    }
}

/// This PC's name (NetBIOS), for the test page and the report.
pub fn computer_name() -> String {
    use windows_sys::Win32::System::SystemInformation::{ComputerNamePhysicalNetBIOS, GetComputerNameExW};
    let mut buf = vec![0u16; 256];
    let mut len = buf.len() as u32;
    // SAFETY: a buffer and its length in characters.
    if unsafe { GetComputerNameExW(ComputerNamePhysicalNetBIOS, buf.as_mut_ptr(), &mut len) } == 0 {
        return String::new();
    }
    crate::text::clean(&String::from_utf16_lossy(&buf[..len as usize]))
}

/// This PC's MachineGuid (the journal keeps each PC's fixes apart), lower case; empty when it
/// cannot be read.
pub fn machine_guid() -> String {
    use windows_sys::Win32::System::Registry::{HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ, RRF_SUBKEY_WOW6464KEY, RegGetValueW};
    let key = wide("SOFTWARE\\Microsoft\\Cryptography");
    let name = wide("MachineGuid");
    let mut buf = vec![0u16; 64];
    let mut size = (buf.len() * 2) as u32;
    // SAFETY: a buffer and its size in bytes; a string only, from the 64-bit view.
    let r = unsafe { RegGetValueW(HKEY_LOCAL_MACHINE, key.as_ptr(), name.as_ptr(), RRF_RT_REG_SZ | RRF_SUBKEY_WOW6464KEY, std::ptr::null_mut(), buf.as_mut_ptr().cast(), &mut size) };
    if r != 0 {
        return String::new();
    }
    let s = String::from_utf16_lossy(&buf[..(size as usize / 2).saturating_sub(1).min(buf.len())]).to_ascii_lowercase();
    if s.len() <= 40 && s.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-') { s } else { String::new() }
}

/// "14:02:11" at unix second `t`, local time at offset `off`.
pub fn clock(t: i64, off: i64) -> String {
    let d = (t + off).rem_euclid(86_400);
    format!("{:02}:{:02}:{:02}", d / 3600, d % 3600 / 60, d % 60)
}

/// "22.10.2026 14:02" at unix second `t`, local time at offset `off`.
pub fn date_time(t: i64, off: i64) -> String {
    let l = t + off;
    let days = l.div_euclid(86_400);
    let (y, m, d) = civil(days);
    let s = l.rem_euclid(86_400);
    format!("{d:02}.{m:02}.{y} {:02}:{:02}", s / 3600, s % 3600 / 60)
}

/// "22.10.2026".
pub fn date(t: i64, off: i64) -> String {
    let (y, m, d) = civil((t + off).div_euclid(86_400));
    format!("{d:02}.{m:02}.{y}")
}

/// Days since 1970-01-01 as (year, month, day) (Howard Hinnant's algorithm).
fn civil(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// A folder in Explorer (or a file shown selected in its folder, with `select`).
pub fn reveal(path: &Path, select: bool) -> Result<(), String> {
    use std::os::windows::process::CommandExt;
    explorer_command()?.raw_arg(reveal_arg(path, select)).spawn().map(|_| ()).map_err(|e| format!("Could not open Explorer: {e}"))
}

/// Explorer by its full path (`<Windows>\explorer.exe`), started in System32. Every program the
/// app starts goes by its full path: a bare "explorer.exe" is looked for in this exe's own folder
/// (and the current one) first, Rust's std as CreateProcess, so on a stick or in the per-user
/// install folder anyone's file of that name would run. Started in System32, the child neither
/// searches nor holds the exe's folder.
pub fn explorer_command() -> Result<std::process::Command, String> {
    let win = windows_dir(false).ok_or("Could not open Explorer: the Windows folder is not known")?;
    let sys = windows_dir(true).ok_or("Could not open Explorer: System32 is not known")?;
    let mut c = std::process::Command::new(win.join("explorer.exe"));
    c.current_dir(sys);
    Ok(c)
}

/// Windows' own folder (`GetSystemWindowsDirectoryW`) or System32 (`GetSystemDirectoryW`), as
/// Windows names them: never from the environment, never relative.
pub fn windows_dir(system: bool) -> Option<PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::System::SystemInformation::{GetSystemDirectoryW, GetSystemWindowsDirectoryW};
    let mut buf = [0u16; 1024];
    // SAFETY: a buffer and its length in units.
    let n = unsafe { if system { GetSystemDirectoryW(buf.as_mut_ptr(), buf.len() as u32) } else { GetSystemWindowsDirectoryW(buf.as_mut_ptr(), buf.len() as u32) } } as usize;
    (n > 0 && n < buf.len()).then(|| PathBuf::from(std::ffi::OsString::from_wide(&buf[..n]))).filter(|p| p.is_absolute())
}

/// Explorer parses its own command line: the path goes in quotes (after /select, when
/// selecting). Built from the path's exact units, never a lossy string (a name with a lone
/// surrogate must still be found: VibeRename RR-7); `"` cannot be in a Windows name.
pub fn reveal_arg(path: &Path, select: bool) -> std::ffi::OsString {
    let mut arg = std::ffi::OsString::from(if select { "/select,\"" } else { "\"" });
    arg.push(path.as_os_str());
    arg.push("\"");
    arg
}

/// A path Windows handed over as UTF-16 units, kept exactly (a lone surrogate included).
pub fn path_from_wide(units: &[u16]) -> PathBuf {
    use std::os::windows::ffi::OsStringExt;
    PathBuf::from(std::ffi::OsString::from_wide(units))
}

/// ShellExecuteEx with the shell's own error dialogs suppressed: a failure comes back as an
/// error here, it never parks a modal box on the UI.
fn shell_open(target: &str) -> Result<(), String> {
    use windows_sys::Win32::System::Com::{COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE, CoInitializeEx};
    use windows_sys::Win32::UI::Shell::{SEE_MASK_FLAG_NO_UI, SEE_MASK_NOASYNC, SHELLEXECUTEINFOW, ShellExecuteExW};
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
    let file = wide(target);
    unsafe {
        CoInitializeEx(std::ptr::null(), (COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) as u32);
        let mut info: SHELLEXECUTEINFOW = std::mem::zeroed();
        info.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
        info.fMask = SEE_MASK_FLAG_NO_UI | SEE_MASK_NOASYNC;
        info.lpFile = file.as_ptr();
        info.nShow = SW_SHOWNORMAL;
        if ShellExecuteExW(&mut info) == 0 {
            return Err(format!("Could not open {target}: {}", std::io::Error::last_os_error()));
        }
    }
    Ok(())
}

/// Text onto the clipboard (reports, paths, messages the window cannot let the user select).
pub fn copy_text(text: &str) -> Result<(), String> {
    use windows_sys::Win32::Foundation::GlobalFree;
    use windows_sys::Win32::System::DataExchange::{CloseClipboard, EmptyClipboard, OpenClipboard, SetClipboardData};
    use windows_sys::Win32::System::Memory::{GMEM_MOVEABLE, GlobalAlloc, GlobalLock, GlobalUnlock};
    use windows_sys::Win32::System::Ole::CF_UNICODETEXT;
    let w = wide(&clipboard_text(text));
    let fail = |what: &str| format!("Could not copy ({what}): {}", std::io::Error::last_os_error());
    unsafe {
        // Another program (a clipboard manager) may hold it for a moment: a few short tries.
        let mut open = OpenClipboard(std::ptr::null_mut()) != 0;
        for _ in 0..4 {
            if open {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(15));
            open = OpenClipboard(std::ptr::null_mut()) != 0;
        }
        if !open {
            return Err(fail("the clipboard is busy"));
        }
        let put = (|| {
            if EmptyClipboard() == 0 {
                return Err(fail("empty"));
            }
            let h = GlobalAlloc(GMEM_MOVEABLE, w.len() * 2);
            if h.is_null() {
                return Err(fail("memory"));
            }
            let p = GlobalLock(h) as *mut u16;
            if p.is_null() {
                let e = fail("memory"); // before GlobalFree, which may overwrite the last error
                GlobalFree(h);
                return Err(e);
            }
            std::ptr::copy_nonoverlapping(w.as_ptr(), p, w.len());
            GlobalUnlock(h);
            // The clipboard owns the memory once this succeeds; only a failure leaves it ours.
            if SetClipboardData(CF_UNICODETEXT as u32, h).is_null() {
                let e = fail("set");
                GlobalFree(h);
                return Err(e);
            }
            Ok(())
        })();
        CloseClipboard();
        put
    }
}

/// Windows text on the clipboard ends its lines with CRLF (Notepad and others expect it).
pub fn clipboard_text(text: &str) -> String {
    text.replace("\r\n", "\n").replace('\n', "\r\n")
}

/// Windows' app mode (Settings > Personalization > Colors), dark when it cannot be read.
pub fn system_dark() -> bool {
    use windows_sys::Win32::System::Registry::{HKEY_CURRENT_USER, RRF_RT_REG_DWORD, RegGetValueW};
    let key = wide("Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize");
    let value = wide("AppsUseLightTheme");
    let mut data: u32 = 1;
    let mut size = std::mem::size_of::<u32>() as u32;
    let r = unsafe {
        RegGetValueW(HKEY_CURRENT_USER, key.as_ptr(), value.as_ptr(), RRF_RT_REG_DWORD, std::ptr::null_mut(), (&mut data as *mut u32).cast(), &mut size)
    };
    r != 0 || data == 0
}

/// A rectangle in physical pixels, edges as Win32's RECT has them (right and bottom exclusive).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Px {
    pub left: i32,
    pub top: i32,
    pub right: i32,
    pub bottom: i32,
}

/// Where a window's visible frame goes so it fits the monitor's work area (X15A11Y-3): a side
/// longer than the area's shrinks to it, then the frame moves inside the area (left and top edges
/// first). None when it already fits. The window's minimum size still wins: Windows keeps it
/// (WM_GETMINMAXINFO), so a window whose minimum is bigger than the area ends up at its minimum.
pub fn fit_frame(frame: Px, work: Px) -> Option<Px> {
    let w = (frame.right - frame.left).min(work.right - work.left);
    let h = (frame.bottom - frame.top).min(work.bottom - work.top);
    let left = frame.left.min(work.right - w).max(work.left);
    let top = frame.top.min(work.bottom - h).max(work.top);
    let fitted = Px { left, top, right: left + w, bottom: top + h };
    (fitted != frame).then_some(fitted)
}

/// A monitor's work area in workspace coordinates, the ones a window's restore rectangle
/// (WINDOWPLACEMENT) is in: (0, 0) is the corner of the primary monitor's work area, so a
/// taskbar at the top or left of the primary monitor shifts every monitor's area by its size.
pub fn workspace_area(work: Px, primary_monitor: Px, primary_work: Px) -> Px {
    let (dx, dy) = (primary_work.left - primary_monitor.left, primary_work.top - primary_monitor.top);
    Px { left: work.left - dx, top: work.top - dy, right: work.right - dx, bottom: work.bottom - dy }
}

/// Fit a window that has just opened into its monitor's work area (X15A11Y-3; `fit_frame`):
/// the window opens at its preferred size, sized for a big screen at 100 %, which on a 1080p
/// laptop at 150 % runs past the taskbar and puts the toasts and the status line out of sight.
/// All in physical pixels (the process is per-monitor DPI aware, so no scaling): the work area of
/// the monitor the window is on, and its visible frame (DWM's, without the invisible resize
/// borders, which go back on around it). A maximized start gets its restore size fitted instead,
/// and a minimized one waits until it is restored (X15RFTP-4). None while the window is not on
/// screen yet or minimized (try again later); else whether it changed.
pub fn fit_to_work_area(hwnd: isize) -> Option<bool> {
    use windows_sys::Win32::Foundation::{POINT, RECT};
    use windows_sys::Win32::Graphics::Dwm::{DWMWA_EXTENDED_FRAME_BOUNDS, DwmGetWindowAttribute};
    use windows_sys::Win32::Graphics::Gdi::{GetMonitorInfoW, HMONITOR, MONITOR_DEFAULTTONEAREST, MONITOR_DEFAULTTOPRIMARY, MONITORINFO, MonitorFromPoint, MonitorFromWindow};
    use windows_sys::Win32::UI::WindowsAndMessaging::{GetWindowPlacement, GetWindowRect, IsIconic, IsWindowVisible, IsZoomed, SWP_NOACTIVATE, SWP_NOZORDER, SetWindowPlacement, SetWindowPos, WINDOWPLACEMENT};
    let hwnd = hwnd as windows_sys::Win32::Foundation::HWND;
    let px = |r: RECT| Px { left: r.left, top: r.top, right: r.right, bottom: r.bottom };
    // SAFETY: plain Win32 calls on the app's own window handle, each with a struct of its own
    // size; a call that fails leaves the window as it is.
    unsafe {
        let monitor = |m: HMONITOR| -> Option<(Px, Px)> {
            let mut mi: MONITORINFO = std::mem::zeroed();
            mi.cbSize = size_of::<MONITORINFO>() as u32;
            (GetMonitorInfoW(m, &mut mi) != 0).then(|| (px(mi.rcMonitor), px(mi.rcWork)))
        };
        if IsWindowVisible(hwnd) == 0 || IsIconic(hwnd) != 0 {
            return None;
        }
        let Some((_, work)) = monitor(MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST)) else { return Some(false) };
        if IsZoomed(hwnd) != 0 {
            let mut wp: WINDOWPLACEMENT = std::mem::zeroed();
            wp.length = size_of::<WINDOWPLACEMENT>() as u32;
            let Some((pm, pw)) = monitor(MonitorFromPoint(POINT { x: 0, y: 0 }, MONITOR_DEFAULTTOPRIMARY)) else { return Some(false) };
            if GetWindowPlacement(hwnd, &mut wp) == 0 {
                return Some(false);
            }
            let Some(to) = fit_frame(px(wp.rcNormalPosition), workspace_area(work, pm, pw)) else { return Some(false) };
            wp.rcNormalPosition = RECT { left: to.left, top: to.top, right: to.right, bottom: to.bottom };
            return Some(SetWindowPlacement(hwnd, &wp) != 0);
        }
        let mut outer: RECT = std::mem::zeroed();
        if GetWindowRect(hwnd, &mut outer) == 0 {
            return Some(false);
        }
        let mut seen = outer;
        if DwmGetWindowAttribute(hwnd, DWMWA_EXTENDED_FRAME_BOUNDS as u32, (&mut seen as *mut RECT).cast(), size_of::<RECT>() as u32) != 0 {
            seen = outer;
        }
        let Some(to) = fit_frame(px(seen), work) else { return Some(false) };
        let (l, t, r, b) = (seen.left - outer.left, seen.top - outer.top, outer.right - seen.right, outer.bottom - seen.bottom);
        Some(SetWindowPos(hwnd, std::ptr::null_mut(), to.left - l, to.top - t, to.right - to.left + l + r, to.bottom - to.top + t + b, SWP_NOZORDER | SWP_NOACTIVATE) != 0)
    }
}
