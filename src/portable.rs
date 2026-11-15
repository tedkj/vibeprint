//! Portable mode, for the field kit's USB stick (SPEC section 6). Decided at start, before any
//! prefs are read: VibePrint is portable when a file named `portable` (exactly, any case, no
//! extension; a folder does not count) sits next to the exe, or the exe's volume is removable
//! (`GetDriveTypeW` DRIVE_REMOVABLE, or its disk reports a USB, SD or MMC bus through
//! `IOCTL_STORAGE_QUERY_PROPERTY` on the volume opened with no access rights). Then its
//! settings live in `<exe folder>\VibePrint-data\`, created on the first write, and nothing goes to
//! the PC's profile or registry. A folder it cannot write to keeps the settings in memory.

use std::path::{Path, PathBuf};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Installed (or run from a fixed disk): the profile's folders.
    Installed,
    /// Portable, settings beside the exe.
    Portable { dir: PathBuf },
    /// Portable, but the exe's folder cannot be written: settings in memory only.
    ReadOnly { dir: PathBuf },
}

impl Mode {
    pub fn portable(&self) -> bool {
        !matches!(self, Mode::Installed)
    }
}

/// The marker's name: `portable`, any case, nothing more.
pub fn is_marker(name: &std::ffi::OsStr) -> bool {
    name.to_str().is_some_and(|n| n.eq_ignore_ascii_case("portable"))
}

/// A file (not a folder) named `portable` in `dir`.
pub fn has_marker(dir: &Path) -> bool {
    let Ok(rd) = std::fs::read_dir(dir) else { return false };
    rd.flatten().take(10_000).any(|e| is_marker(&e.file_name()) && e.file_type().is_ok_and(|t| t.is_file()))
}

/// The bus types that make a disk a stick or a card.
pub fn removable_bus(bus: i32) -> bool {
    use windows_sys::Win32::Storage::FileSystem::{BusTypeMmc, BusTypeSd, BusTypeUsb};
    bus == BusTypeUsb || bus == BusTypeSd || bus == BusTypeMmc
}

/// The exe's volume is removable: by drive type, or by its disk's bus.
pub fn on_removable(exe: &Path) -> bool {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::*;
    use windows_sys::Win32::System::IO::DeviceIoControl;
    use windows_sys::Win32::System::Ioctl::{IOCTL_STORAGE_QUERY_PROPERTY, PropertyStandardQuery, STORAGE_DEVICE_DESCRIPTOR, STORAGE_PROPERTY_QUERY, StorageDeviceProperty};
    let mut p: Vec<u16> = exe.as_os_str().encode_wide().collect();
    p.push(0);
    let mut root = vec![0u16; 1024];
    // SAFETY: NUL-terminated in, a buffer and its length out.
    if unsafe { GetVolumePathNameW(p.as_ptr(), root.as_mut_ptr(), root.len() as u32) } == 0 {
        return false;
    }
    // SAFETY: the root just read.
    if unsafe { GetDriveTypeW(root.as_ptr()) } == 2 {
        return true; // DRIVE_REMOVABLE
    }
    let mut name = vec![0u16; 64];
    // SAFETY: the root (NUL-terminated), a buffer of 50+ units.
    if unsafe { GetVolumeNameForVolumeMountPointW(root.as_ptr(), name.as_mut_ptr(), name.len() as u32) } == 0 {
        return false;
    }
    // `\\?\Volume{…}\` without its last backslash opens the volume itself.
    let n = name.iter().position(|&c| c == 0).unwrap_or(0);
    let mut dev = name[..n.saturating_sub(1)].to_vec();
    dev.push(0);
    // SAFETY: no access rights asked: a query of the device only; closed below.
    let h = unsafe { CreateFileW(dev.as_ptr(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE, std::ptr::null(), OPEN_EXISTING, 0, std::ptr::null_mut()) };
    if h == INVALID_HANDLE_VALUE {
        return false;
    }
    let q = STORAGE_PROPERTY_QUERY { PropertyId: StorageDeviceProperty, QueryType: PropertyStandardQuery, AdditionalParameters: [0] };
    let mut out = [0u64; 128];
    let mut got = 0u32;
    // SAFETY: the query in, a 1 KiB aligned buffer out; the handle closed below.
    let ok = unsafe { DeviceIoControl(h, IOCTL_STORAGE_QUERY_PROPERTY, (&q as *const STORAGE_PROPERTY_QUERY).cast(), size_of::<STORAGE_PROPERTY_QUERY>() as u32, out.as_mut_ptr().cast(), 1024, &mut got, std::ptr::null_mut()) } != 0;
    unsafe { CloseHandle(h) };
    if !ok || (got as usize) < size_of::<STORAGE_DEVICE_DESCRIPTOR>() {
        return false;
    }
    // SAFETY: the buffer holds a descriptor of at least its own size, 8-aligned.
    let d = unsafe { &*(out.as_ptr() as *const STORAGE_DEVICE_DESCRIPTOR) };
    removable_bus(d.BusType)
}

/// The folder can be written: a probe file of this process's own, made create-new and removed.
pub fn writable(dir: &Path) -> bool {
    let probe = dir.join(format!("VibePrint-write-test.{}.tmp", std::process::id()));
    match std::fs::OpenOptions::new().write(true).create_new(true).open(&probe) {
        Ok(f) => {
            drop(f);
            let _ = std::fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

/// The mode for an exe at `exe`.
pub fn detect(exe: &Path) -> Mode {
    let Some(dir) = exe.parent().map(Path::to_path_buf) else { return Mode::Installed };
    if !(has_marker(&dir) || on_removable(exe)) {
        return Mode::Installed;
    }
    if writable(&dir) { Mode::Portable { dir } } else { Mode::ReadOnly { dir } }
}

/// The settings folders of a portable copy.
pub fn paths(dir: &Path) -> crate::host::Paths {
    let data = dir.join("VibePrint-data");
    crate::host::Paths { config: data.join("config"), local_data: data.join("local") }
}
