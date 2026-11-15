//! A small JSON file the app remembers things in (theme, window choices, recent entries).
//! Missing or garbled (a file over `MAX_FILE` included, never read whole) means defaults, but a garbled file is never written over: the first save
//! keeps it aside as `prefs.json.broken` (replacing an older copy; VibeBackup BA-3), and the
//! window says so (a file that turns garbled while the window is open too: `take_garbled`). A
//! file that is there but cannot be read right now is never overwritten. The window's changes
//! are kept as changes, not as a merged value: every write reads the file afresh and puts the
//! unwritten changes onto what it read, so another instance's prefs stay, even when this window
//! started on defaults because the file could not be read then (R2-TRACE-1, R2-SCAN-1). Writes
//! happen off the UI thread, whole or not at all.

use serde::Serialize;
use serde::de::DeserializeOwned;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

/// One change of this window's to the prefs (set a field, remember an entry), applied onto the
/// newest prefs right before each write.
pub type Change<T> = Arc<dyn Fn(&mut T) + Send + Sync>;

/// Room when the prefs would outgrow `MAX_FILE` (RIB-1): drop about this many bytes' worth of
/// what may go, and say how many items went (0: nothing more may go).
pub type Fit<T> = Arc<dyn Fn(&mut T, usize) -> usize + Send + Sync>;

pub struct Store<T> {
    path: PathBuf,
    /// This window's changes that are not in the file yet, oldest first.
    changes: Arc<Mutex<Vec<Change<T>>>>,
    /// This window's prefs as last loaded or written: what the changes go onto when the file is
    /// missing or garbled.
    own: Arc<Mutex<T>>,
    write: Arc<Mutex<()>>,
    /// `load` found the file garbled.
    broken: Arc<AtomicBool>,
    /// The garbled file `load` found (told at start); cleared once a good file is written.
    noted: Arc<AtomicBool>,
    /// A garbled file was kept aside and the good one not written yet.
    aside: Arc<AtomicBool>,
    /// A garbled file was kept aside and replaced that nobody has told the user about yet.
    garbled_new: Arc<AtomicBool>,
    /// No file at all (a portable copy on a stick that cannot be written): the changes live in
    /// memory for this run only.
    memory: bool,
    /// How a write that would pass `MAX_FILE` makes room (none: it is not written).
    fit: Option<Fit<T>>,
    /// Items `fit` dropped from written files that nobody has told the user about yet.
    trimmed: Arc<AtomicUsize>,
}

impl<T> Clone for Store<T> {
    fn clone(&self) -> Self {
        Store {
            path: self.path.clone(),
            changes: self.changes.clone(),
            own: self.own.clone(),
            write: self.write.clone(),
            broken: self.broken.clone(),
            noted: self.noted.clone(),
            aside: self.aside.clone(),
            garbled_new: self.garbled_new.clone(),
            memory: self.memory,
            fit: self.fit.clone(),
            trimmed: self.trimmed.clone(),
        }
    }
}

/// A lock that a panic elsewhere does not turn into a second one (the test rigs flush in Drop).
fn lock<X>(m: &Mutex<X>) -> MutexGuard<'_, X> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Where a garbled file is kept: `prefs.json.broken`.
pub fn broken_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".broken");
    path.with_file_name(name)
}

/// The largest prefs or journal file read (IN-VibePrint-2), and written (RIB-1): prefs are a few
/// KiB; a full PC's journal is about 380 KB, so a stick's journal of many PCs makes room by
/// dropping the oldest entries of the other PCs (`Store::with_fit`, said by a toast). Anything
/// larger (not ours) is garbled.
pub const MAX_FILE: u64 = 4 * 1024 * 1024;

/// A file's bytes, at most MAX_FILE and one more: memory stays bounded whatever its size.
fn read_capped(path: &Path) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let mut b = Vec::new();
    std::fs::File::open(path)?.take(MAX_FILE + 1).read_to_end(&mut b)?;
    Ok(b)
}

/// The prefs in `b`; a file over MAX_FILE is garbled like one that is not JSON.
fn parse<T: DeserializeOwned>(b: &[u8]) -> Option<T> {
    if b.len() as u64 > MAX_FILE {
        return None;
    }
    serde_json::from_slice(b).ok()
}

/// Defaults when the file is missing or garbled; an error when it is there but unreadable now.
pub fn read<T: DeserializeOwned + Default>(path: &Path) -> std::io::Result<T> {
    match read_capped(path) {
        Ok(b) => Ok(parse(&b).unwrap_or_default()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound || e.kind() == std::io::ErrorKind::InvalidData => Ok(T::default()),
        Err(e) => Err(e),
    }
}

/// Whole or not at all: a crash or a power cut mid-write leaves the old file. The temp file sits
/// beside the target and is this process's own (named by its id, and made create-new), so
/// neither a second instance writing at the same moment nor a file of the user's that happens to
/// have its name is ever written into or removed: a name already taken moves on to the next.
/// It is on the disk (`sync_all`, FlushFileBuffers) before it takes the name, so a power cut
/// right after cannot leave the name on zeros (FS10), and it is removed on every error. std's
/// rename replaces with POSIX semantics on NTFS: a reader holding the file open (another
/// instance, a scanner) does not block it, where MoveFileExW is refused. The new file takes the
/// folder's attributes and ACL, as before.
pub fn write_atomic(path: &Path, body: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let pid = std::process::id();
    let mut n = 0;
    let (tmp, mut file) = loop {
        let tmp = path.with_extension(if n == 0 { format!("{pid}.tmp") } else { format!("{pid}-{n}.tmp") });
        match std::fs::OpenOptions::new().write(true).create_new(true).open(&tmp) {
            Ok(f) => break (tmp, f),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && n < 20 => n += 1,
            Err(e) => return Err(e),
        }
    };
    let r = file.write_all(body).and_then(|_| file.sync_all());
    drop(file);
    let r = r.and_then(|_| std::fs::rename(&tmp, path));
    if r.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    r
}

impl<T: Serialize + DeserializeOwned + Default + Clone + PartialEq + Send + 'static> Store<T> {
    pub fn new(path: PathBuf) -> Store<T> {
        Store {
            path,
            changes: Default::default(),
            own: Default::default(),
            write: Default::default(),
            broken: Default::default(),
            noted: Default::default(),
            aside: Default::default(),
            garbled_new: Default::default(),
            memory: false,
            fit: None,
            trimmed: Default::default(),
        }
    }

    /// How a write that would pass `MAX_FILE` makes room. Without one such a write does not
    /// happen (the changes wait): the app never writes a file it would refuse to read.
    pub fn with_fit(mut self, fit: Fit<T>) -> Store<T> {
        self.fit = Some(fit);
        self
    }

    /// How many items were dropped to keep written files under `MAX_FILE` since this was last
    /// asked: the window says so once.
    pub fn take_trimmed(&self) -> usize {
        self.trimmed.swap(0, Ordering::SeqCst)
    }

    /// `v` as written: at most `MAX_FILE` bytes, made to fit by `fit`; with how many items went.
    /// None when it cannot fit.
    fn body(&self, v: &mut T) -> Option<(Vec<u8>, usize)> {
        let mut dropped = 0;
        loop {
            let b = serde_json::to_vec_pretty(v).ok()?;
            if b.len() as u64 <= MAX_FILE {
                return Some((b, dropped));
            }
            let n = self.fit.as_ref().map_or(0, |f| f(v, b.len() - MAX_FILE as usize));
            if n == 0 {
                return None;
            }
            dropped += n;
        }
    }

    /// A store with no file: defaults at start, changes kept in memory, nothing ever written.
    pub fn memory() -> Store<T> {
        Store { memory: true, ..Store::new(PathBuf::new()) }
    }

    /// No file behind it (`memory`).
    pub fn in_memory(&self) -> bool {
        self.memory
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The prefs, defaults when missing, garbled or unreadable now. Reads only; a garbled file
    /// is noted (`broken`) and kept aside by the first write.
    pub fn load(&self) -> T {
        if self.memory {
            return lock(&self.own).clone();
        }
        let v = match read_capped(&self.path) {
            Ok(b) => parse(&b).unwrap_or_else(|| {
                self.broken.store(true, Ordering::Relaxed);
                self.noted.store(true, Ordering::SeqCst);
                T::default()
            }),
            Err(_) => T::default(),
        };
        *lock(&self.own) = v.clone();
        v
    }

    /// `load` found the file garbled (the window tells the user).
    pub fn broken(&self) -> bool {
        self.broken.load(Ordering::Relaxed)
    }

    /// Whether a garbled file was kept aside and replaced since this was last asked (not the one
    /// `load` found at start, which the window tells by `broken`): the window says so once.
    pub fn take_garbled(&self) -> bool {
        self.garbled_new.swap(false, Ordering::SeqCst)
    }

    /// One change of this window's: kept until it is in the file, and written now (`flush`). Call
    /// it off the UI thread (it reads the file).
    pub fn change(&self, f: Change<T>) {
        lock(&self.changes).push(f);
        self.flush();
    }

    /// Write the unwritten changes: read the file afresh, put every change onto it in order,
    /// write the result, and only then forget the changes. While the file cannot be read nothing
    /// is written and the changes wait for the next write (one still waiting at exit is lost:
    /// never this window's defaults over a file it could not read). A garbled file is kept aside
    /// first (never written over), and a garbled or missing one is replaced by this window's
    /// own prefs with the changes.
    pub fn flush(&self) {
        let _w = lock(&self.write);
        let n = lock(&self.changes).len();
        if n == 0 {
            return;
        }
        if self.memory {
            let todo: Vec<Change<T>> = lock(&self.changes).drain(..n).collect();
            let mut own = lock(&self.own);
            for f in &todo {
                f(&mut own);
            }
            return;
        }
        let base = match read_capped(&self.path) {
            Ok(b) => match parse::<T>(&b) {
                Some(v) => Some(v),
                // Garbled (or too large): kept aside (replacing an older copy), never written over.
                None if std::fs::rename(&self.path, broken_path(&self.path)).is_ok() => {
                    self.aside.store(true, Ordering::SeqCst);
                    Some(lock(&self.own).clone())
                }
                None => None,
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Some(lock(&self.own).clone()),
            Err(_) => None,
        };
        let Some(mut v) = base else { return };
        let todo: Vec<Change<T>> = lock(&self.changes)[..n].to_vec();
        for f in &todo {
            f(&mut v);
        }
        // Never more than a read takes (RIB-1): made to fit, or not written (the changes wait).
        let Some((body, dropped)) = self.body(&mut v) else { return };
        if write_atomic(&self.path, &body).is_ok() {
            self.trimmed.fetch_add(dropped, Ordering::SeqCst);
            lock(&self.changes).drain(..n);
            *lock(&self.own) = v;
            // Kept aside and replaced: now it is true to say so (unless it is the one told at start).
            if self.aside.swap(false, Ordering::SeqCst) && !self.noted.load(Ordering::SeqCst) {
                self.garbled_new.store(true, Ordering::SeqCst);
            }
            self.noted.store(false, Ordering::SeqCst);
        }
    }
}
