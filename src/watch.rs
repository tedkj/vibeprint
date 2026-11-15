//! Changes are watched, not polled: `FindFirstPrinterChangeNotification` on the local print
//! server (`PRINTER_CHANGE_ALL`) on a thread of its own, debounced 500 ms (a burst of changes is
//! one re-read). When the spooler is not there (stopped), the watch tries again every 3 s and
//! says so once when it comes back.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

pub const DEBOUNCE: Duration = Duration::from_millis(500);
const RETRY: Duration = Duration::from_secs(3);

/// Collapses a burst of signals into one call: `signal` at each change, `due` says when the
/// burst has been quiet for `DEBOUNCE`. Pure, for the tests.
#[derive(Default, Debug)]
pub struct Debounce {
    last: Option<Instant>,
}

impl Debounce {
    pub fn signal(&mut self, now: Instant) {
        self.last = Some(now);
    }

    /// True once per burst, when it has been quiet long enough.
    pub fn due(&mut self, now: Instant) -> bool {
        match self.last {
            Some(t) if now.duration_since(t) >= DEBOUNCE => {
                self.last = None;
                true
            }
            _ => false,
        }
    }
}

/// Watch until `stop`; `changed` is called (on the watch thread) after each quiet burst, and
/// when the spooler comes back or goes away.
pub fn start(stop: Arc<AtomicBool>, changed: impl Fn() + Send + 'static) -> std::thread::JoinHandle<()> {
    std::thread::Builder::new()
        .name("watch".into())
        .stack_size(256 * 1024)
        .spawn(move || {
            use windows_sys::Win32::Foundation::*;
            use windows_sys::Win32::Graphics::Printing::*;
            use windows_sys::Win32::System::Threading::WaitForSingleObject;
            let mut was_up = true;
            while !stop.load(Ordering::SeqCst) {
                // The local print server.
                let Ok(server) = crate::printers::sys::open_server() else {
                    if was_up {
                        was_up = false;
                        changed();
                    }
                    sleep_until(&stop, RETRY);
                    continue;
                };
                // SAFETY: an open server handle; the notification handle is closed below.
                let n = unsafe { FindFirstPrinterChangeNotification(server.0, PRINTER_CHANGE_ALL, 0, std::ptr::null()) };
                if n == INVALID_HANDLE_VALUE || n.is_null() {
                    if was_up {
                        was_up = false;
                        changed();
                    }
                    sleep_until(&stop, RETRY);
                    continue;
                }
                if !was_up {
                    was_up = true;
                    changed();
                }
                let mut d = Debounce::default();
                loop {
                    if stop.load(Ordering::SeqCst) {
                        break;
                    }
                    // SAFETY: the notification handle opened above.
                    let w = unsafe { WaitForSingleObject(n, 100) };
                    if w == WAIT_OBJECT_0 {
                        let mut what = 0u32;
                        // SAFETY: resets the notification; no info asked for.
                        if unsafe { FindNextPrinterChangeNotification(n, &mut what, std::ptr::null(), std::ptr::null_mut()) } == 0 {
                            break; // the spooler went away
                        }
                        d.signal(Instant::now());
                    } else if w != WAIT_TIMEOUT {
                        break;
                    }
                    if d.due(Instant::now()) {
                        changed();
                    }
                }
                // SAFETY: opened above, closed once.
                unsafe { FindClosePrinterChangeNotification(n) };
                drop(server);
                if !stop.load(Ordering::SeqCst) {
                    was_up = false;
                    changed();
                    sleep_until(&stop, RETRY);
                }
            }
        })
        .expect("the watch thread")
}

fn sleep_until(stop: &AtomicBool, d: Duration) {
    let end = Instant::now() + d;
    while Instant::now() < end && !stop.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(100));
    }
}
