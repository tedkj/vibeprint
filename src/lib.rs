//! VibePrint: A printer doctor: each printer's real state, and the usual fixes done properly, each shown before it runs. A VibeWare app: Rust and Slint on the software renderer,
//! one small exe, no runtime beside it.
//!
//! `controller` ties the app to the window, which only lays out and draws.

pub mod arp;
pub mod check;
pub mod controller;
#[cfg(feature = "dev-hooks")]
pub mod dev;
pub mod drivers;
pub mod fake;
pub mod find;
pub mod fixes;
pub mod helper;
pub mod host;
pub mod icmp;
pub mod ipp;
pub mod journal;
pub mod launch;
pub mod mdns;
pub mod net;
pub mod oui;
pub mod portable;
pub mod ports;
pub mod prefs;
pub mod printers;
pub mod probe;
pub mod queue;
pub mod report;
pub mod shd;
pub mod snmp;
pub mod status;
pub mod testpage;
pub mod text;
pub mod trust;
pub mod watch;
pub mod xcv;

use serde::{Deserialize, Serialize};
use slint::ComponentHandle;

slint::include_modules!();

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// What the window remembers between runs (prefs.json in %APPDATA%\com.tedkj.vibeprint).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Prefs {
    /// "dark" or "light" once the user has picked one; until then the system's choice.
    pub theme: Option<String>,
}

impl Prefs {
    pub fn dark(&self) -> bool {
        match self.theme.as_deref() {
            Some("dark") => true,
            Some("light") => false,
            _ => host::system_dark(),
        }
    }

    /// Only the values the window offers survive a hand-edited file; the rest fall back.
    pub fn sanitized(mut self) -> Prefs {
        if !matches!(self.theme.as_deref(), None | Some("dark") | Some("light")) {
            self.theme = None;
        }
        self
    }
}

/// The window with its basics wired: theme, version, copying. The controller adds the rest (the
/// theme switch too: it saves on the prefs thread).
pub fn window(prefs: prefs::Store<Prefs>) -> Result<AppWindow, slint::PlatformError> {
    let ui = AppWindow::new()?;
    let p = prefs.load().sanitized();
    ui.global::<Theme>().set_dark(p.dark());
    ui.set_version(VERSION.into());
    ui.on_copy_text(|t| host::copy_text(&t).is_ok());
    Ok(ui)
}
