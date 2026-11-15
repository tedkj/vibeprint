# VibePrint

A printer doctor for Windows: each printer's real state, and the usual fixes done properly, each
shown before it runs.

Every printer gets one row with what Windows thinks of it and, for a network printer, what the
printer itself says when it answers on your network: its port and address, driver and queue. When
it says "Offline" again, VibePrint tells you why in plain words and offers the fix that fits:
clear a stuck queue, swap a flaky WSD port for a Standard TCP/IP port on the same address, point
the printer at its new address, print a test page, or search your network for printers and add one
by its address. Each fix says what it will do before it runs, reads the printer again first (and
stops if things changed), then says what is now true. Every fix is written to a journal, so Undo
can put the old settings back.

It is written in Rust with a native Slint interface, with no browser engine inside.

## What it does not do

It doesn't download or install drivers, scan, order toner, keep a print history, change Point and
Print policies or fix a shared printer on the PC that shares it.

## What it touches on your PC

- **Admin rights:** the app itself never runs as admin. A fix that needs it (clearing other users'
  jobs, restarting the Print Spooler, changing a port) asks with one Windows prompt and runs in a
  short helper that does just that one job.
- **Keeps:** settings in `%APPDATA%\com.tedkj.vibeprint` and the journal of fixes (what Undo works
  from) in `%LOCALAPPDATA%\com.tedkj.vibeprint`. Run from a USB stick (or with a file named
  `portable` next to the exe) it keeps them in `VibePrint-data` beside the exe instead, so it fits
  a field kit.

## What it connects to

Only your printers (every minute while the window is open), your DNS servers, your own network
when you search it for printers, and getvibeware.com when you press About's "Check this install".
Nothing else is sent anywhere: no accounts, no tracking.

## Download

Get the installer from [Releases](https://github.com/tedkj/vibeprint/releases) or from
[getvibeware.com](https://getvibeware.com). It installs for your user only, without admin rights.
The installer and the app are code signed by "Open Source Developer Ted Kenneth Johansen" (the
certificate's name): right-click the file, Properties › Digital Signatures. Compare the
installer's SHA-256 with the one on the release page:

```powershell
Get-FileHash .\VibePrint_0.1.0-preview_x64-setup.exe
```

## Building from source

You need a current stable Rust toolchain on Windows (the MSVC target).

```sh
cargo build --release --locked
```

The app is then at `target\release\vibeprint.exe`. `vendor/` holds Slint's `i-slint-core` with
one small repaint fix; `vendor/README.md` says what changed and why.

### Building the installer

`installer\build.ps1` builds the app and its installer,
`target\release\bundle\VibePrint_<version>_x64-setup.exe`. It needs the official NSIS 3.13:
download `nsis-3.13.zip` from SourceForge (SHA-256
`ba63dffc4410ee89193e1cb5a41989991bd77c61068da17e3156d136b7b0b3d8`) and unpack it to
`_tools\nsis-3.13` in the folder that holds this repository (`..\_tools\nsis-3.13`). The script
checks that whole folder against a pinned hash before it runs anything from it.
`installer\notices.ps1` writes `THIRD-PARTY-NOTICES.txt` for each build (every crate the app
links, with its licence text), and the installer puts it and `LICENSE` next to the app.

## License

[AGPL-3.0](LICENSE). Use it, change it, share it. If you hand out a changed version, or run one as
a service for other people, you share your changes under the same license. Slint is used under
its GPLv3 option.

Made in Norway by Ted K. Johansen.
