//! Print test page: our own page through GDI, no admin (`CreateDCW` on the printer, `StartDocW`,
//! one page), so its content says what was tested: "VibePrint test page", the printer, its
//! driver, port and address, this PC, the date and time, a 1 cm grid and the alphabet.
//! `CreateDCW` loads the driver's user-mode part into this process: unelevated only, never in
//! the helper (SPEC section 5).

/// What the page says, line by line (the grid and the alphabet are drawn after).
pub fn lines(printer: &str, driver: &str, port: &str, address: &str, pc: &str, when: &str) -> Vec<String> {
    let mut v = vec!["VibePrint test page".to_string(), String::new()];
    v.push(format!("Printer: {}", crate::text::clean_max(printer, 120)));
    v.push(format!("Driver: {}", crate::text::clean_max(driver, 120)));
    v.push(format!("Port: {}", crate::text::clean_max(port, 120)));
    if !address.is_empty() {
        v.push(format!("Address: {}", crate::text::clean_max(address, 120)));
    }
    v.push(format!("Printed from: {}", crate::text::clean_max(pc, 60)));
    v.push(format!("Date and time: {when}"));
    v
}

pub const ALPHABET: [&str; 3] = ["ABCDEFGHIJKLMNOPQRSTUVWXYZ ÆØÅ ÄÖÜ", "abcdefghijklmnopqrstuvwxyz æøå äöü ß", "0123456789 .,:;!?()[]{}/\\@#%&*+-=<>"];

/// Print the page on printer `name` (exact units). Blocks while the driver renders it: call on a
/// worker.
pub fn print(name: &[u16], text: &[String]) -> Result<(), String> {
    use windows_sys::Win32::Graphics::Gdi::*;
    use windows_sys::Win32::Storage::Xps::*;
    let mut device = name.to_vec();
    device.push(0);
    let driver = crate::host::wide("WINSPOOL");
    // SAFETY: NUL-terminated names; no DEVMODE (the printer's defaults); the DC is deleted below.
    let dc = unsafe { CreateDCW(driver.as_ptr(), device.as_ptr(), std::ptr::null(), std::ptr::null()) };
    if dc.is_null() {
        return Err(format!("the printer's driver did not open ({})", std::io::Error::last_os_error()));
    }
    struct Dc(HDC);
    impl Drop for Dc {
        fn drop(&mut self) {
            // SAFETY: created above, deleted once.
            unsafe { DeleteDC(self.0) };
        }
    }
    let dc = Dc(dc);
    let doc_name = crate::host::wide("VibePrint test page");
    let info = DOCINFOW { cbSize: size_of::<DOCINFOW>() as i32, lpszDocName: doc_name.as_ptr(), lpszOutput: std::ptr::null(), lpszDatatype: std::ptr::null(), fwType: 0 };
    // SAFETY: the DC above and a DOCINFOW whose strings outlive the call.
    if unsafe { StartDocW(dc.0, &info) } <= 0 {
        return Err(format!("the spooler did not take the page ({})", std::io::Error::last_os_error()));
    }
    // SAFETY: GDI calls on the DC; the font is selected out and deleted before the DC goes.
    unsafe {
        if StartPage(dc.0) <= 0 {
            AbortDoc(dc.0);
            return Err(format!("the page did not start ({})", std::io::Error::last_os_error()));
        }
        let dpi_x = GetDeviceCaps(dc.0, LOGPIXELSX as i32).max(72);
        let dpi_y = GetDeviceCaps(dc.0, LOGPIXELSY as i32).max(72);
        let width = GetDeviceCaps(dc.0, HORZRES as i32);
        let height = GetDeviceCaps(dc.0, VERTRES as i32);
        let face = crate::host::wide("Segoe UI");
        // 12 pt text, 24 pt title.
        let font = |pt: i32, weight: i32| CreateFontW(-(pt * dpi_y / 72), 0, 0, 0, weight, 0, 0, 0, DEFAULT_CHARSET as u32, OUT_DEFAULT_PRECIS as u32, CLIP_DEFAULT_PRECIS as u32, DEFAULT_QUALITY as u32, (DEFAULT_PITCH | FF_SWISS) as u32, face.as_ptr());
        let title = font(24, 700);
        let body = font(12, 400);
        let margin_x = dpi_x / 2;
        let mut y = dpi_y / 2;
        let line_h = 12 * dpi_y / 72 * 3 / 2;
        let old = SelectObject(dc.0, title);
        for (i, l) in text.iter().enumerate() {
            if i == 1 {
                SelectObject(dc.0, body);
            }
            let w: Vec<u16> = l.encode_utf16().collect();
            TextOutW(dc.0, margin_x, y, w.as_ptr(), w.len() as i32);
            y += if i == 0 { line_h * 2 } else { line_h };
        }
        y += line_h;
        for l in ALPHABET {
            let w: Vec<u16> = l.encode_utf16().collect();
            TextOutW(dc.0, margin_x, y, w.as_ptr(), w.len() as i32);
            y += line_h;
        }
        // The 1 cm grid: 10 by 10 cm (or what fits), with its size printed under it.
        y += line_h;
        let cm_x = dpi_x * 100 / 254;
        let cm_y = dpi_y * 100 / 254;
        let cells_x = ((width - 2 * margin_x) / cm_x.max(1)).clamp(1, 10);
        let cells_y = ((height - y - 3 * line_h) / cm_y.max(1)).clamp(1, 10);
        for i in 0..=cells_x {
            MoveToEx(dc.0, margin_x + i * cm_x, y, std::ptr::null_mut());
            LineTo(dc.0, margin_x + i * cm_x, y + cells_y * cm_y);
        }
        for j in 0..=cells_y {
            MoveToEx(dc.0, margin_x, y + j * cm_y, std::ptr::null_mut());
            LineTo(dc.0, margin_x + cells_x * cm_x, y + j * cm_y);
        }
        let note: Vec<u16> = format!("Each square is 1 cm: measure it to check the scaling ({cells_x} by {cells_y} cm).").encode_utf16().collect();
        TextOutW(dc.0, margin_x, y + cells_y * cm_y + line_h / 2, note.as_ptr(), note.len() as i32);
        SelectObject(dc.0, old);
        DeleteObject(title);
        DeleteObject(body);
        if EndPage(dc.0) <= 0 {
            AbortDoc(dc.0);
            return Err(format!("the page did not finish ({})", std::io::Error::last_os_error()));
        }
        if EndDoc(dc.0) <= 0 {
            return Err(format!("the spooler did not finish the page ({})", std::io::Error::last_os_error()));
        }
    }
    Ok(())
}
