//! What a printer says over IPP (RFC 8010/8011): one Get-Printer-Attributes, as an HTTP/1.1 POST
//! to `http://<ip>:631/<path>` (`Content-Type: application/ipp`), 5 s in all, 64 KiB at most.
//! IPP 2.0 first, 1.1 when the printer answers "version not supported". The encoder and the parser
//! are plain Rust over byte slices: every length is checked, collections may nest only so deep,
//! and every string that comes back is cleaned before anyone sees it. TLS (IPPS) is not spoken in
//! v1: a printer that only answers that way is said so.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

pub const PORT: u16 = 631;
pub const OP_GET_PRINTER_ATTRIBUTES: u16 = 0x000B;
/// The most an answer may be (bytes, headers included); more is cut there.
pub const CAP: usize = 64 * 1024;
pub const TIMEOUT: Duration = Duration::from_secs(5);
/// What the window asks for.
pub const WANTED: [&str; 7] = ["printer-state", "printer-state-reasons", "printer-make-and-model", "printer-name", "printer-uuid", "marker-names", "marker-levels"];

/// The path asked when nothing better is known (the port URL's, the mDNS `rp` value).
pub const DEFAULT_PATH: &str = "ipp/print";

// Delimiter and value tags.
const TAG_OPERATION: u8 = 0x01;
const TAG_END: u8 = 0x03;
const VT_INTEGER: u8 = 0x21;
const VT_BOOLEAN: u8 = 0x22;
const VT_ENUM: u8 = 0x23;
const VT_BEG_COLLECTION: u8 = 0x34;
const VT_END_COLLECTION: u8 = 0x37;
const VT_NAME: u8 = 0x42;
const VT_KEYWORD: u8 = 0x44;
const VT_URI: u8 = 0x45;
const VT_CHARSET: u8 = 0x47;
const VT_LANGUAGE: u8 = 0x48;
const VT_MEMBER_NAME: u8 = 0x4A;
const VT_EXTENSION: u8 = 0x7F;

/// Status codes the app tells apart.
pub const STATUS_VERSION_NOT_SUPPORTED: u16 = 0x0503;

/// The request: Get-Printer-Attributes for `uri`, IPP `version` (major, minor).
pub fn request(version: (u8, u8), request_id: u32, uri: &str) -> Vec<u8> {
    let mut b = Vec::with_capacity(256);
    b.extend_from_slice(&[version.0, version.1]);
    b.extend_from_slice(&OP_GET_PRINTER_ATTRIBUTES.to_be_bytes());
    b.extend_from_slice(&request_id.to_be_bytes());
    b.push(TAG_OPERATION);
    attr(&mut b, VT_CHARSET, "attributes-charset", b"utf-8");
    attr(&mut b, VT_LANGUAGE, "attributes-natural-language", b"en");
    attr(&mut b, VT_URI, "printer-uri", uri.as_bytes());
    attr(&mut b, VT_NAME, "requesting-user-name", b"VibePrint");
    for (i, w) in WANTED.iter().enumerate() {
        // The first value carries the name; the rest of the set have an empty one.
        attr(&mut b, VT_KEYWORD, if i == 0 { "requested-attributes" } else { "" }, w.as_bytes());
    }
    b.push(TAG_END);
    b
}

fn attr(b: &mut Vec<u8>, tag: u8, name: &str, value: &[u8]) {
    b.push(tag);
    b.extend_from_slice(&(name.len() as u16).to_be_bytes());
    b.extend_from_slice(name.as_bytes());
    b.extend_from_slice(&(value.len().min(u16::MAX as usize) as u16).to_be_bytes());
    b.extend_from_slice(&value[..value.len().min(u16::MAX as usize)]);
}

/// Why an answer was not taken.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Bad {
    Truncated,
    /// A tag where none may be (0x00, a value before any group, a named attribute inside a
    /// collection, an end of collection without a beginning).
    Tag(u8),
    /// A value whose length does not fit its type.
    Length,
    /// Collections nested deeper than anything real.
    TooDeep,
    TooMany,
}

/// One value, as far as the app needs it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    Int(i32),
    Bool(bool),
    /// Text of any of the string types (text, name, keyword, uri, charset, ...), lossy UTF-8.
    Text(String),
    /// Anything else (a date, a resolution, a collection, an out-of-band value).
    Other,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attribute {
    pub group: u8,
    pub name: String,
    pub values: Vec<Value>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    pub version: (u8, u8),
    pub status: u16,
    pub request_id: u32,
    pub attrs: Vec<Attribute>,
}

impl Response {
    pub fn get(&self, name: &str) -> Option<&[Value]> {
        self.attrs.iter().find(|a| a.name == name).map(|a| a.values.as_slice())
    }

    /// The status class: 0x0000..0x00FF are successes.
    pub fn ok(&self) -> bool {
        self.status < 0x0100
    }
}

fn u16_at(b: &[u8], i: usize) -> Result<u16, Bad> {
    b.get(i..i + 2).map(|s| u16::from_be_bytes([s[0], s[1]])).ok_or(Bad::Truncated)
}

/// An IPP message (the body of the HTTP answer).
pub fn parse(b: &[u8]) -> Result<Response, Bad> {
    if b.len() < 8 {
        return Err(Bad::Truncated);
    }
    let version = (b[0], b[1]);
    let status = u16_at(b, 2)?;
    let request_id = u32::from_be_bytes([b[4], b[5], b[6], b[7]]);
    let mut at = 8;
    let mut group: Option<u8> = None;
    let mut attrs: Vec<Attribute> = Vec::new();
    let mut depth = 0usize;
    loop {
        let tag = *b.get(at).ok_or(Bad::Truncated)?;
        at += 1;
        if tag == TAG_END {
            if depth != 0 {
                return Err(Bad::Tag(tag));
            }
            break;
        }
        if tag < 0x10 {
            // A delimiter: a new group (0x00 is reserved).
            if tag == 0 || depth != 0 {
                return Err(Bad::Tag(tag));
            }
            group = Some(tag);
            continue;
        }
        let g = group.ok_or(Bad::Tag(tag))?;
        let name_len = u16_at(b, at)? as usize;
        at += 2;
        let name = b.get(at..at + name_len).ok_or(Bad::Truncated)?;
        at += name_len;
        let value_len = u16_at(b, at)? as usize;
        at += 2;
        let v = b.get(at..at + value_len).ok_or(Bad::Truncated)?;
        at += value_len;
        if depth > 0 {
            // Inside a collection: member names and values, all without a name of their own.
            if name_len != 0 {
                return Err(Bad::Tag(tag));
            }
            match tag {
                VT_BEG_COLLECTION => {
                    depth += 1;
                    if depth > 16 {
                        return Err(Bad::TooDeep);
                    }
                }
                VT_END_COLLECTION => {
                    if value_len != 0 {
                        return Err(Bad::Length);
                    }
                    depth -= 1;
                }
                _ => check_len(tag, value_len)?,
            }
            continue;
        }
        if tag == VT_END_COLLECTION || tag == VT_MEMBER_NAME {
            return Err(Bad::Tag(tag));
        }
        let value = if tag == VT_BEG_COLLECTION {
            depth = 1;
            Value::Other
        } else {
            check_len(tag, value_len)?;
            value_of(tag, v)
        };
        if name_len == 0 {
            // Another value of the attribute before it.
            let last = attrs.last_mut().ok_or(Bad::Tag(tag))?;
            if last.values.len() >= 1024 {
                return Err(Bad::TooMany);
            }
            last.values.push(value);
        } else {
            if attrs.len() >= 4096 {
                return Err(Bad::TooMany);
            }
            attrs.push(Attribute { group: g, name: String::from_utf8_lossy(name).into_owned(), values: vec![value] });
        }
    }
    Ok(Response { version, status, request_id, attrs })
}

fn check_len(tag: u8, len: usize) -> Result<(), Bad> {
    let ok = match tag {
        VT_INTEGER | VT_ENUM => len == 4,
        VT_BOOLEAN => len == 1,
        0x31 => len == 11, // dateTime
        0x32 => len == 9,  // resolution
        0x33 => len == 8,  // rangeOfInteger
        VT_EXTENSION => len >= 4,
        _ => true,
    };
    if ok { Ok(()) } else { Err(Bad::Length) }
}

fn value_of(tag: u8, v: &[u8]) -> Value {
    match tag {
        VT_INTEGER | VT_ENUM => Value::Int(i32::from_be_bytes([v[0], v[1], v[2], v[3]])),
        VT_BOOLEAN => Value::Bool(v[0] != 0),
        0x35 | 0x36 => {
            // textWithLanguage / nameWithLanguage: a language and the text, each length-prefixed.
            let lang = u16_at(v, 0).unwrap_or(u16::MAX) as usize;
            let tl = 2 + lang;
            match u16_at(v, tl) {
                Ok(n) if v.len() == tl + 2 + n as usize => Value::Text(String::from_utf8_lossy(&v[tl + 2..]).into_owned()),
                _ => Value::Other,
            }
        }
        0x41..=0x49 => Value::Text(String::from_utf8_lossy(v).into_owned()),
        _ => Value::Other,
    }
}

/// What a printer said of itself.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Attrs {
    /// printer-state: 3 idle, 4 processing, 5 stopped.
    pub state: Option<i32>,
    pub reasons: Vec<String>,
    pub make_model: Option<String>,
    pub name: Option<String>,
    pub uuid: Option<String>,
    /// (marker name, level): the level is a percent, or -1/-2 unknown, -3 "some left".
    pub markers: Vec<(String, i32)>,
}

impl Attrs {
    pub fn from(r: &Response) -> Attrs {
        let text = |n: &str| {
            r.get(n).and_then(|v| v.iter().find_map(|x| if let Value::Text(t) = x { Some(crate::text::clean(t)) } else { None })).filter(|t| !t.is_empty())
        };
        let state = r.get("printer-state").and_then(|v| v.iter().find_map(|x| if let Value::Int(i) = x { Some(*i) } else { None }));
        let reasons: Vec<String> = r
            .get("printer-state-reasons")
            .map(|v| v.iter().filter_map(|x| if let Value::Text(t) = x { Some(crate::text::clean_max(t, 80).to_ascii_lowercase()) } else { None }).filter(|t| !t.is_empty() && t != "none").take(32).collect())
            .unwrap_or_default();
        let names: Vec<String> = r.get("marker-names").map(|v| v.iter().map(|x| if let Value::Text(t) = x { crate::text::clean_max(t, 80) } else { String::new() }).collect()).unwrap_or_default();
        let levels: Vec<i32> = r.get("marker-levels").map(|v| v.iter().map(|x| if let Value::Int(i) = x { *i } else { -2 }).collect()).unwrap_or_default();
        let markers = names.into_iter().zip(levels).take(16).collect();
        Attrs { state, reasons, make_model: text("printer-make-and-model"), name: text("printer-name"), uuid: text("printer-uuid"), markers }
    }

    /// The printer's state in words, the worst reason first ("Out of paper", "Ready").
    pub fn words(&self) -> String {
        let worst = self.reasons.iter().filter_map(|r| reason_words(r).map(|w| (reason_rank(r), w))).min_by_key(|x| x.0);
        if let Some((_, w)) = worst {
            return w.to_string();
        }
        match self.state {
            Some(3) => "Ready".into(),
            Some(4) => "Printing".into(),
            Some(5) => "Stopped".into(),
            Some(n) => format!("Unknown state ({n})"),
            None => "Says nothing about its state".into(),
        }
    }

    /// A reason that is a fault (an error, not a report or a warning).
    pub fn has_problem(&self) -> bool {
        self.state == Some(5) || self.reasons.iter().any(|r| reason_rank(r) < 50 && !r.ends_with("-report"))
    }
}

/// The keyword without its severity suffix.
fn reason_base(r: &str) -> &str {
    r.strip_suffix("-error").or_else(|| r.strip_suffix("-warning")).or_else(|| r.strip_suffix("-report")).unwrap_or(r)
}

/// What a printer-state-reasons keyword means, for the reasons the window names.
pub fn reason_words(r: &str) -> Option<&'static str> {
    Some(match reason_base(r) {
        "media-empty" | "media-needed" => "Out of paper",
        "media-low" => "Paper low",
        "media-jam" => "Paper jam",
        "toner-empty" | "marker-supply-empty" => "Out of toner or ink",
        "toner-low" | "marker-supply-low" => "Toner or ink low",
        "door-open" | "cover-open" | "interlock-open" => "Door open",
        "input-tray-missing" => "Input tray missing",
        "output-tray-missing" => "Output tray missing",
        "output-area-full" => "Output tray full",
        "output-area-almost-full" => "Output tray almost full",
        "marker-waste-full" => "Waste toner or ink full",
        "marker-waste-almost-full" => "Waste toner or ink almost full",
        "paused" => "Paused at the printer",
        "offline" => "Offline (the printer says so)",
        "shutdown" => "Shutting down",
        "spool-area-full" => "Its memory is full",
        "moving-to-paused" => "Pausing",
        "connecting-to-device" => "Connecting",
        "fuser-over-temp" | "fuser-under-temp" => "Fuser fault",
        "developer-empty" | "developer-low" => "Developer low",
        "opc-life-over" | "opc-near-eol" => "Drum worn out",
        _ => return None,
    })
}

/// Lower is worse: faults that stop printing first, then warnings.
fn reason_rank(r: &str) -> u8 {
    let base = reason_base(r);
    let severe = match base {
        "media-jam" => 0,
        "door-open" | "cover-open" | "interlock-open" => 1,
        "media-empty" | "media-needed" => 2,
        "toner-empty" | "marker-supply-empty" => 3,
        "input-tray-missing" | "output-tray-missing" => 4,
        "output-area-full" | "marker-waste-full" | "spool-area-full" => 5,
        "offline" | "shutdown" | "paused" | "moving-to-paused" => 6,
        "fuser-over-temp" | "fuser-under-temp" => 7,
        "connecting-to-device" => 8,
        _ => 60,
    };
    let warning = r.ends_with("-warning") || r.ends_with("-report") || matches!(base, "toner-low" | "marker-supply-low" | "media-low" | "output-area-almost-full" | "marker-waste-almost-full" | "developer-low" | "opc-near-eol");
    if warning { 60 + severe.min(39) } else { severe }
}

/// A marker's level in words: "62 %", "unknown", "some left".
pub fn level_words(l: i32) -> String {
    match l {
        0..=100 => format!("{l} %"),
        -3 => "some left".into(),
        _ => "unknown".into(),
    }
}

// ---------- HTTP ----------

/// An HTTP answer as far as IPP needs it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpAnswer {
    pub status: u16,
    pub content_type: String,
    pub location: Option<String>,
    pub body: Vec<u8>,
}

/// The POST that carries an IPP request.
pub fn http_request(host: &str, path: &str, body: &[u8]) -> Vec<u8> {
    let mut r = format!(
        "POST /{} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/ipp\r\nContent-Length: {}\r\nUser-Agent: VibePrint/{}\r\nConnection: close\r\n\r\n",
        path.trim_start_matches('/'),
        body.len(),
        crate::VERSION
    )
    .into_bytes();
    r.extend_from_slice(body);
    r
}

/// Parse what came back (at most 64 KiB, possibly cut there): status line, headers, body
/// (Content-Length, chunked, or until close). Headers that are not UTF-8 are read lossily.
pub fn http_parse(raw: &[u8]) -> Result<HttpAnswer, String> {
    // Interim answers (100 Continue, measured from a Canon GX6000) come first: the real one
    // follows them.
    let mut raw = raw;
    for _ in 0..8 {
        match interim_end(raw) {
            Some(n) => raw = &raw[n..],
            None => break,
        }
    }
    let end = raw.windows(4).position(|w| w == b"\r\n\r\n").ok_or("the answer has no end of headers")?;
    let head = String::from_utf8_lossy(&raw[..end]);
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let mut parts = status_line.splitn(3, ' ');
    if !parts.next().unwrap_or("").starts_with("HTTP/1.") {
        return Err("the answer is not HTTP/1.x".into());
    }
    let status: u16 = parts.next().and_then(|s| s.parse().ok()).filter(|s| (100..600).contains(s)).ok_or("no status code")?;
    let (mut content_type, mut location, mut length, mut chunked) = (String::new(), None, None::<usize>, false);
    for l in lines {
        let Some((k, v)) = l.split_once(':') else { continue };
        let (k, v) = (k.trim(), v.trim());
        if k.eq_ignore_ascii_case("content-type") {
            content_type = v.to_ascii_lowercase();
        } else if k.eq_ignore_ascii_case("location") {
            location = Some(crate::text::clean_max(v, 200));
        } else if k.eq_ignore_ascii_case("content-length") {
            length = v.parse().ok();
        } else if k.eq_ignore_ascii_case("transfer-encoding") && v.to_ascii_lowercase().contains("chunked") {
            chunked = true;
        }
    }
    let rest = &raw[end + 4..];
    let body = if chunked {
        dechunk(rest)
    } else if let Some(n) = length {
        rest[..n.min(rest.len())].to_vec()
    } else {
        rest.to_vec()
    };
    Ok(HttpAnswer { status, content_type, location, body })
}

/// Where an interim (1xx) answer at the start of `raw` ends, if it is one.
fn interim_end(raw: &[u8]) -> Option<usize> {
    let end = raw.windows(4).position(|w| w == b"\r\n\r\n")?;
    let line = String::from_utf8_lossy(&raw[..end.min(64)]);
    let mut parts = line.split(' ');
    let ver = parts.next()?;
    let code: u16 = parts.next()?.trim().parse().ok()?;
    (ver.starts_with("HTTP/1.") && (100..200).contains(&code)).then_some(end + 4)
}

/// A chunked body, as far as it goes.
fn dechunk(mut b: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    while let Some(nl) = b.windows(2).position(|w| w == b"\r\n") {
        let size_text = String::from_utf8_lossy(&b[..nl]);
        let Ok(n) = usize::from_str_radix(size_text.split(';').next().unwrap_or("").trim(), 16) else { break };
        b = &b[nl + 2..];
        // Checked: a hostile size (16 hex digits) must not overflow.
        if n == 0 || out.len().checked_add(n).is_none_or(|t| t > CAP) {
            break;
        }
        let take = n.min(b.len());
        out.extend_from_slice(&b[..take]);
        if take < n {
            break;
        }
        b = n.checked_add(2).and_then(|e| b.get(e..)).unwrap_or(&[]);
    }
    out
}

/// How the IPP question ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The printer answered with its attributes.
    Answered(Attrs),
    /// An IPP answer with an error status (0x0400 and up).
    Refused { status: u16 },
    /// HTTP answered, but not with IPP: the status (a redirect's target host when it has one).
    Http { status: u16, location: Option<String> },
    /// Something answered that is not IPP at all (HTML, a truncated body, garbage): why.
    NotIpp(String),
    /// Only TLS is spoken there (an upgrade or a redirect to https): IPPS, not checked in v1.
    TlsOnly,
    /// No answer: why (refused, timed out, broke).
    NoAnswer(String),
}

impl Outcome {
    /// The printer answered at the IPP port in some way (it is there).
    pub fn answered(&self) -> bool {
        !matches!(self, Outcome::NoAnswer(_))
    }

    pub fn words(&self) -> String {
        match self {
            Outcome::Answered(a) => a.words(),
            Outcome::Refused { status } => format!("IPP refused the question (status 0x{status:04X})"),
            Outcome::Http { status, location: Some(l) } => format!("answered HTTP {status} (to {l}), not IPP"),
            Outcome::Http { status, location: None } => format!("answered HTTP {status}, not IPP"),
            Outcome::NotIpp(w) => format!("answered, but not with IPP ({w})"),
            Outcome::TlsOnly => "answers IPPS only (not checked in v1)".into(),
            Outcome::NoAnswer(w) => w.clone(),
        }
    }
}

/// What an HTTP answer means for IPP.
#[allow(clippy::result_large_err)]
pub fn classify(a: &HttpAnswer, request_id: u32) -> Result<Response, Outcome> {
    match a.status {
        200 => {}
        426 => return Err(Outcome::TlsOnly),
        301 | 302 | 303 | 307 | 308 if a.location.as_deref().is_some_and(|l| l.to_ascii_lowercase().starts_with("https:")) => return Err(Outcome::TlsOnly),
        s => return Err(Outcome::Http { status: s, location: a.location.as_deref().map(location_host) }),
    }
    if a.content_type.starts_with("text/html") || a.body.starts_with(b"<") {
        return Err(Outcome::NotIpp("a web page".into()));
    }
    match parse(&a.body) {
        Ok(r) if r.request_id == request_id || r.request_id == 0 => Ok(r),
        Ok(_) => Err(Outcome::NotIpp("an answer to another request".into())),
        Err(Bad::Truncated) => Err(Outcome::NotIpp("the answer was cut short".into())),
        Err(e) => Err(Outcome::NotIpp(format!("malformed: {e:?}"))),
    }
}

/// The host of a redirect target, for the words ("192.168.1.50:443").
fn location_host(l: &str) -> String {
    let after = l.find("://").map_or(l, |i| &l[i + 3..]);
    crate::text::clean_max(after.split(['/', '?', '#']).next().unwrap_or(""), 80)
}

/// The URI and Host header for an address and path.
pub fn uri_for(addr: SocketAddr, path: &str) -> (String, String) {
    let host = match addr {
        SocketAddr::V4(a) => format!("{}:{}", a.ip(), a.port()),
        SocketAddr::V6(a) => format!("[{}]:{}", a.ip(), a.port()),
    };
    (format!("ipp://{host}/{}", path.trim_start_matches('/')), host)
}

/// One exchange: send `req`, read the answer until close, the cap, or the deadline.
fn exchange(addr: SocketAddr, host: &str, path: &str, body: &[u8], deadline: Instant) -> Result<Vec<u8>, String> {
    let left = |d: Instant| d.saturating_duration_since(Instant::now()).max(Duration::from_millis(1));
    let mut s = match TcpStream::connect_timeout(&addr, left(deadline)) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::TimedOut => return Err("no answer at the IPP port in 5 s".into()),
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => return Err("the IPP port is closed".into()),
        Err(e) => return Err(format!("no connection to the IPP port ({e})")),
    };
    let _ = s.set_write_timeout(Some(left(deadline)));
    s.write_all(&http_request(host, path, body)).map_err(|e| format!("the question did not go out ({e})"))?;
    let mut raw = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        if Instant::now() >= deadline {
            break;
        }
        let _ = s.set_read_timeout(Some(left(deadline)));
        match s.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                raw.extend_from_slice(&buf[..n]);
                if raw.len() >= CAP {
                    raw.truncate(CAP);
                    break;
                }
                // A complete answer by Content-Length ends the read without waiting for close.
                if complete(&raw) {
                    break;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut || e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) if raw.is_empty() => return Err(format!("the connection broke ({e})")),
            Err(_) => break,
        }
    }
    if raw.is_empty() {
        return Err("the IPP port accepted the connection but said nothing".into());
    }
    Ok(raw)
}

/// The answer is all there: past any interim answers, its Content-Length's worth of body came.
fn complete(raw: &[u8]) -> bool {
    let mut raw = raw;
    while let Some(n) = interim_end(raw) {
        raw = &raw[n..];
    }
    let Some(end) = raw.windows(4).position(|w| w == b"\r\n\r\n") else { return false };
    let head = String::from_utf8_lossy(&raw[..end]).to_ascii_lowercase();
    let body = &raw[end + 4..];
    // Chunked (the Canon GX6000 answers so, and keeps the connection open after): complete at
    // the last, empty chunk.
    if head.lines().any(|l| l.starts_with("transfer-encoding:") && l.contains("chunked")) {
        return chunks_complete(body);
    }
    head.lines().find_map(|l| l.strip_prefix("content-length:").and_then(|v| v.trim().parse::<usize>().ok())).is_some_and(|n| body.len() >= n)
}

/// A chunked body has come to its last (empty) chunk and the blank line after it.
fn chunks_complete(mut b: &[u8]) -> bool {
    while let Some(nl) = b.windows(2).position(|w| w == b"\r\n") {
        let size_text = String::from_utf8_lossy(&b[..nl]);
        let Ok(n) = usize::from_str_radix(size_text.split(';').next().unwrap_or("").trim(), 16) else { return false };
        b = &b[nl + 2..];
        if n == 0 {
            // Trailers end with a blank line; most send none.
            return b.windows(2).any(|w| w == b"\r\n");
        }
        match n.checked_add(2).and_then(|e| b.get(e..)) {
            Some(rest) => b = rest,
            None => return false,
        }
    }
    false
}

/// Get-Printer-Attributes at `addr` (port 631), path `path`: IPP 2.0, then 1.1 on "version not
/// supported". 5 s in all.
pub fn get_printer_attributes(addr: SocketAddr, path: &str) -> Outcome {
    let deadline = Instant::now() + TIMEOUT;
    let (uri, host) = uri_for(addr, path);
    for (i, version) in [(2u8, 0u8), (1, 1)].into_iter().enumerate() {
        let id = 1 + i as u32;
        let raw = match exchange(addr, &host, path, &request(version, id, &uri), deadline) {
            Ok(r) => r,
            Err(e) => return Outcome::NoAnswer(e),
        };
        let answer = match http_parse(&raw) {
            Ok(a) => a,
            Err(e) => return Outcome::NotIpp(e),
        };
        match classify(&answer, id) {
            Ok(r) if r.status == STATUS_VERSION_NOT_SUPPORTED && i == 0 => continue,
            Ok(r) if r.ok() => return Outcome::Answered(Attrs::from(&r)),
            Ok(r) => return Outcome::Refused { status: r.status },
            Err(o) => return o,
        }
    }
    Outcome::Refused { status: STATUS_VERSION_NOT_SUPPORTED }
}

/// The path of an IPP port URL or `rp` value: "http://host:631/ipp/print" -> "ipp/print".
pub fn path_of(url_or_rp: &str) -> Option<String> {
    let s = url_or_rp.trim();
    let after = match s.find("://") {
        Some(i) => {
            let rest = &s[i + 3..];
            rest.find('/').map_or("", |j| &rest[j..])
        }
        None => s,
    };
    let p = after.trim_start_matches('/');
    let ok = !p.is_empty() && p.len() <= 200 && p.chars().all(|c| c.is_ascii_graphic() && !matches!(c, '"' | '<' | '>' | '\\' | '^' | '`' | '{' | '|' | '}'));
    ok.then(|| p.to_string())
}
