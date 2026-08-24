//! Git's pkt-line wire format: every line on the wire is a 4-hex-digit
//! length prefix (the total length *including* those 4 bytes) followed by
//! that many bytes of payload. Two special zero-length packets exist:
//! flush (`0000`, ends a section) and delimiter (`0001`, protocol v2 only —
//! unused here since this speaks protocol v0).

pub const FLUSH: &[u8] = b"0000";

/// Encodes one payload as a pkt-line and appends it to `out`.
pub fn write_pkt_line(out: &mut Vec<u8>, payload: &[u8]) {
    // +4 for the length prefix itself, per the format's own accounting.
    let len = payload.len() + 4;
    out.extend_from_slice(format!("{len:04x}").as_bytes());
    out.extend_from_slice(payload);
}

pub fn write_flush(out: &mut Vec<u8>) {
    out.extend_from_slice(FLUSH);
}

#[derive(Debug, PartialEq, Eq)]
pub enum PktLine<'a> {
    Data(&'a [u8]),
    Flush,
}

/// Reads pkt-lines out of `input` starting at `pos`, advancing `pos` past
/// each one consumed. Returns `None` once `input` is exhausted.
pub fn read_pkt_line<'a>(input: &'a [u8], pos: &mut usize) -> Option<PktLine<'a>> {
    if *pos + 4 > input.len() {
        return None;
    }
    let len_hex = std::str::from_utf8(&input[*pos..*pos + 4]).ok()?;
    let len = usize::from_str_radix(len_hex, 16).ok()?;

    if len == 0 {
        *pos += 4;
        return Some(PktLine::Flush);
    }
    if len < 4 || *pos + len > input.len() {
        return None; // malformed: shorter than the prefix itself, or truncated
    }

    let payload = &input[*pos + 4..*pos + len];
    *pos += len;
    Some(PktLine::Data(payload))
}

/// Reads every pkt-line in `input` into a `Vec`, stopping at the first flush
/// (the common case: one logical section per read). Returns the data lines
/// only — callers that need to know where the flush landed use
/// `read_pkt_line` directly instead.
pub fn read_pkt_lines_until_flush(input: &[u8]) -> Vec<&[u8]> {
    let mut pos = 0;
    let mut lines = Vec::new();
    while let Some(line) = read_pkt_line(input, &mut pos) {
        match line {
            PktLine::Flush => break,
            PktLine::Data(data) => lines.push(data),
        }
    }
    lines
}
