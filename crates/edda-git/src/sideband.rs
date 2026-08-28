//! `side-band-64k` framing (git protocol capability of the same name).
//!
//! When a client negotiates `side-band-64k`, the upload-pack response's
//! pack stream is no longer written raw after the `NAK` line; instead every
//! chunk is wrapped in a pkt-line whose **first payload byte** is a channel
//! number:
//!
//! * `1` — pack data (the real payload)
//! * `2` — progress text, which `git` shows to the user prefixed `remote: `
//! * `3` — a fatal error message; `git` aborts the transfer
//!
//! This lets the server interleave progress with pack bytes and, crucially,
//! report a failure that happens *after* the header has been sent. A single
//! flush pkt ends the multiplexed stream.
//!
//! The framing is transport-agnostic (it operates on `Vec<u8>`), shared by
//! the HTTP and SSH bridges exactly like the rest of [`crate::protocol`].

use crate::pktline::write_pkt_line;

/// Channel 1: pack data.
pub const BAND_PACK: u8 = 1;
/// Channel 2: progress text (`git` prints it as `remote: <text>`).
pub const BAND_PROGRESS: u8 = 2;
/// Channel 3: a fatal error; `git` aborts on receipt.
pub const BAND_ERROR: u8 = 3;

/// The most data bytes one `side-band-64k` pkt-line may carry: the
/// pkt-line payload ceiling (65516) minus the one channel byte. Matches
/// git's `LARGE_PACKET_DATA_MAX`.
pub const MAX_DATA_PER_PACKET: usize = 65515;

fn write_band(out: &mut Vec<u8>, band: u8, payload: &[u8]) {
    let mut framed = Vec::with_capacity(payload.len() + 1);
    framed.push(band);
    framed.extend_from_slice(payload);
    write_pkt_line(out, &framed);
}

/// Appends `pack` to `out` as one or more channel-1 pkt-lines, splitting on
/// [`MAX_DATA_PER_PACKET`] boundaries.
pub fn write_pack_data(out: &mut Vec<u8>, pack: &[u8]) {
    for chunk in pack.chunks(MAX_DATA_PER_PACKET) {
        write_band(out, BAND_PACK, chunk);
    }
}

/// Appends `message` as a single channel-2 progress pkt-line. `message`
/// should be short and usually end in `\r` (to overwrite in place) or `\n`.
pub fn write_progress(out: &mut Vec<u8>, message: &str) {
    write_band(out, BAND_PROGRESS, message.as_bytes());
}

/// Appends `message` as a single channel-3 error pkt-line.
pub fn write_error(out: &mut Vec<u8>, message: &str) {
    write_band(out, BAND_ERROR, message.as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pktline::{read_pkt_line, PktLine};

    #[test]
    fn pack_data_is_split_into_channel_1_packets_that_reassemble() {
        let payload: Vec<u8> = (0..(MAX_DATA_PER_PACKET * 2 + 17))
            .map(|n| (n % 251) as u8)
            .collect();
        let mut out = Vec::new();
        write_pack_data(&mut out, &payload);

        let mut pos = 0;
        let mut reassembled = Vec::new();
        let mut packets = 0;
        while let Some(PktLine::Data(data)) = read_pkt_line(&out, &mut pos) {
            assert_eq!(data[0], BAND_PACK);
            assert!(data.len() - 1 <= MAX_DATA_PER_PACKET);
            reassembled.extend_from_slice(&data[1..]);
            packets += 1;
        }
        assert_eq!(packets, 3, "two full packets + a remainder");
        assert_eq!(reassembled, payload);
    }

    #[test]
    fn progress_and_error_carry_their_channel_byte() {
        let mut out = Vec::new();
        write_progress(&mut out, "counting objects\r");
        write_error(&mut out, "boom");

        let mut pos = 0;
        let PktLine::Data(first) = read_pkt_line(&out, &mut pos).unwrap() else {
            panic!("expected data")
        };
        assert_eq!(first[0], BAND_PROGRESS);
        assert_eq!(&first[1..], b"counting objects\r");

        let PktLine::Data(second) = read_pkt_line(&out, &mut pos).unwrap() else {
            panic!("expected data")
        };
        assert_eq!(second[0], BAND_ERROR);
        assert_eq!(&second[1..], b"boom");
    }
}
