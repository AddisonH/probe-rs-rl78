//! The RL78/G23's debug monitor: where it differs from the G15's.
//!
//! An 8 KB ROM at `0EE000H`. It is entered as the G15's is, by a reset with TOOL0 low and the
//! `CAH` mode byte, but the mode byte is followed by the flash protocol's Baud Rate Set frame,
//! whose rate the monitor then uses. Framing is 8-N-2.
//!
//! | Request | Reply |
//! |---|---|
//! | `90H` | `05H 01H` |
//! | `91H`, then the security ID and its checksum | `F1H`, then `F2H` (`F0H` if unlocked) |
//! | `92H lo hi n` | `n` bytes from `F0000H + hi:lo`, `n` = 0 meaning 256 |
//! | `93H lo hi n data` | `93H` |
//! | `94H` | `94H`, then `CALL !0F07E0H` |
//! | `95H` | `95H`, then `RETI` |
//!
//! On entry the monitor keeps the program's AX, HL, BC, PC and PSW in [`CONTEXT`], and its ES
//! in bank 0's C, then sends `00H` and waits for `90H` and an unlock. It touches neither DE
//! nor SP, so those are the program's as they stand.

use super::protocol::SECURITY_ID_LEN;

pub const VERSION: u8 = 0x90;
pub const VERSION_REPLY: [u8; 2] = [0x05, 0x01];
pub const UNLOCK: u8 = 0x91;
pub const UNLOCK_CHALLENGE: u8 = 0xF1;
pub const UNLOCK_ALREADY: u8 = 0xF0;
pub const UNLOCK_ACCEPTED: u8 = 0xF2;
/// A wrong ID when on-chip debug option byte bit 0 is clear: the monitor executes `HALT`, and
/// the part erases its flash.
pub const UNLOCK_HALTED: u8 = 0xF4;
pub const READ: u8 = 0x92;
pub const WRITE: u8 = 0x93;
pub const CALL: u8 = 0x94;
pub const RUN: u8 = 0x95;

/// The routine `94H` calls. `F07F4H` onward is the monitor's.
pub const GATE: u32 = 0xF_07E0;
/// AX, HL, BC, then PC (three bytes) and PSW.
pub const CONTEXT: u32 = 0xF_07F6;
pub const CONTEXT_LEN: usize = 10;
/// Bit 0 makes `95H` execute one instruction.
pub const STEP_ENABLE: u32 = 0xF_0088;

/// The rates the entry frame can choose, and their codes.
pub const RATES: [(u32, u8); 4] = [(115_200, 0), (250_000, 1), (500_000, 2), (1_000_000, 3)];

/// `CAH`, then Baud Rate Set at `rate`'s code, for 1.8 V.
pub fn entry(rate_code: u8) -> [u8; 8] {
    let body = [0x03, 0x9A, rate_code, 0x12];
    let sum = body.iter().fold(0u8, |s, b| s.wrapping_sub(*b));
    [0xCA, 0x01, body[0], body[1], body[2], body[3], sum, 0x03]
}

/// The security ID followed by its checksum, the sum of its bytes less one.
pub fn unlock_id(id: &[u8; SECURITY_ID_LEN]) -> [u8; SECURITY_ID_LEN + 1] {
    let mut out = [0; SECURITY_ID_LEN + 1];
    out[..SECURITY_ID_LEN].copy_from_slice(id);
    out[SECURITY_ID_LEN] = id
        .iter()
        .fold(0u8, |s, b| s.wrapping_add(*b))
        .wrapping_sub(1);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_frame_matches_the_vendor() {
        assert_eq!(entry(0), [0xCA, 0x01, 0x03, 0x9A, 0x00, 0x12, 0x51, 0x03]);
        assert_eq!(entry(3)[6], 0x4E);
    }

    #[test]
    fn blank_id_checksum() {
        assert_eq!(unlock_id(&[0; SECURITY_ID_LEN])[SECURITY_ID_LEN], 0xFF);
        assert_eq!(unlock_id(&[0x01; SECURITY_ID_LEN])[SECURITY_ID_LEN], 0x09);
    }
}
