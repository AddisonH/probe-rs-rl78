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

/// Put at the gate before a run. In code flash programming mode the ROM cannot be read, and a
/// break enters [`GATE`] instead. This returns to the program if `FFFAEH` holds no break cause
/// (the byte was the host's) or code flash is still in that mode, and enters the ROM's break
/// entry otherwise. Its last instruction's offset is the lock byte, `C6H` while the program
/// runs. The vendor's handler, in that mode, branches to `F0800H`, which mirrors the start of
/// the program's RAM.
pub const BREAK_HANDLER: [u8; 21] = [
    0xC1, 0x8E, 0xAE, 0x5C, 0x73, 0xDF, 0x03, 0xC0, 0x61, 0xFC, 0x8F, 0xC0, 0x02, 0x31, 0x13, 0xF7,
    0xF1, 0x91, 0xDF, 0xFD, 0xEE,
];

/// Data flash, and its access control: bit 0 (DFLEN) enables reads.
pub const DATA_FLASH: std::ops::Range<u32> = 0xF_1000..0xF_3000;
pub const DFLCTL: u32 = 0xF_0090;

/// The rates the entry frame can choose, and their codes.
pub const RATES: [(u32, u8); 4] = [(115_200, 0), (250_000, 1), (500_000, 2), (1_000_000, 3)];

/// The clock registers. CKC's CLS, MCS and MCS1 say what the CPU runs from: the subsystem
/// clock, the high-speed system clock (X1), the middle-speed on-chip oscillator.
pub const CSC: u32 = 0xF_FFA1;
pub const CKC: u32 = 0xF_FFA4;
pub const HOCODIV: u32 = 0xF_00A8;
pub const MOCODIV: u32 = 0xF_00F2;
pub const CKC_CLS: u8 = 1 << 7;
pub const CKC_CSS: u8 = 1 << 6;
pub const CKC_MCS: u8 = 1 << 5;
pub const CKC_MCM0: u8 = 1 << 4;
pub const CKC_MCS1: u8 = 1 << 1;
pub const CKC_MCM1: u8 = 1 << 0;
pub const CSC_MSTOP: u8 = 1 << 7;
pub const CSC_MIOEN: u8 = 1 << 1;
pub const CSC_HIOSTOP: u8 = 1 << 0;

/// `BR !!0EFA00H` at the gate: the ROM's command service, a loop that reads `cmd lo hi ES len`
/// from the link and parks the monitor's return address in the gate's own bytes, so it borrows
/// no RAM. [`SERVICE_READ`] sends `len` bytes from `ES:HL` (0 meaning 256); [`SERVICE_STAY`]
/// keeps it for more commands and [`SERVICE_LEAVE`] returns, each answered [`SERVICE_ACK`].
pub const SERVICE_GATE: [u8; 4] = [0xEC, 0x00, 0xFA, 0x0E];
pub const SERVICE_LEAVE: u8 = 0x00;
pub const SERVICE_READ: u8 = 0x01;
pub const SERVICE_STAY: u8 = 0x06;
pub const SERVICE_ACK: u8 = 0x55;

/// The routine the vendor runs at the gate to move the link to `rate_code`: `MOV FFFAFH,#0`
/// (the link's UART off), `MOV CKC,#ckc` (CKC written with its own value), `MOV FFFAFH,#40H`
/// with the rate (on again at the new rate), `RET`.
pub fn rate_routine(ckc: u8, rate_code: u8) -> [u8; 10] {
    let on = 0x40 | rate_code;
    [0xCE, 0xAF, 0x00, 0xCE, 0xA4, ckc, 0xCE, 0xAF, on, 0xD7]
}

/// `mode`, then the flash protocol's Baud Rate Set at `rate`'s code, for 1.8 V. Mode `CAH` is
/// the monitor; `00H` is the flash protocol itself (Protocol C).
pub fn entry(mode: u8, rate_code: u8) -> Vec<u8> {
    let mut out = vec![mode];
    out.extend(packet(SOH, &[0x9A, rate_code, 0x12], ETX));
    out
}

/// Protocol C's packets: a command (`SOH`) or data (`STX`), ended by `ETX`, or `ETB` when more
/// data follows. `LEN` is 0 for 256 bytes; `SUM` makes `LEN` and the body add up to 0.
pub const SOH: u8 = 0x01;
pub const STX: u8 = 0x02;
pub const ETX: u8 = 0x03;
pub const ETB: u8 = 0x17;
pub const ACK: u8 = 0x06;

pub fn packet(start: u8, body: &[u8], end: u8) -> Vec<u8> {
    let len = body.len() as u8;
    let sum = body
        .iter()
        .fold(len, |s, b| s.wrapping_add(*b))
        .wrapping_neg();
    let mut out = vec![start, len];
    out.extend_from_slice(body);
    out.extend([sum, end]);
    out
}

/// Protocol C commands.
pub const PC_RESET: u8 = 0x00;
pub const PC_BLOCK_ERASE: u8 = 0x22;
pub const PC_PROGRAM: u8 = 0x40;
/// Code flash's erase and programming unit.
pub const BLOCK: usize = 0x800;

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
        assert_eq!(
            entry(0xCA, 0),
            [0xCA, 0x01, 0x03, 0x9A, 0x00, 0x12, 0x51, 0x03]
        );
        assert_eq!(entry(0xCA, 3)[6], 0x4E);
        // The flash protocol's reset and its ACK, as on the wire.
        assert_eq!(
            packet(SOH, &[PC_RESET], ETX),
            [0x01, 0x01, 0x00, 0xFF, 0x03]
        );
        assert_eq!(packet(STX, &[ACK], ETX), [0x02, 0x01, 0x06, 0xF9, 0x03]);
    }

    #[test]
    fn blank_id_checksum() {
        assert_eq!(unlock_id(&[0; SECURITY_ID_LEN])[SECURITY_ID_LEN], 0xFF);
        assert_eq!(unlock_id(&[0x01; SECURITY_ID_LEN])[SECURITY_ID_LEN], 0x09);
    }
}
