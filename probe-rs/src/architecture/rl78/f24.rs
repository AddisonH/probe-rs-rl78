//! The RL78/F24's debug monitor: the G23's commands and context block in a different 8 KB ROM.
//!
//! The probe enters and unlocks it; the commands are [`g23`](super::g23)'s, except that `90H`
//! answers [`VERSION_REPLY`] and the ROM has no command service for addresses below `F0000H`.
//! Those are read by [`read_far`], a routine of ours in RAM that sends through the ROM's own
//! byte routines. A reset leaves RAM below `FEF00H` unusable until the program sets `RAMSAR`.

use std::time::Duration;

use super::communication_interface::Rl78Error;
use super::g23::{self, MonitorLink};

pub const VERSION_REPLY: [u8; 2] = [0x06, 0x07];

/// The monitor's byte routines: A out, A in.
const SEND: u32 = 0xE_FF76;
const RECV: u32 = 0xE_FF88;

/// RAM that is there whatever `RAMSAR` holds.
const RAM: std::ops::Range<u32> = 0xF_EF00..0xF_FE20;

/// `CALL !!RECV` four times for L, H, ES and a count (0 meaning 256), then `ES:[HL]` sent a
/// byte at a time through `SEND`, and `RET`. It changes A, B, HL and ES, which the monitor
/// keeps for the program and restores on a run.
fn reader() -> Vec<u8> {
    let call = |a: u32| [0xFC, a as u8, (a >> 8) as u8, (a >> 16) as u8];
    let mut code = Vec::new();
    for then in [&[0x76][..], &[0x77], &[0x9E, 0xFD], &[0x73]] {
        code.extend(call(RECV));
        code.extend_from_slice(then);
    }
    code.extend([0x11, 0x8B, 0xA7]); // MOV A, ES:[HL]; INCW HL
    code.extend(call(SEND));
    code.extend([0x93, 0xDF, 0xF6, 0xD7]); // DEC B; BNZ to the MOV; RET
    code
}

/// Where [`reader`] goes: clear of the monitor's stack, which runs just below the program's SP.
fn reader_at(sp: u32, len: u32) -> u32 {
    [RAM.start, RAM.start + 0x800]
        .into_iter()
        .find(|&at| at + len + 0x20 <= sp || sp + 4 <= at)
        .expect("the candidates are further apart than the monitor's stack is long")
}

/// Read anywhere in the 20-bit space, borrowing RAM for the routine and putting it back.
pub fn read_far(
    link: &mut impl MonitorLink,
    address: u32,
    data: &mut [u8],
) -> Result<(), Rl78Error> {
    let code = reader();
    let mut sp = [0; 2];
    g23::read(link, 0xF_FFF8, &mut sp)?;
    let at = reader_at(
        0xF_0000 | u32::from(u16::from_le_bytes(sp)),
        code.len() as u32,
    );
    let mut saved = vec![0; code.len()];
    g23::read(link, at, &mut saved)?;
    g23::write(link, at, &code)?;
    let [l, m, h, _] = at.to_le_bytes();
    g23::write(link, g23::GATE, &[0xEC, l, m, h])?;
    let read = (|| {
        let mut a = address;
        for chunk in data.chunks_mut(256) {
            g23::expect(link, &[g23::CALL], &[g23::CALL], "read")?;
            let [lo, hi, es, _] = a.to_le_bytes();
            let req = [lo, hi, es, chunk.len() as u8];
            chunk.copy_from_slice(&link.transact(
                &req,
                chunk.len(),
                "read",
                Duration::from_secs(1),
            )?);
            a += chunk.len() as u32;
        }
        Ok(())
    })();
    g23::write(link, at, &saved)?;
    read
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_reader_is_the_one_tried_on_the_board() {
        // Notes 56.8, assembled with llvm-mc.
        let want = "fc88ff0e76fc88ff0e77fc88ff0e9efdfc88ff0e73118ba7fc76ff0e93dff6d7";
        let got: String = reader().iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(got, want);
    }

    #[test]
    fn the_reader_keeps_clear_of_the_stack() {
        assert_eq!(reader_at(0xF_FE20, 32), 0xF_EF00);
        assert_eq!(reader_at(0xF_EF10, 32), 0xF_F700);
    }
}
