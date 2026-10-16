//! Code flash programming during a debug session: self-programming, driven by a routine behind
//! the monitor's call gate (§7.1, §46; the procedure is [g15:p678]–[g15:p680]).
//!
//! The flash sequencer writes one 4-byte word, or erases a run of 1 KB blocks, per command, and
//! the CPU waits while it works. The routine below runs one command over up to 64 words from RAM.
//! Its operands are in RAM too, not patched into its code, so it is staged once per halt and each
//! call costs one write (operands and data together), one `5BH` and a one-byte read.

use std::{borrow::Cow, ops::Range, time::Duration};

use probe_rs_target::MemoryRegion;

use super::{
    Rl78, STUB_BUF_BELOW, STUB_BUF_SIZE,
    communication_interface::{Rl78Error, Rl78OcdInterface},
    protocol::{SECURITY_ID_LEN, Sync},
};
use crate::{
    CoreInterface, Error, MemoryInterface, Target,
    flashing::DebugFlashSequence,
    session::{Permissions, Session},
};

/// Run one flash sequencer command (§7.1). Assembled with rl-rs's `llvm-mc`:
///
/// ```text
///         mov   !FSSQ, #00H         ; stop the sequencer
/// w0:     mov   a, !FSASTH
///         bt    a.6, $w0            ; until SQEND clears
///         mov   a, !P_FSSET  ->  mov !FSSET, a
///         mov   a, !P_FLPMC  ->  mov !FLPMC, a      ; FWEDIS = 0, FLSPM = 1
///         mov   a, !P_FLAPL  ->  mov !FLAPL, a      ; and FLAPH, FLSEDL, FLSEDH
///         movw  hl, #0FD00H         ; the data: the buffer, moved when staged
///         mov   a, !P_WORDS  ->  mov b, a
/// next:   mov   a, [hl] .. [hl+3]  ->  FLWLL .. FLWHH
///         mov   a, !P_FSSQ   ->  mov !FSSQ, a       ; start; the CPU waits
/// w1:     mov   a, !FSASTH
///         bf    a.6, $w1            ; until SQEND sets
///         mov   !FSSQ, #00H
/// w2:     mov   a, !FSASTH
///         bt    a.6, $w2            ; until SQEND clears
///         mov   a, !FSASTL
///         and   a, #13H             ; SEQER | WRER | ERER
///         bnz   $done
///         FLAPH:FLAPL += 4
///         incw hl (x4)
///         dec   b
///         bnz   $next
///         clrb  a
/// done:   mov   !P_STATUS, a
///         mov   !FLPMC, #08H        ; write/erase disabled, read mode
///         ret
/// ```
///
/// The sequencer's registers are 2nd SFRs at `F00BEH`–`F00CBH` [g15:p74], reached by `!addr16`.
const STUB_FLASH: [u8; 133] = [
    0xCF, 0xC1, 0x00, 0x00, //       mov  !FSSQ, #00H
    0x8F, 0xC7, 0x00, //       w0:   mov  a, !FSASTH
    0x31, 0x63, 0xFA, //             bt   a.6, $w0
    0x8F, 0xF9, 0xFC, //             mov  a, !P_FSSET
    0x9F, 0xBE, 0x00, //             mov  !FSSET, a
    0x8F, 0xFA, 0xFC, //             mov  a, !P_FLPMC
    0x9F, 0xC0, 0x00, //             mov  !FLPMC, a
    0x8F, 0xFB, 0xFC, //             mov  a, !P_FLAPL
    0x9F, 0xC2, 0x00, //             mov  !FLAPL, a
    0x8F, 0xFC, 0xFC, //             mov  a, !P_FLAPH
    0x9F, 0xC3, 0x00, //             mov  !FLAPH, a
    0x8F, 0xFD, 0xFC, //             mov  a, !P_FLSEDL
    0x9F, 0xC4, 0x00, //             mov  !FLSEDL, a
    0x8F, 0xFE, 0xFC, //             mov  a, !P_FLSEDH
    0x9F, 0xC5, 0x00, //             mov  !FLSEDH, a
    0x36, 0x00, 0xFD, //             movw hl, #0FD00H
    0x8F, 0xF7, 0xFC, //             mov  a, !P_WORDS
    0x73, //                         mov  b, a
    0x8B, //                   next: mov  a, [hl]
    0x9F, 0xC8, 0x00, //             mov  !FLWLL, a
    0x8C, 0x01, //                   mov  a, [hl+1]
    0x9F, 0xC9, 0x00, //             mov  !FLWLH, a
    0x8C, 0x02, //                   mov  a, [hl+2]
    0x9F, 0xCA, 0x00, //             mov  !FLWHL, a
    0x8C, 0x03, //                   mov  a, [hl+3]
    0x9F, 0xCB, 0x00, //             mov  !FLWHH, a
    0x8F, 0xFF, 0xFC, //             mov  a, !P_FSSQ
    0x9F, 0xC1, 0x00, //             mov  !FSSQ, a
    0x8F, 0xC7, 0x00, //       w1:   mov  a, !FSASTH
    0x31, 0x65, 0xFA, //             bf   a.6, $w1
    0xCF, 0xC1, 0x00, 0x00, //       mov  !FSSQ, #00H
    0x8F, 0xC7, 0x00, //       w2:   mov  a, !FSASTH
    0x31, 0x63, 0xFA, //             bt   a.6, $w2
    0x8F, 0xC6, 0x00, //             mov  a, !FSASTL
    0x5C, 0x13, //                   and  a, #13H
    0xDF, 0x18, //                   bnz  $done
    0x8F, 0xC2, 0x00, //             mov  a, !FLAPL
    0x0C, 0x04, //                   add  a, #4
    0x9F, 0xC2, 0x00, //             mov  !FLAPL, a
    0x8F, 0xC3, 0x00, //             mov  a, !FLAPH
    0x1C, 0x00, //                   addc a, #0
    0x9F, 0xC3, 0x00, //             mov  !FLAPH, a
    0xA7, //                         incw hl
    0xA7, //                         incw hl
    0xA7, //                         incw hl
    0xA7, //                         incw hl
    0x93, //                         dec  b
    0xDF, 0xB9, //                   bnz  $next
    0xF1, //                         clrb a
    0x9F, 0xF6, 0xFC, //       done: mov  !P_STATUS, a
    0xCF, 0xC0, 0x00, 0x08, //       mov  !FLPMC, #08H
    0xD7, //                         ret
];

/// The routine's operands, directly below its data. From `P_FSSET` on they are laid out as
/// Renesas's RAM kernel had them (§7.2).
const PARAMS_LEN: usize = STUB_BUF_BELOW;
const P_STATUS: usize = 0;
const P_WORDS: usize = 1;
const P_FSSET: usize = 3;
const P_FLPMC: usize = 4;
const P_FLAP: usize = 5;
const P_FLSED: usize = 7;
const P_FSSQ: usize = 9;

/// [`STUB_FLASH`] as assembled has its data at `FFD00H`; staged, it is moved to the halt's buffer.
const STUB_FLASH_BUF: u32 = 0xF_FD00;
/// The `!addr16` and `#imm16` operands in [`STUB_FLASH`] that address the operands or the data.
const STUB_FLASH_RELOCS: [usize; 10] = [11, 17, 23, 29, 35, 41, 47, 50, 73, 126];

/// The flash routine for a buffer at `buf`.
fn flash_stub(buf: u32) -> [u8; STUB_FLASH.len()] {
    let mut code = STUB_FLASH;
    let delta = buf.wrapping_sub(STUB_FLASH_BUF) as u16;
    for at in STUB_FLASH_RELOCS {
        let operand = u16::from_le_bytes([code[at], code[at + 1]]).wrapping_add(delta);
        code[at..at + 2].copy_from_slice(&operand.to_le_bytes());
    }
    code
}

/// What the status byte holds until the routine overwrites it.
const NOT_RUN: u8 = 0xFF;

/// FSSQ: start a write of one word, or a block erase [g15:p676].
const FSSQ_WRITE: u8 = 0x81;
const FSSQ_ERASE: u8 = 0x84;
/// FLPMC: code flash, write/erase enabled, self-programming mode [g15:p674].
const FLPMC_CODE: u8 = 0x02;

/// A code flash block, the erase unit [g15:p672].
const BLOCK: u32 = 0x400;
const WORD: usize = 4;

/// System clock control: MCS set means the CPU runs from the high-speed system clock [g15:p135].
const CKC: u32 = 0xF_FFA4;
const CKC_MCS: u8 = 1 << 5;
/// The on-chip oscillator's frequency [g15:p145].
const HOCODIV: u32 = 0xF_00A8;

/// The security ID's place in code flash [g15:p687].
const SECURITY_ID: Range<usize> = 0xC4..0xC4 + SECURITY_ID_LEN;
/// The on-chip debug option byte; bit 7 is OCDENSET [g15:p652].
const OCD_OPTION: usize = 0xC3;

/// Generous: the sequencer's own times are in the datasheet, not the hardware manual, and a call
/// that is cut off leaves the monitor mid-command.
const WRITE_TIMEOUT: Duration = Duration::from_secs(1);
const ERASE_TIMEOUT_PER_BLOCK: Duration = Duration::from_secs(1);

impl Rl78<'_> {
    /// `FSSET` for the CPU clock: its frequency in MHz, rounded up, less one [g15:p675]. Read
    /// rather than assumed, because the program may have changed the clock, and the sequencer
    /// times its pulses by it. Renesas's kernel stages `0FH` at 16 MHz.
    fn flash_fsset(&mut self) -> Result<u8, Error> {
        if let Some(fsset) = self.state.fsset {
            return Ok(fsset);
        }
        let mut ckc = [0];
        self.interface.read_mem(CKC, &mut ckc)?;
        if ckc[0] & CKC_MCS != 0 {
            return Err(Rl78Error::Other(
                "the CPU runs from the high-speed system clock (CKC.MCS = 1), whose frequency the \
                 debugger cannot read; flash programming needs it on the on-chip oscillator"
                    .into(),
            )
            .into());
        }
        let mut div = [0];
        self.interface.read_mem(HOCODIV, &mut div)?;
        let mhz: u8 = match div[0] & 0x07 {
            1 => 16,
            2 => 8,
            3 => 4,
            4 => 2,
            5 => 1,
            v => {
                return Err(Rl78Error::Other(format!(
                    "HOCODIV is {v:02X}H, which the manual prohibits; no flash timing for it"
                ))
                .into());
            }
        };
        let fsset = mhz - 1;
        self.state.fsset = Some(fsset);
        Ok(fsset)
    }

    /// Run one sequencer command: `fssq` over the words in `data`, or once for an erase.
    fn flash_command(
        &mut self,
        op: &'static str,
        fssq: u8,
        flap: u32,
        flsed: u32,
        data: &[u8],
        timeout: Duration,
    ) -> Result<(), Error> {
        self.require_halted("flash programming")?;
        debug_assert!(data.len().is_multiple_of(WORD) && data.len() <= STUB_BUF_SIZE);
        let fsset = self.flash_fsset()?;
        let params = self.stub_buf()? - PARAMS_LEN as u32;
        if !self.state.flash_resident {
            self.stage_stub(&flash_stub(params + PARAMS_LEN as u32))?;
            self.state.flash_resident = true;
        }

        let mut buf = vec![0; PARAMS_LEN + data.len()];
        buf[P_STATUS] = NOT_RUN;
        buf[P_WORDS] = (data.len() / WORD).max(1) as u8;
        buf[P_FSSET] = fsset;
        buf[P_FLPMC] = FLPMC_CODE;
        buf[P_FLAP..P_FLAP + 2].copy_from_slice(&(flap as u16).to_le_bytes());
        buf[P_FLSED..P_FLSED + 2].copy_from_slice(&(flsed as u16).to_le_bytes());
        buf[P_FSSQ] = fssq;
        buf[PARAMS_LEN..].copy_from_slice(data);
        self.interface.write_mem(params, &buf)?;
        self.routine_runs()?;
        self.interface.call_stub(timeout)?;

        let mut status = [0];
        self.interface
            .read_mem(params + P_STATUS as u32, &mut status)?;
        match status[0] {
            0 => Ok(()),
            NOT_RUN => Err(Rl78Error::Other(format!(
                "flash {op} at {flap:05X}H: the routine did not report back"
            ))
            .into()),
            status => Err(Rl78Error::Flash {
                op,
                address: flap,
                status,
            }
            .into()),
        }
    }

    /// Erase the code flash blocks that `range` touches, in one command. The sequencer takes the
    /// first block's start and the last block's start with bits 9-2 set [g15:p671].
    pub(super) fn flash_erase(&mut self, range: Range<u32>) -> Result<(), Error> {
        let first = range.start & !(BLOCK - 1);
        let last = (range.end - 1) & !(BLOCK - 1);
        let blocks = (last - first) / BLOCK + 1;
        tracing::debug!(
            "rl78: erasing {blocks} block(s) {first:05X}H-{:05X}H",
            last + BLOCK - 1
        );
        self.flash_command(
            "erase",
            FSSQ_ERASE,
            first,
            last | 0x3FC,
            &[],
            ERASE_TIMEOUT_PER_BLOCK * blocks,
        )?;
        self.state.breakpoints.erased(first..last + BLOCK);
        Ok(())
    }

    /// Write erased code flash, whole words from a word boundary. Runs of `FFH` are left out:
    /// erased flash already reads that way.
    pub(super) fn flash_write(&mut self, address: u32, data: &[u8]) -> Result<(), Error> {
        if !address.is_multiple_of(WORD as u32) || !data.len().is_multiple_of(WORD) {
            return Err(Rl78Error::Other(format!(
                "flash writes are whole 4-byte words: {address:05X}H+{}",
                data.len()
            ))
            .into());
        }
        for (i, chunk) in data.chunks(STUB_BUF_SIZE).enumerate() {
            if chunk.iter().all(|&b| b == 0xFF) {
                continue;
            }
            let at = address + (i * STUB_BUF_SIZE) as u32;
            self.flash_command("write", FSSQ_WRITE, at, 0, chunk, WRITE_TIMEOUT)?;
        }
        Ok(())
    }
}

/// Code flash programming for the RL78/G15 class, as probe-rs's host-side flasher drives it:
/// a 1 KB block is a sector, and pages are written 64 words to a call.
///
/// Two things are added to an image on its way into flash, both in its first page and both only
/// where the image leaves the bytes erased:
///
/// - **The session's security ID** at `000C4H`–`000CDH`. A toolchain leaves it erased, which
///   makes the part's ID ten `FFH` and locks out the next attach (§48.1); e2 studio fills it the
///   same way.
/// - **The debug stub** at `000CEH`–`000D7H` (§31.3, §46.5), with the reset vector pointed at it
///   and `000C3H` bits 3 and 1 set (§31.5). It arms the monitor at every boot and branches to the
///   image's own entry, so the program runs after a normal reset with its own watchdog setting,
///   and a `00H` on TOOL0 halts it. `PROBE_RS_RL78_DEBUG_STUB=0` leaves it out, for an image that
///   ships: an armed monitor halts the part on any byte that reaches TOOL0.
#[derive(Debug)]
pub struct Rl78Flash {
    debug_stub: bool,
}

/// `MOV !F0080H,#0C5H` / `MOV FFFAFH,#40H` / `BR !entry` (§31.3), without the entry.
pub(super) const DEBUG_STUB: [u8; 8] = [0xCF, 0x80, 0x00, 0xC5, 0xCE, 0xAF, 0x40, 0xED];
pub(super) const DEBUG_STUB_AT: usize = 0xCE;
pub(super) const DEBUG_STUB_LEN: usize = DEBUG_STUB.len() + 2;
/// The first page must reach past the stub for any of this to apply.
const HEAD: usize = DEBUG_STUB_AT + DEBUG_STUB_LEN;

impl Rl78Flash {
    /// The sequence, with the debug stub unless `PROBE_RS_RL78_DEBUG_STUB` is `0`.
    pub fn from_env() -> Self {
        Self {
            debug_stub: std::env::var("PROBE_RS_RL78_DEBUG_STUB").as_deref() != Ok("0"),
        }
    }

    /// `data` for `address` as it goes into flash: the image's first page with the session's
    /// security ID and the debug stub added where it leaves room for them. `report` logs what
    /// was done (once, when programming; not again when verifying).
    fn debug_image<'d>(
        &self,
        address: u64,
        data: &'d [u8],
        session_id: [u8; SECURITY_ID_LEN],
        report: bool,
    ) -> Cow<'d, [u8]> {
        if address != 0 || data.len() < HEAD {
            return Cow::Borrowed(data);
        }
        let mut page = data.to_vec();
        let erased = |r: Range<usize>| data[r].iter().all(|&b| b == 0xFF);

        let id = &mut page[SECURITY_ID];
        if erased(SECURITY_ID) {
            id.copy_from_slice(&session_id);
            if report {
                tracing::info!(
                    "rl78: the image leaves the security ID erased: writing the session's"
                );
            }
        } else if report && *id != session_id {
            tracing::warn!(
                "rl78: the image sets the security ID to {id:02X?}, not the session's; set \
                 PROBE_RS_RL78_SECURITY_ID to it to attach afterwards"
            );
        }

        let ocd = data[OCD_OPTION];
        let entry = u16::from_le_bytes([data[0], data[1]]);
        if ocd & 0x80 == 0 {
            if report {
                tracing::warn!(
                    "rl78: the image's option byte 000C3H is {ocd:02X}H, which disables on-chip \
                     debugging (OCDENSET = 0): the debugger cannot attach to the part afterwards"
                );
            }
        } else if !self.debug_stub || entry == DEBUG_STUB_AT as u16 {
            // Left out on request, or already there.
        } else if entry == 0xFFFF {
            if report {
                tracing::warn!("rl78: the image has no reset vector: no debug stub");
            }
        } else if !erased(DEBUG_STUB_AT..HEAD) {
            if report {
                tracing::warn!(
                    "rl78: the image uses 000CEH-000D7H, where the debug stub goes: the program \
                     cannot be halted after a reset. Leave those 10 bytes free in the link map."
                );
            }
        } else {
            page[DEBUG_STUB_AT..DEBUG_STUB_AT + DEBUG_STUB.len()].copy_from_slice(&DEBUG_STUB);
            page[DEBUG_STUB_AT + DEBUG_STUB.len()..HEAD].copy_from_slice(&entry.to_le_bytes());
            page[..2].copy_from_slice(&(DEBUG_STUB_AT as u16).to_le_bytes());
            page[OCD_OPTION] |= 0x0A;
            if report {
                tracing::info!(
                    "rl78: debug stub at 000CEH, branching to the image's entry {entry:05X}H"
                );
            }
        }
        Cow::Owned(page)
    }
}

/// The code flash: the NVM region at 00000H.
fn code_flash(target: &Target) -> Result<Range<u32>, Error> {
    target
        .memory_map
        .iter()
        .find_map(|region| match region {
            MemoryRegion::Nvm(nvm) if nvm.range.start == 0 => {
                Some(nvm.range.start as u32..nvm.range.end as u32)
            }
            _ => None,
        })
        .ok_or_else(|| Error::Other("the target has no code flash at 00000H".into()))
}

/// Erased code flash the debugger can attach to: the debug stub with the reset vector on it,
/// the session's security ID, and the option bytes e2 studio writes with them (§4, §31). This is
/// e2 studio's own monitor image: the stub branches to `0FFFFH`, so the part stops in the
/// monitor whenever it boots, until a program is flashed.
fn monitor_image(size: usize, security_id: [u8; SECURITY_ID_LEN]) -> Vec<u8> {
    let mut image = vec![0xFF; size];
    image[..2].copy_from_slice(&(DEBUG_STUB_AT as u16).to_le_bytes());
    image[0xC2] = 0xF9;
    image[OCD_OPTION] = 0x8F;
    image[SECURITY_ID].copy_from_slice(&security_id);
    image[DEBUG_STUB_AT..DEBUG_STUB_AT + DEBUG_STUB.len()].copy_from_slice(&DEBUG_STUB);
    image
}

/// Attach, and if the debugger cannot reach the part (it is blank, its security ID is not the
/// session's, or its debug stub is gone) and erasing it is permitted, recover it over the flash
/// protocol: erase all of code flash and write [`monitor_image`], then attach again. Without
/// the permission, say how to give it.
pub(crate) fn attach_or_recover(
    interface: &mut dyn Rl78OcdInterface,
    target: &Target,
    permissions: &Permissions,
) -> Result<Attached, Error> {
    if let Some(sync) = interface.attach_running()? {
        return Ok(Attached::Running(sync));
    }
    let error = match interface.attach() {
        Ok(sync) => return Ok(Attached::UnderReset(sync)),
        Err(e @ (Rl78Error::NoMonitor | Rl78Error::SecurityIdRejected)) => e,
        Err(e) => return Err(e.into()),
    };
    if permissions.erase_all().is_err() {
        return Err(Error::MissingPermissions(format!(
            "{error} To erase all of code flash over the flash protocol and make the part \
             attachable again, allow erase-all (--allow-erase-all)"
        )));
    }
    tracing::warn!(
        "rl78: {error} Erase-all is allowed: erasing all of code flash over the flash protocol"
    );
    let flash = code_flash(target)?;
    let image = monitor_image(flash.len(), interface.security_id());
    interface.erase_all_and_program(&image)?;
    Ok(Attached::UnderReset(interface.attach()?))
}

/// How a session found the part.
#[derive(Debug)]
pub(crate) enum Attached {
    /// A program running with the monitor armed, halted where it was.
    Running(Sync),
    /// Reset into the monitor: the boot ROM's idle loop, the program not started (§27.5).
    UnderReset(Sync),
}

impl DebugFlashSequence for Rl78Flash {
    fn prepare_flash(&self, session: &mut Session) -> Result<(), Error> {
        let mut core = session.get_rl78_core()?;
        if !core.core_halted()? {
            core.halt(Duration::from_millis(100))?;
        }
        // The halted program is about to be replaced: resuming it at the end of the session
        // would run new code from an old PC.
        core.state.resume_at_detach = false;
        core.forget_rrm();
        Ok(())
    }

    fn erase_all(&self, session: &mut Session) -> Result<(), Error> {
        let flash = code_flash(session.target())?;
        session.get_rl78_core()?.flash_erase(flash)
    }

    fn erase_sector(&self, session: &mut Session, address: u64) -> Result<(), Error> {
        let address = address as u32;
        session
            .get_rl78_core()?
            .flash_erase(address..address + BLOCK)
    }

    fn program(&self, session: &mut Session, address: u64, data: &[u8]) -> Result<(), Error> {
        let mut core = session.get_rl78_core()?;
        let data = self.debug_image(address, data, core.interface.security_id(), true);
        core.flash_write(address as u32, &data)
    }

    fn verify(&self, session: &mut Session, address: u64, data: &[u8]) -> Result<bool, Error> {
        let mut core = session.get_rl78_core()?;
        let expected = self.debug_image(address, data, core.interface.security_id(), false);
        let mut got = vec![0; data.len()];
        core.read(address, &mut got)?;
        Ok(got == *expected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flash_stub_layout() {
        // The operand addresses the routine reads are where flash_command writes them, for each
        // place the buffer can be.
        for buf in super::super::STUB_BUFS {
            let code = flash_stub(buf);
            let addr = |off: usize| u16::from_le_bytes([code[off], code[off + 1]]);
            let param = |p: usize| (buf - PARAMS_LEN as u32 + p as u32) as u16;
            assert_eq!(addr(11), param(P_FSSET));
            assert_eq!(addr(17), param(P_FLPMC));
            assert_eq!(addr(23), param(P_FLAP));
            assert_eq!(addr(29), param(P_FLAP + 1));
            assert_eq!(addr(35), param(P_FLSED));
            assert_eq!(addr(41), param(P_FLSED + 1));
            assert_eq!(addr(47), buf as u16);
            assert_eq!(addr(50), param(P_WORDS));
            assert_eq!(addr(73), param(P_FSSQ));
            assert_eq!(addr(126), param(P_STATUS));
            assert_eq!(code[132], 0xD7);
        }
        // Nothing else in it addresses that RAM.
        let relocated = flash_stub(STUB_FLASH_BUF + 0x100);
        let moved: Vec<usize> = (0..STUB_FLASH.len())
            .filter(|&i| relocated[i] != STUB_FLASH[i])
            .collect();
        assert_eq!(moved, STUB_FLASH_RELOCS.map(|at| at + 1));
    }

    /// A first page as a toolchain links it: reset vector to 000D8H, option bytes with
    /// OCDENSET, the ID and the stub's place erased, code from 000D8H.
    fn linked_page() -> Vec<u8> {
        let mut page = vec![0xFF; 0x100];
        page[..2].copy_from_slice(&[0xD8, 0x00]);
        page[0xC0..0xC4].copy_from_slice(&[0xEE, 0xFF, 0xF9, 0x85]);
        page[0xD8..0xDC].copy_from_slice(&[0xCB, 0xF8, 0x20, 0xFE]);
        page
    }

    const ID: [u8; SECURITY_ID_LEN] = [0x11; SECURITY_ID_LEN];

    #[test]
    fn first_page_gets_the_id_and_the_stub() {
        let page = linked_page();
        let out = Rl78Flash { debug_stub: true }.debug_image(0, &page, ID, false);
        assert_eq!(out[..2], [0xCE, 0x00], "reset vector to the stub");
        assert_eq!(out[0xC3], 0x8F, "debug-in-use bits 3 and 1");
        assert_eq!(out[SECURITY_ID], ID);
        assert_eq!(
            out[0xCE..0xD8],
            [0xCF, 0x80, 0x00, 0xC5, 0xCE, 0xAF, 0x40, 0xED, 0xD8, 0x00]
        );
        assert_eq!(out[0xD8..], page[0xD8..], "the image itself is untouched");
    }

    #[test]
    fn what_the_image_sets_is_kept() {
        let mut page = linked_page();
        page[0xC4] = 0x00;
        page[0xCE] = 0x00;
        let out = Rl78Flash { debug_stub: true }.debug_image(0, &page, ID, false);
        assert_eq!(
            *out,
            page[..],
            "an ID of its own, and code where the stub goes"
        );

        let page = linked_page();
        let out = Rl78Flash { debug_stub: false }.debug_image(0, &page, ID, false);
        assert_eq!(out[..2], page[..2], "no stub when asked");
        assert_eq!(out[SECURITY_ID], ID, "the ID all the same");

        // Not the first page.
        let tail = vec![0xFF; 0x100];
        assert_eq!(
            *Rl78Flash { debug_stub: true }.debug_image(0x100, &tail, ID, false),
            tail[..]
        );
    }
}
