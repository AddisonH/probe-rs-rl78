//! Code flash programming during a debug session: self-programming, driven by a routine behind
//! the monitor's call gate.
//!
//! The flash sequencer writes one 4-byte word, or erases a run of 1 KB blocks, per command, and
//! the CPU waits while it works. The routine below runs one command over up to 64 words from RAM.
//! Its operands are in RAM too, not patched into its code, so it is staged once per halt and each
//! call costs one write (operands and data together), one `5BH` and a one-byte read.

use std::{borrow::Cow, collections::BTreeMap, ops::Range, time::Duration};

use probe_rs_target::{MemoryRegion, Rl78Monitor};

use super::{
    Rl78, STUB_BUF_BELOW, STUB_BUF_SIZE,
    communication_interface::{Rl78Error, Rl78OcdInterface},
    g23,
    protocol::{SECURITY_ID_LEN, Sync},
};
use crate::{
    CoreInterface, Error, MemoryInterface, Target,
    config::NvmRegion,
    flashing::{DebugFlashSequence, FlashLayout},
    session::{Permissions, Session},
};

/// Run one flash sequencer command:
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
/// The sequencer's registers are 2nd SFRs at `F00BEH`–`F00CBH`, reached by `!addr16`.
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

/// The routine's operands, directly below its data.
const PARAMS_LEN: usize = STUB_BUF_BELOW;
const P_STATUS: usize = 0;
const P_WORDS: usize = 1;
const P_FSSET: usize = 3;
const P_FLPMC: usize = 4;
const P_FLAP: usize = 5;
const P_FLSED: usize = 7;
const P_FSSQ: usize = 9;

/// The RL78/G23's [`STUB_FLASH`]. Its sequencer is the G15's at other addresses, with 16-bit
/// address and data registers, and `FLPMC` is written through `PFCMD`'s protection sequence (`mode`).
/// Its operands are laid out for word access: status, words, `FLAPL` (2), `FLSEDL` (2), `FLAPH`,
/// `FLSEDH`, the `FSSET` frequency bits, `FSSQ`.
const STUB_FLASH_G23: [u8; 147] = [
    0xF5, 0xC5, 0x02, //             clrb !FSSQ
    0x8F, 0xCB, 0x02, //       w0:   mov  a, !FSASTH
    0x31, 0x63, 0xFA, //             bt   a.6, $w0
    0x50, 0x02, //                   mov  x, #02H          ; code flash programming mode
    0xFE, 0x70, 0x00, //             call $!mode
    0xE5, 0xC9, 0x02, //             oneb !FLRST
    0xF5, 0xC9, 0x02, //             clrb !FLRST
    0x8F, 0xB6, 0x00, //             mov  a, !FSSET
    0x5C, 0xC0, //                   and  a, #0C0H         ; keep the boot area bits
    0x6F, 0xFE, 0xFC, //             or   a, !P_FSET
    0x9F, 0xB6, 0x00, //             mov  !FSSET, a
    0xAF, 0xF8, 0xFC, //             movw ax, !P_FLAPL
    0xBF, 0xC2, 0x02, //             movw !FLAPL, ax
    0x8F, 0xFC, 0xFC, //             mov  a, !P_FLAPH
    0x9F, 0xC4, 0x02, //             mov  !FLAPH, a
    0xAF, 0xFA, 0xFC, //             movw ax, !P_FLSEDL
    0xBF, 0xC6, 0x02, //             movw !FLSEDL, ax
    0x8F, 0xFD, 0xFC, //             mov  a, !P_FLSEDH
    0x9F, 0xC8, 0x02, //             mov  !FLSEDH, a
    0x36, 0x00, 0xFD, //             movw hl, #0FD00H
    0x8F, 0xF7, 0xFC, //             mov  a, !P_WORDS
    0x73, //                         mov  b, a
    0xAB, //                   next: movw ax, [hl]
    0xBF, 0xCC, 0x02, //             movw !FLWL, ax
    0xAC, 0x02, //                   movw ax, [hl+2]
    0xBF, 0xCE, 0x02, //             movw !FLWH, ax
    0x8F, 0xFF, 0xFC, //             mov  a, !P_FSSQ
    0x9F, 0xC5, 0x02, //             mov  !FSSQ, a
    0x8F, 0xCB, 0x02, //       w1:   mov  a, !FSASTH
    0x31, 0x65, 0xFA, //             bf   a.6, $w1
    0xF5, 0xC5, 0x02, //             clrb !FSSQ
    0x8F, 0xCB, 0x02, //       w2:   mov  a, !FSASTH
    0x31, 0x63, 0xFA, //             bt   a.6, $w2
    0x8F, 0xCA, 0x02, //             mov  a, !FSASTL
    0x5C, 0x13, //                   and  a, #13H
    0xDF, 0x16, //                   bnz  $done
    0xAF, 0xC2, 0x02, //             movw ax, !FLAPL
    0x04, 0x04, 0x00, //             addw ax, #4
    0xBF, 0xC2, 0x02, //             movw !FLAPL, ax
    0xDE, 0x03, //                   bnc  $nc
    0xA0, 0xC4, 0x02, //             inc  !FLAPH
    0xA7, //                   nc:   incw hl
    0xA7, //                         incw hl
    0xA7, //                         incw hl
    0xA7, //                         incw hl
    0x93, //                         dec  b
    0xDF, 0xC6, //                   bnz  $next
    0xF1, //                         clrb a
    0x9F, 0xF6, 0xFC, //       done: mov  !P_STATUS, a
    0x50, 0x08, //                   mov  x, #08H          ; not programmable; falls into mode
    0x60, //                   mode: mov  a, x
    0x7C, 0xFF, //                   xor  a, #0FFH
    0x72, //                         mov  c, a
    0x60, //                         mov  a, x
    0xCF, 0xC0, 0x00, 0xA5, //       mov  !PFCMD, #0A5H
    0x9F, 0xC0, 0x02, //             mov  !FLPMC, a
    0x62, //                         mov  a, c
    0x9F, 0xC0, 0x02, //             mov  !FLPMC, a
    0x60, //                         mov  a, x
    0x9F, 0xC0, 0x02, //             mov  !FLPMC, a
    0xD7, //                         ret
];
const STUB_FLASH_G23_RELOCS: [usize; 9] = [26, 32, 38, 44, 50, 56, 59, 72, 122];
const G23_P_FLAPL: usize = 2;
const G23_P_FLSEDL: usize = 4;
const G23_P_FLAPH: usize = 6;
const G23_P_FLSEDH: usize = 7;
const G23_P_FSET: usize = 8;

/// [`STUB_FLASH`] as assembled has its data at `FFD00H`; staged, it is moved to the halt's buffer.
const STUB_FLASH_BUF: u32 = 0xF_FD00;
/// The `!addr16` and `#imm16` operands in [`STUB_FLASH`] that address the operands or the data.
const STUB_FLASH_RELOCS: [usize; 10] = [11, 17, 23, 29, 35, 41, 47, 50, 73, 126];

/// The flash routine for a buffer at `buf`.
fn flash_stub(buf: u32) -> [u8; STUB_FLASH.len()] {
    relocate(STUB_FLASH, &STUB_FLASH_RELOCS, buf)
}

/// A flash routine, assembled for a buffer at [`STUB_FLASH_BUF`], for one at `buf`.
fn relocate<const N: usize>(mut code: [u8; N], relocs: &[usize], buf: u32) -> [u8; N] {
    let delta = buf.wrapping_sub(STUB_FLASH_BUF) as u16;
    for &at in relocs {
        let operand = u16::from_le_bytes([code[at], code[at + 1]]).wrapping_add(delta);
        code[at..at + 2].copy_from_slice(&operand.to_le_bytes());
    }
    code
}

/// What the status byte holds until the routine overwrites it.
const NOT_RUN: u8 = 0xFF;

/// FSSQ: start a write of one word, or a block erase.
const FSSQ_WRITE: u8 = 0x81;
const FSSQ_ERASE: u8 = 0x84;
/// FLPMC: code flash, write/erase enabled, self-programming mode.
const FLPMC_CODE: u8 = 0x02;

const WORD: usize = 4;

/// System clock control: MCS set means the CPU runs from the high-speed system clock.
const CKC: u32 = 0xF_FFA4;
const CKC_MCS: u8 = 1 << 5;
const HOCODIV: u32 = 0xF_00A8;

const SECURITY_ID: Range<usize> = 0xC4..0xC4 + SECURITY_ID_LEN;
/// The on-chip debug option byte; bit 7 is OCDENSET.
const OCD_OPTION: usize = 0xC3;

/// Generous: the sequencer's own times are in the datasheet, not the hardware manual, and a call
/// that is cut off leaves the monitor mid-command.
const WRITE_TIMEOUT: Duration = Duration::from_secs(1);
const ERASE_TIMEOUT_PER_BLOCK: Duration = Duration::from_secs(1);

impl Rl78<'_> {
    /// `FSSET` for the CPU clock: its frequency in MHz, rounded up, less one. Read rather than
    /// assumed, because the program may have changed the clock, and the sequencer times its
    /// pulses by it.
    pub(super) fn flash_fsset(&mut self) -> Result<u8, Error> {
        if let Some(fsset) = self.state.fsset {
            return Ok(fsset);
        }
        if self.g23() {
            self.flash_clock_g23()?;
            let fsset = self.cpu_mhz_g23()? - 1;
            self.state.fsset = Some(fsset);
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

    /// Self-programming needs the CPU on the high-speed on-chip oscillator, with the
    /// middle-speed one stopped [RL78/G23 manual, 33.6]. A program on another clock is moved
    /// there, and its settings go back before it runs again.
    pub(super) fn flash_clock_g23(&mut self) -> Result<(), Error> {
        use g23::{CKC_CLS, CKC_CSS, CKC_MCM0, CKC_MCM1, CKC_MCS1, CSC_HIOSTOP, CSC_MIOEN};
        let mut regs = [0; 4];
        self.interface.read_mem(g23::CSC, &mut regs)?;
        let (mut csc, ckc) = (regs[0], regs[3]);
        let off_hoco = CKC_CLS | CKC_CSS | CKC_MCS | CKC_MCM0 | CKC_MCS1 | CKC_MCM1;
        if ckc & off_hoco == 0 && csc & (CSC_MIOEN | CSC_HIOSTOP) == 0 {
            return Ok(());
        }
        tracing::info!(
            "rl78: CKC {ckc:02X}H, CSC {csc:02X}H: moving the CPU to the high-speed on-chip \
             oscillator to program flash, until the program runs again"
        );
        self.state.clock.get_or_insert([csc, ckc]);
        let set_csc = |this: &mut Self, value: u8| this.interface.write_mem(g23::CSC, &[value]);
        if csc & CSC_HIOSTOP != 0 {
            csc &= !CSC_HIOSTOP;
            set_csc(self, csc)?;
        }
        let mut select = ckc & (CKC_CSS | CKC_MCM0 | CKC_MCM1);
        if select & CKC_CSS != 0 {
            // Off the subsystem clock first, to whatever the main clock is: MCM0 and MCM1
            // cannot change while CSS is set.
            if select & CKC_MCM0 != 0 && csc & g23::CSC_MSTOP != 0 {
                return Err(Rl78Error::Other(
                    "the CPU runs from the subsystem clock with X1 stopped; flash programming \
                     needs the high-speed on-chip oscillator"
                        .into(),
                )
                .into());
            }
            if select & (CKC_MCM0 | CKC_MCM1) == CKC_MCM1 && csc & CSC_MIOEN == 0 {
                csc |= CSC_MIOEN;
                set_csc(self, csc)?;
            }
            select &= !CKC_CSS;
            self.select_clock_g23(select, CKC_CLS, 0)?;
        }
        if select & CKC_MCM0 != 0 {
            select &= !CKC_MCM0;
            self.select_clock_g23(select, CKC_MCS, 0)?;
        }
        if select & CKC_MCM1 != 0 {
            self.select_clock_g23(0, CKC_MCS1, 0)?;
        }
        if csc & CSC_MIOEN != 0 {
            set_csc(self, csc & !CSC_MIOEN)?;
        }
        Ok(())
    }

    /// Put back the clock settings [`flash_clock_g23`](Self::flash_clock_g23) changed: each
    /// source running, then the selections in the order the manual allows, then CSC as it was.
    pub(super) fn restore_clock_g23(&mut self) -> Result<(), Error> {
        use g23::{CKC_CLS, CKC_CSS, CKC_MCM0, CKC_MCM1, CKC_MCS1, CSC_MIOEN};
        let Some([csc, ckc]) = self.state.clock else {
            return Ok(());
        };
        let select = ckc & (CKC_MCM0 | CKC_MCM1);
        // Selecting the middle-speed oscillator needs it running, whatever CSC had.
        if csc & CSC_MIOEN != 0 || select & CKC_MCM1 != 0 {
            self.interface
                .write_mem(g23::CSC, &[(csc | CSC_MIOEN) & !g23::CSC_HIOSTOP])?;
        }
        if select & CKC_MCM1 != 0 {
            self.select_clock_g23(CKC_MCM1, CKC_MCS1, CKC_MCS1)?;
        }
        if select & CKC_MCM0 != 0 {
            self.select_clock_g23(select, CKC_MCS, CKC_MCS)?;
        }
        if ckc & CKC_CSS != 0 {
            self.select_clock_g23(select | CKC_CSS, CKC_CLS, CKC_CLS)?;
        }
        self.interface.write_mem(g23::CSC, &[csc])?;
        self.state.clock = None;
        Ok(())
    }

    /// Write CKC's selection bits, and wait for its status bit `mask` to read `want`.
    fn select_clock_g23(&mut self, select: u8, mask: u8, want: u8) -> Result<(), Error> {
        self.interface.write_mem(g23::CKC, &[select])?;
        let mut ckc = [0];
        for _ in 0..10 {
            self.interface.read_mem(g23::CKC, &mut ckc)?;
            if ckc[0] & mask == want {
                return Ok(());
            }
        }
        Err(Rl78Error::Other(format!(
            "CKC reads {:02X}H after writing {select:02X}H: the clock did not switch",
            ckc[0]
        ))
        .into())
    }

    /// The G23's CPU clock in MHz, on the high-speed on-chip oscillator, whose frequency is
    /// `HOCODIV`'s, from a table that option byte `000C2H` bit 3 (FRQSEL3) chooses
    /// [RL78/G23 manual, 6.3.9].
    fn cpu_mhz_g23(&mut self) -> Result<u8, Error> {
        let mut option = [0];
        self.read_bytes(0xC2, &mut option)?;
        let mut div = [0];
        self.interface.read_mem(HOCODIV, &mut div)?;
        let table: &[u8] = if option[0] & 0x08 != 0 {
            &[32, 16, 8, 4, 2, 1]
        } else {
            &[24, 12, 6, 3]
        };
        table
            .get(usize::from(div[0] & 0x07))
            .copied()
            .ok_or_else(|| {
                Rl78Error::Other(format!(
                "HOCODIV is {:02X}H, which the manual prohibits with option byte 000C2H at {:02X}H",
                div[0], option[0]
            ))
            .into()
            })
    }

    /// Back into the monitor after the flash protocol has erased the blocks at `erased`, under
    /// reset as the protocol leaves the part.
    fn attach_after_flash_protocol(&mut self, erased: &[u32]) -> Result<(), Error> {
        let block = self.flash_block();
        for &at in erased {
            self.state.breakpoints.erased(at..at + block);
        }
        let sync = self.interface.attach()?;
        self.state.attached(Attached::UnderReset(sync));
        Ok(())
    }

    /// The code flash erase unit.
    pub(super) fn flash_block(&self) -> u32 {
        if self.g23() { 0x800 } else { 0x400 }
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
            let buf = params + PARAMS_LEN as u32;
            if self.g23() {
                self.stage_stub(&relocate(STUB_FLASH_G23, &STUB_FLASH_G23_RELOCS, buf))?;
            } else {
                self.stage_stub(&flash_stub(buf))?;
            }
            self.state.flash_resident = true;
        }

        self.state.code_cache.clear();
        self.state.code_image.clear();
        let operands = params..params + (PARAMS_LEN + data.len()) as u32;
        self.ram_borrow(operands)?;
        let mut buf = vec![0; PARAMS_LEN + data.len()];
        buf[P_STATUS] = NOT_RUN;
        buf[P_WORDS] = (data.len() / WORD).max(1) as u8;
        if self.g23() {
            buf[G23_P_FLAPL..G23_P_FLAPL + 2].copy_from_slice(&(flap as u16).to_le_bytes());
            buf[G23_P_FLSEDL..G23_P_FLSEDL + 2].copy_from_slice(&(flsed as u16).to_le_bytes());
            buf[G23_P_FLAPH] = (flap >> 16) as u8;
            buf[G23_P_FLSEDH] = (flsed >> 16) as u8;
            buf[G23_P_FSET] = fsset;
        } else {
            buf[P_FSSET] = fsset;
            buf[P_FLPMC] = FLPMC_CODE;
            buf[P_FLAP..P_FLAP + 2].copy_from_slice(&(flap as u16).to_le_bytes());
            buf[P_FLSED..P_FLSED + 2].copy_from_slice(&(flsed as u16).to_le_bytes());
        }
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
    /// first block's start and the last block's start with bits 9-2 set.
    pub(super) fn flash_erase(&mut self, range: Range<u32>) -> Result<(), Error> {
        let block = self.flash_block();
        let first = range.start & !(block - 1);
        let last = (range.end - 1) & !(block - 1);
        let blocks = (last - first) / block + 1;
        tracing::debug!(
            "rl78: erasing {blocks} block(s) {first:05X}H-{:05X}H",
            last + block - 1
        );
        self.flash_command(
            "erase",
            FSSQ_ERASE,
            first,
            last | (block - WORD as u32),
            &[],
            ERASE_TIMEOUT_PER_BLOCK * blocks,
        )?;
        self.state.breakpoints.erased(first..last + block);
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

/// Code flash programming as probe-rs's host-side flasher drives it. On the RL78/G15 class, by
/// self-programming: a 1 KB block is a sector, and pages are written 64 words to a call. On the
/// G23, whole images over the flash protocol ([`g23`](Self::g23)).
///
/// Two things are added to an image on its way into flash, both in its first page and both only
/// where the image leaves the bytes erased:
///
/// - **The session's security ID** at `000C4H`–`000CDH`. A toolchain leaves it erased, which
///   makes the part's ID ten `FFH` and locks out the next attach.
/// - **The debug stub** at `000CEH`–`000D7H`, with the reset vector pointed at it and `000C3H`
///   bits 3 and 1 set. It arms the monitor at every boot and branches to the
///   image's own entry, so the program runs after a normal reset with its own watchdog setting,
///   and a `00H` on TOOL0 halts it. `PROBE_RS_RL78_DEBUG_STUB=0` leaves it out, for an image that
///   ships: an armed monitor halts the part on any byte that reaches TOOL0.
#[derive(Debug)]
pub struct Rl78Flash {
    debug_stub: bool,
    /// Whole images over the flash protocol rather than by self-programming.
    flash_protocol: bool,
}

/// `MOV !F0080H,#0C5H` / `MOV FFFAFH,#40H` / `BR !entry`, without the entry.
pub(super) const DEBUG_STUB: [u8; 8] = [0xCF, 0x80, 0x00, 0xC5, 0xCE, 0xAF, 0x40, 0xED];
pub(super) const DEBUG_STUB_AT: usize = 0xCE;
pub(super) const DEBUG_STUB_LEN: usize = DEBUG_STUB.len() + 2;
const HEAD: usize = DEBUG_STUB_AT + DEBUG_STUB_LEN;

impl Rl78Flash {
    /// The sequence, with the debug stub unless `PROBE_RS_RL78_DEBUG_STUB` is `0`.
    pub fn from_env() -> Self {
        Self {
            debug_stub: std::env::var("PROBE_RS_RL78_DEBUG_STUB").as_deref() != Ok("0"),
            flash_protocol: false,
        }
    }

    /// The RL78/G23's sequence: no debug stub, and whole images over the flash protocol
    /// (Protocol C), which costs a reset but needs nothing of the program or its clock.
    pub fn g23() -> Self {
        Self {
            debug_stub: false,
            flash_protocol: true,
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
/// the session's security ID, and option bytes that enable debugging. The stub branches to
/// `0FFFFH`, so the part stops in the monitor whenever it boots, until a program is flashed.
fn monitor_image(size: usize, security_id: [u8; SECURITY_ID_LEN]) -> Vec<u8> {
    let mut image = vec![0xFF; size];
    image[..2].copy_from_slice(&(DEBUG_STUB_AT as u16).to_le_bytes());
    image[0xC2] = 0xF9;
    image[OCD_OPTION] = 0x8F;
    image[SECURITY_ID].copy_from_slice(&security_id);
    image[DEBUG_STUB_AT..DEBUG_STUB_AT + DEBUG_STUB.len()].copy_from_slice(&DEBUG_STUB);
    image
}

/// The G23's [`monitor_image`]: option bytes as the FPB's sample project sets them, with a
/// wrong security ID not erasing flash, and the session's ID. The G23 needs no stub: the debugger
/// starts its programs itself.
fn monitor_image_g23(size: usize, security_id: [u8; SECURITY_ID_LEN]) -> Vec<u8> {
    let mut image = vec![0xFF; size];
    image[0xC0..0xC4].copy_from_slice(&[0xEF, 0x3A, 0xE8, 0x85]);
    image[SECURITY_ID].copy_from_slice(&security_id);
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
    if let Some(crate::config::Core {
        core_access_options: probe_rs_target::CoreAccessOptions::Rl78(options),
        ..
    }) = target.cores.first()
    {
        interface.set_monitor(options.monitor)?;
    }
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
    let image = match interface.monitor() {
        Rl78Monitor::G23 => monitor_image_g23(flash.len(), interface.security_id()),
        _ => monitor_image(flash.len(), interface.security_id()),
    };
    interface.erase_all_and_program(&image)?;
    Ok(Attached::UnderReset(interface.attach()?))
}

/// Blocks as the flash protocol writes them: contiguous ones in one run, erased ones not at all.
fn block_runs(blocks: &BTreeMap<u32, Vec<u8>>) -> Vec<(u32, Vec<u8>)> {
    let mut runs: Vec<(u32, Vec<u8>)> = Vec::new();
    for (&at, data) in blocks.iter().filter(|(_, d)| d.iter().any(|&b| b != 0xFF)) {
        match runs.last_mut() {
            Some((start, run)) if *start + run.len() as u32 == at => run.extend(data),
            _ => runs.push((at, data.clone())),
        }
    }
    runs
}

/// How a session found the part.
#[derive(Debug)]
pub(crate) enum Attached {
    /// A program running with the monitor armed, halted where it was.
    Running(Sync),
    /// Reset into the monitor: the boot ROM's idle loop, the program not started.
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
        let mut core = session.get_rl78_core()?;
        if self.flash_protocol {
            // A G23 whose ID is erased refuses every ID, so block 0 gets the session's back.
            let erase: Vec<u32> = flash.clone().step_by(g23::BLOCK).collect();
            let first = monitor_image_g23(g23::BLOCK, core.interface.security_id());
            core.interface
                .flash_protocol_write(&erase, &[(0, &first)])?;
            return core.attach_after_flash_protocol(&erase);
        }
        core.flash_erase(flash)
    }

    fn program_image(
        &self,
        session: &mut Session,
        regions: &[(&NvmRegion, &FlashLayout)],
    ) -> Result<bool, Error> {
        if !self.flash_protocol {
            return Ok(false);
        }
        let flash = code_flash(session.target())?;
        let block = g23::BLOCK as u32;
        let mut blocks: BTreeMap<u32, Vec<u8>> = BTreeMap::new();
        for (_, layout) in regions {
            for sector in layout.sectors() {
                blocks
                    .entry(sector.address() as u32 & !(block - 1))
                    .or_insert_with(|| vec![0xFF; g23::BLOCK]);
            }
            for page in layout.pages() {
                let at = page.address() as u32;
                let base = at & !(block - 1);
                let end = at + page.data().len() as u32;
                let data = blocks
                    .get_mut(&base)
                    .filter(|_| flash.start <= at && end <= flash.end.min(base + block));
                let Some(data) = data else {
                    return Err(Rl78Error::Other(format!(
                        "the flash protocol writes whole code flash blocks; {at:05X}H-{:05X}H is not \
                         in one",
                        end - 1
                    ))
                    .into());
                };
                data[(at - base) as usize..(end - base) as usize].copy_from_slice(page.data());
            }
        }
        let mut core = session.get_rl78_core()?;
        if let Some(first) = blocks.get_mut(&0) {
            let image = self
                .debug_image(0, first, core.interface.security_id(), true)
                .into_owned();
            *first = image;
        }
        let runs = block_runs(&blocks);
        let writes: Vec<(u32, &[u8])> = runs.iter().map(|(at, d)| (*at, &d[..])).collect();
        let erase: Vec<u32> = blocks.into_keys().collect();
        core.interface.flash_protocol_write(&erase, &writes)?;
        core.attach_after_flash_protocol(&erase)?;
        Ok(true)
    }

    fn erase_sector(&self, session: &mut Session, address: u64) -> Result<(), Error> {
        let address = address as u32;
        let mut core = session.get_rl78_core()?;
        let block = core.flash_block();
        core.flash_erase(address..address + block)
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

    #[test]
    fn g23_flash_stub_layout() {
        for buf in super::super::STUB_BUFS {
            let code = relocate(STUB_FLASH_G23, &STUB_FLASH_G23_RELOCS, buf);
            let addr = |off: usize| u16::from_le_bytes([code[off], code[off + 1]]);
            let param = |p: usize| (buf - PARAMS_LEN as u32 + p as u32) as u16;
            assert_eq!(addr(26), param(G23_P_FSET));
            assert_eq!(addr(32), param(G23_P_FLAPL));
            assert_eq!(addr(38), param(G23_P_FLAPH));
            assert_eq!(addr(44), param(G23_P_FLSEDL));
            assert_eq!(addr(50), param(G23_P_FLSEDH));
            assert_eq!(addr(56), buf as u16);
            assert_eq!(addr(59), param(P_WORDS));
            assert_eq!(addr(72), param(P_FSSQ));
            assert_eq!(addr(122), param(P_STATUS));
            // MOVW ignores bit 0 of its address.
            assert_eq!(param(G23_P_FLAPL) % 2, 0);
            assert_eq!(param(G23_P_FLSEDL) % 2, 0);
            assert_eq!(buf % 2, 0);
        }
    }

    #[test]
    fn contiguous_blocks_are_one_run_and_erased_ones_none() {
        let block = |b: u8| vec![b; g23::BLOCK];
        let blocks = BTreeMap::from([
            (0x0000, block(1)),
            (0x0800, block(2)),
            (0x1000, block(0xFF)),
            (0x1800, block(3)),
            (0x3000, block(4)),
        ]);
        let runs: Vec<(u32, usize)> = block_runs(&blocks)
            .iter()
            .map(|(at, data)| (*at, data.len()))
            .collect();
        assert_eq!(runs, [(0x0000, 0x1000), (0x1800, 0x800), (0x3000, 0x800)]);
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
        let out = Rl78Flash {
            debug_stub: true,
            flash_protocol: false,
        }
        .debug_image(0, &page, ID, false);
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
        let out = Rl78Flash {
            debug_stub: true,
            flash_protocol: false,
        }
        .debug_image(0, &page, ID, false);
        assert_eq!(
            *out,
            page[..],
            "an ID of its own, and code where the stub goes"
        );

        let page = linked_page();
        let out = Rl78Flash {
            debug_stub: false,
            flash_protocol: false,
        }
        .debug_image(0, &page, ID, false);
        assert_eq!(out[..2], page[..2], "no stub when asked");
        assert_eq!(out[SECURITY_ID], ID, "the ID all the same");

        let tail = vec![0xFF; 0x100];
        assert_eq!(
            *Rl78Flash {
                debug_stub: true,
                flash_protocol: false,
            }
            .debug_image(0x100, &tail, ID, false),
            tail[..]
        );
    }
}
