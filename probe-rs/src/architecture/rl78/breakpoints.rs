//! Breakpoints as `FFH` traps.
//!
//! `FFH` is the illegal instruction, and with the monitor armed it enters the monitor instead of
//! resetting the part, with the PC one past it. probe-rs and GDB set breakpoints only through
//! hardware units, so the driver presents [`UNITS`] virtual ones. Setting or clearing a unit
//! records it; the traps go into memory in one batch before the target next runs or steps:
//!
//! - **In code flash**, a trap costs a 1 KB block erase and rewrite: programming only clears
//!   bits, and `FFH` sets them. So changes are applied a block at a time, each block once,
//!   and the original byte is kept to put back.
//! - **In RAM**, the byte is simply written.
//!
//! Continuing from a trap means executing the instruction under it without the trap. The trap
//! stays in flash: a copy of the instruction runs from the dead stack below the program's SP,
//! and the PC is moved back into the program (a displaced step). Only `HALT` and `STOP`, or a stack with no room under it, fall back to
//! lifting the trap, stepping, and putting it back: two block rewrites.

use std::collections::BTreeMap;

use std::time::Duration;

use super::{
    PC_ID, RAM_BASE, RAM_SIZE, Rl78, SPH_ID, SPL_ID,
    flash::{DEBUG_STUB, DEBUG_STUB_AT, DEBUG_STUB_LEN},
    protocol,
};
use crate::{BreakpointCause, CoreInterface, Error, HaltReason};

/// Virtual breakpoint units. `FFH` traps have no hardware limit.
pub(super) const UNITS: usize = 16;

/// A code flash block, the erase unit.
const BLOCK: u32 = 0x400;
const TRAP: u8 = 0xFF;

/// Breakpoints: the ones asked for, and the traps in memory with the bytes they replaced.
#[derive(Debug, Default)]
pub(super) struct Breakpoints {
    units: [Option<u32>; UNITS],
    /// A trap of the driver's own, for one boot: [`Rl78::boot_to_entry`].
    catch: Option<u32>,
    planted: BTreeMap<u32, u8>,
}

impl Breakpoints {
    /// None asked for and none in memory: nothing to do before a run or a step.
    pub(super) fn is_idle(&self) -> bool {
        self.units.iter().all(Option::is_none) && self.planted.is_empty()
    }

    fn wanted(&self, skip: Option<u32>) -> impl Iterator<Item = u32> + '_ {
        self.units
            .iter()
            .chain(std::iter::once(&self.catch))
            .flatten()
            .copied()
            .filter(move |&a| Some(a) != skip)
    }

    pub(super) fn is_planted(&self, address: u32) -> bool {
        self.planted.contains_key(&address)
    }

    /// Show the program in `data`, read from `address`, rather than the traps standing in it.
    pub(super) fn hide_traps(&self, address: u32, data: &mut [u8]) {
        let end = address.saturating_add(data.len() as u32);
        for (&a, &original) in self.planted.range(address..end) {
            data[(a - address) as usize] = original;
        }
    }

    /// Flash blocks in `range` were erased: the traps in them are gone.
    pub(super) fn erased(&mut self, range: std::ops::Range<u32>) {
        self.planted.retain(|a, _| !range.contains(a));
    }
}

fn in_ram(address: u32) -> bool {
    (RAM_BASE..RAM_BASE + RAM_SIZE as u32).contains(&address)
}

/// Bytes copied for a displaced step: the instruction (at most five, six with an `ES:` prefix)
/// and the next, which a skip jumps over.
const WINDOW: u32 = 16;
/// How far below the program's SP the copy ends: clear of what one instruction pushes (four
/// bytes), the monitor's frame on re-entry (six) and its stack under that.
const BELOW_SP: u32 = 32;

/// What an instruction does to the PC, as far as running a copy of it elsewhere is concerned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Flow {
    /// Falls through, or skips the next instruction: the PC lands in the copy.
    Plain,
    /// A branch relative to itself: the target moves with the copy.
    Relative,
    /// A branch to an absolute address, or a return.
    Absolute,
    /// A call: it pushes the address after itself, which is in the copy.
    Call {
        /// `CALL $!addr20`, relative to itself.
        relative: bool,
    },
    /// The step would not end (`HALT`, `STOP`), or it is a trap itself.
    Unsafe,
}

fn flow(code: &[u8]) -> Flow {
    // ES: is a prefix to a data access, never to a branch.
    let code = if code[0] == 0x11 { &code[1..] } else { code };
    match code[0] {
        0xFF => Flow::Unsafe,
        // BR $addr20, BR $!addr20, BC, BZ, BNC, BNZ
        0xEF | 0xEE | 0xDC..=0xDF => Flow::Relative,
        // BT, BF, BTCLR: the 31H map's low nibbles 0-5 (the rest are shifts)
        0x31 if code[1] & 0x0F <= 5 => Flow::Relative,
        // BR !addr16, BR !!addr20, RET
        0xED | 0xEC | 0xD7 => Flow::Absolute,
        // CALL !addr16, CALL !!addr20
        0xFD | 0xFC => Flow::Call { relative: false },
        // CALL $!addr20
        0xFE => Flow::Call { relative: true },
        0x61 => match code[1] {
            // BH, BNH
            0xC3 | 0xD3 => Flow::Relative,
            // BR AX, RETI, RETB
            0xCB | 0xFC | 0xEC => Flow::Absolute,
            // CALL AX/BC/DE/HL, BRK
            0xCA | 0xDA | 0xEA | 0xFA | 0xCC => Flow::Call { relative: false },
            // CALLT [addr5]
            b if b & 0x8C == 0x84 => Flow::Call { relative: false },
            // HALT, STOP
            0xED | 0xFD => Flow::Unsafe,
            _ => Flow::Plain,
        },
        _ => Flow::Plain,
    }
}

impl Rl78<'_> {
    pub(super) fn breakpoint_units(&self) -> Vec<Option<u64>> {
        self.state
            .breakpoints
            .units
            .iter()
            .map(|u| u.map(u64::from))
            .collect()
    }

    pub(super) fn set_breakpoint_unit(&mut self, unit: usize, address: u64) -> Result<(), Error> {
        let address = u32::try_from(address).unwrap_or(u32::MAX);
        if address >= super::protocol::ADDR16_BASE && !in_ram(address) {
            return Err(Error::Other(format!(
                "no breakpoint at {address:#x}: code runs from flash (below F0000H) or RAM"
            )));
        }
        *self
            .state
            .breakpoints
            .units
            .get_mut(unit)
            .ok_or_else(|| Error::Other(format!("no breakpoint unit {unit}")))? = Some(address);
        Ok(())
    }

    pub(super) fn clear_breakpoint_unit(&mut self, unit: usize) {
        if let Some(u) = self.state.breakpoints.units.get_mut(unit) {
            *u = None;
        }
    }

    /// The traps go into memory before the target next runs or steps, so a change made while it
    /// runs would wait for the next halt; but a debugger sets breakpoints whenever its user
    /// clicks. Apply the change now: halt, put the traps in, resume. A target that has stopped
    /// by itself in the meantime is left stopped, for its debugger to find; the change goes in
    /// at its next run.
    pub(super) fn apply_breakpoints_now(&mut self) -> Result<(), Error> {
        if !self.state.running || self.core_halted()? {
            return Ok(());
        }
        let sync = self.interface.halt()?;
        self.entered(sync, HaltReason::Request)?;
        self.run()
    }

    /// Boot the program and stop at its first instruction. An attach under reset halts in the
    /// boot ROM, where stepping only goes round the ROM's idle loop, and from where resuming
    /// would run the program with the watchdog and clock the attach left. So a step from there
    /// is a normal reset with a one-shot trap at the entry the debug stub branches to. The trap costs a rewrite of block 0, and another to take
    /// it out at the next run or step; only a step from the boot ROM pays it.
    pub(super) fn boot_to_entry(&mut self) -> Result<(), Error> {
        let mut stub = [0; DEBUG_STUB_LEN];
        self.read_bytes(DEBUG_STUB_AT as u64, &mut stub)?;
        if stub[..DEBUG_STUB.len()] != DEBUG_STUB {
            return Err(Error::Other(
                "the program cannot be booted under the debugger: flash has no debug stub at \
                 000CEH. Flash the program with probe-rs to add one."
                    .to_string(),
            ));
        }
        let entry = u32::from(u16::from_le_bytes([
            stub[DEBUG_STUB.len()],
            stub[DEBUG_STUB.len() + 1],
        ]));
        tracing::info!("rl78: stepping from the boot ROM: booting the program to {entry:05X}H");
        self.state.breakpoints.catch = Some(entry);
        let booted = self
            .reset()
            .and_then(|()| self.wait_for_core_halted(Duration::from_secs(2)));
        self.state.breakpoints.catch = None;
        booted?;
        let pc = self.pc()? as u32;
        if pc != entry {
            return Err(Error::Other(format!(
                "booting the program stopped at {pc:05X}H, not at its entry {entry:05X}H"
            )));
        }
        self.state.halt_reason = Some(HaltReason::Step);
        Ok(())
    }

    /// Put into memory the traps that are asked for, except at `skip`, and take out the rest.
    pub(super) fn sync_breakpoints(&mut self, skip: Option<u32>) -> Result<(), Error> {
        let want: Vec<u32> = self.state.breakpoints.wanted(skip).collect();
        let planted: Vec<u32> = self.state.breakpoints.planted.keys().copied().collect();
        let mut changes: Vec<u32> = want
            .iter()
            .filter(|a| !planted.contains(a))
            .copied()
            .collect();
        changes.extend(planted.iter().filter(|a| !want.contains(a)));
        if changes.is_empty() {
            return Ok(());
        }

        let (ram, flash): (Vec<u32>, Vec<u32>) = changes.into_iter().partition(|&a| in_ram(a));
        for address in ram {
            self.toggle_trap_in_ram(address)?;
        }
        let mut blocks: Vec<u32> = flash.iter().map(|a| a & !(BLOCK - 1)).collect();
        blocks.dedup();
        for block in blocks {
            self.rewrite_block(block, &flash)?;
        }
        Ok(())
    }

    fn toggle_trap_in_ram(&mut self, address: u32) -> Result<(), Error> {
        let byte = match self.state.breakpoints.planted.remove(&address) {
            Some(original) => original,
            None => {
                let mut original = [0];
                self.read_bytes_raw(u64::from(address), &mut original)?;
                self.state.breakpoints.planted.insert(address, original[0]);
                TRAP
            }
        };
        self.write_bytes(u64::from(address), &[byte])
    }

    /// One block: read it, put in or take out the traps at `changes` that fall in it, erase it,
    /// write it back.
    fn rewrite_block(&mut self, block: u32, changes: &[u32]) -> Result<(), Error> {
        // As it is, traps included: the ones not changing stay.
        let mut data = vec![0; BLOCK as usize];
        self.read_bytes_raw(u64::from(block), &mut data)?;
        for &address in changes.iter().filter(|a| *a & !(BLOCK - 1) == block) {
            let at = (address - block) as usize;
            let bp = &mut self.state.breakpoints;
            match bp.planted.remove(&address) {
                Some(original) => data[at] = original,
                None => {
                    bp.planted.insert(address, data[at]);
                    data[at] = TRAP;
                }
            }
        }
        tracing::debug!("rl78: rewriting block {block:05X}H for breakpoints");
        let planted = std::mem::take(&mut self.state.breakpoints.planted);
        let result = self
            .flash_erase(block..block + BLOCK)
            .and_then(|()| self.flash_write(block, &data));
        // flash_erase forgets the traps in the block; they are in `data`, written back.
        self.state.breakpoints.planted = planted;
        if result.is_err() {
            tracing::error!(
                "rl78: rewriting block {block:05X}H failed; what is in it now is unknown. \
                 Flash the program again."
            );
        }
        result
    }

    /// The target stopped by itself. A trap leaves the PC one past it; a trap the debugger
    /// planted is a breakpoint, and the PC goes back onto it. Otherwise it is an `FFH` in the
    /// program, or a reset into the monitor: the wire cannot tell those apart, only memory can.
    /// An `FFH` in the program is a software breakpoint, reported like ARM's `BKPT`:
    /// the PC on it, so a continue traps again until the PC is moved past it.
    pub(super) fn classify_stop(&mut self) -> Result<(), Error> {
        let pc = self.pc()? as u32;
        let at = pc.wrapping_sub(1);
        let cause = if self.state.breakpoints.is_planted(at) {
            BreakpointCause::Hardware
        } else {
            let mut byte = [0];
            self.read_bytes_raw(u64::from(at), &mut byte)?;
            if byte[0] != TRAP {
                tracing::info!(
                    "rl78: the target stopped by itself at PC={pc:05X}H, not after an FFH: a \
                     reset into the monitor?"
                );
                return Ok(());
            }
            tracing::debug!("rl78: the program's own FFH at {at:05X}H");
            BreakpointCause::Software
        };
        self.load_context()?.set(PC_ID, at);
        self.state.halt_reason = Some(HaltReason::Breakpoint(cause));
        Ok(())
    }

    /// Before the target runs from a breakpoint, the instruction under it has to run. Returns
    /// whether it stepped.
    pub(super) fn step_off_breakpoint(&mut self) -> Result<bool, Error> {
        if self.state.breakpoints.is_idle() {
            return Ok(false);
        }
        let pc = self.pc()? as u32;
        if !self.state.breakpoints.wanted(None).any(|a| a == pc) {
            return Ok(false);
        }
        self.step_over_traps()?;
        Ok(true)
    }

    /// Step one instruction with every breakpoint in place, the one at the PC included when it
    /// can be stepped displaced; otherwise that one is lifted for the step.
    pub(super) fn step_over_traps(&mut self) -> Result<(), Error> {
        let pc = self.pc()? as u32;
        self.sync_breakpoints(None)?;
        if self.state.breakpoints.is_planted(pc) && self.step_displaced(pc)? {
            return Ok(());
        }
        self.sync_breakpoints(Some(pc))?;
        self.step_raw()
    }

    /// Step the instruction at `pc` by running a copy of it from the dead stack below the
    /// program's SP, and move the PC back into the program. Returns false, having done nothing,
    /// when it cannot: `HALT` or `STOP` at `pc`, or no room under the stack.
    fn step_displaced(&mut self, pc: u32) -> Result<bool, Error> {
        let mut code = [0; WINDOW as usize];
        self.read_bytes(u64::from(pc), &mut code)?;
        let flow = flow(&code);
        let ctx = self.load_context()?;
        let sp = u32::from(ctx.regs[usize::from(SPH_ID)] as u8) << 8
            | u32::from(ctx.regs[usize::from(SPL_ID)] as u8);
        let at = (protocol::ADDR16_BASE | sp).wrapping_sub(BELOW_SP + WINDOW);
        if flow == Flow::Unsafe || at < RAM_BASE {
            return Ok(false);
        }
        let copy = at..at + WINDOW;
        let moved = |a: u32| a.wrapping_sub(at).wrapping_add(pc) & 0xF_FFFF;

        ctx.set(PC_ID, at);
        // The program's RAM back first, so that the instruction sees it; then the copy.
        let sync = self.store_context()?;
        self.interface.write_mem(at, &code)?;
        let sync = self
            .interface
            .execute(sync, true)?
            .expect("a step returns the re-entry sync");
        self.entered(sync, HaltReason::Step)?;

        let landed = self.pc()? as u32;
        let (new_pc, pushed) = match flow {
            Flow::Plain if copy.contains(&landed) => (moved(landed), false),
            // Out of the copy without a branch: an interrupt, to an absolute vector, with the
            // address in the copy pushed.
            Flow::Plain => (landed, true),
            Flow::Relative => (moved(landed), false),
            Flow::Absolute => (landed, false),
            Flow::Call { relative } => (if relative { moved(landed) } else { landed }, true),
            Flow::Unsafe => unreachable!(),
        };
        if pushed {
            // CALL, BRK and an interrupt push the return address at the new SP, low byte first.
            let ctx = self.load_context()?;
            let sp = protocol::ADDR16_BASE
                | u32::from(ctx.regs[usize::from(SPH_ID)] as u8) << 8
                | u32::from(ctx.regs[usize::from(SPL_ID)] as u8);
            let mut ret = [0; 3];
            self.interface.read_mem(sp, &mut ret)?;
            let address = u32::from_le_bytes([ret[0], ret[1], ret[2] & 0x0F, 0]);
            if copy.contains(&address) {
                let fixed = moved(address).to_le_bytes();
                let ret = [fixed[0], fixed[1], ret[2] & 0xF0 | fixed[2]];
                self.interface.write_mem(sp, &ret)?;
            }
        }
        tracing::debug!("rl78: stepped {pc:05X}H from a copy at {at:05X}H, to {new_pc:05X}H");
        self.load_context()?.set(PC_ID, new_pc);
        Ok(true)
    }

    /// The program counter is on a breakpoint that is asked for: the target would trap there
    /// before executing anything.
    pub(super) fn at_breakpoint(&mut self) -> Result<bool, Error> {
        let pc = self.pc()? as u32;
        Ok(self.state.breakpoints.wanted(None).any(|a| a == pc))
    }

    /// Take every trap out of memory, for the end of a session. A running target is halted for
    /// it and resumed after.
    pub(super) fn lift_all_breakpoints(&mut self) -> Result<(), Error> {
        if self.state.breakpoints.planted.is_empty() {
            return Ok(());
        }
        let was_running = self.state.running;
        if was_running {
            let sync = self.interface.halt()?;
            self.entered(sync, HaltReason::Request)?;
        }
        self.state.breakpoints.units = [None; UNITS];
        self.sync_breakpoints(None)?;
        if was_running {
            let sync = self.store_context()?;
            self.interface.execute(sync, false)?;
            self.state.running = true;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flow_of_each_kind() {
        let cases: &[(&[u8], Flow)] = &[
            (&[0xF6], Flow::Plain),                                      // clrw ax
            (&[0x11, 0x8F, 0x34, 0x12], Flow::Plain),                    // mov a, es:!0x1234
            (&[0x31, 0x0B], Flow::Plain), // sar a, 0 (31H map, a shift)
            (&[0x61, 0xC8], Flow::Plain), // skc
            (&[0xEF, 0xFE], Flow::Relative), // br $.
            (&[0xEE, 0, 0], Flow::Relative), // br $!addr20
            (&[0xDD, 0], Flow::Relative), // bz
            (&[0x61, 0xD3, 0], Flow::Relative), // bnh
            (&[0x31, 0x94, 0x20, 0], Flow::Relative), // bf 0xfff20.1
            (&[0x31, 0xA1, 0], Flow::Relative), // btclr [hl].2
            (&[0xED, 0x34, 0x12], Flow::Absolute), // br !0x1234
            (&[0xEC, 0x45, 0x23, 0x01], Flow::Absolute), // br !!0x12345
            (&[0x61, 0xCB], Flow::Absolute), // br ax
            (&[0xD7], Flow::Absolute),    // ret
            (&[0x61, 0xFC], Flow::Absolute), // reti
            (&[0x61, 0xEC], Flow::Absolute), // retb
            (&[0xFD, 0x34, 0x12], Flow::Call { relative: false }), // call !0x1234
            (&[0xFC, 0x45, 0x23, 0x01], Flow::Call { relative: false }), // call !!0x12345
            (&[0xFE, 0, 0], Flow::Call { relative: true }), // call $!addr20
            (&[0x61, 0xFA], Flow::Call { relative: false }), // call hl
            (&[0x61, 0x84], Flow::Call { relative: false }), // callt [0x80]
            (&[0x61, 0xF7], Flow::Call { relative: false }), // callt [0xbe]
            (&[0x61, 0xCC], Flow::Call { relative: false }), // brk
            (&[0x61, 0xED], Flow::Unsafe), // halt
            (&[0x61, 0xFD], Flow::Unsafe), // stop
            (&[0xFF], Flow::Unsafe),
        ];
        for (code, expected) in cases {
            let mut window = [0; 4];
            window[..code.len()].copy_from_slice(code);
            assert_eq!(flow(&window), *expected, "{code:02X?}");
        }
    }

    #[test]
    fn erase_forgets_traps() {
        let mut bp = Breakpoints::default();
        bp.planted.insert(0x0410, 0x12);
        bp.planted.insert(0x0900, 0x34);
        bp.erased(0x0400..0x0800);
        assert!(!bp.is_planted(0x0410));
        assert!(bp.is_planted(0x0900));
    }
}
