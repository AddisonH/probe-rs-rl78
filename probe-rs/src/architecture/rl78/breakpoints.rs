//! Breakpoints on a part with no breakpoint hardware (§42): `FFH` traps (§24).
//!
//! `FFH` is the illegal instruction, and with the monitor armed it enters the monitor instead of
//! resetting the part, with the PC one past it. probe-rs and GDB set breakpoints only through
//! hardware units, so the driver presents [`UNITS`] virtual ones. Setting or clearing a unit
//! records it; the traps go into memory in one batch before the target next runs or steps:
//!
//! - **In code flash**, a trap costs a 1 KB block erase and rewrite: programming only clears
//!   bits, and `FFH` sets them (§24.2). So changes are applied a block at a time, each block once,
//!   and the original byte is kept to put back.
//! - **In RAM**, the byte is simply written.
//!
//! Continuing from a trap means executing the instruction under it: that one is lifted, the
//! instruction stepped, and the batch applied again before the run. That costs two block
//! rewrites per continue; Renesas's server runs the instruction on a host simulator instead.

use std::collections::BTreeMap;

use super::{PC_ID, RAM_BASE, RAM_SIZE, Rl78};
use crate::{BreakpointCause, Error, HaltReason};

/// Virtual breakpoint units. `FFH` traps have no hardware limit; this is what Renesas's engine
/// reports for the G15 (`GetMonEventNumMax`, §43.5).
pub(super) const UNITS: usize = 16;

/// A code flash block, the erase unit [g15:p672].
const BLOCK: u32 = 0x400;
const TRAP: u8 = 0xFF;

/// Breakpoints: the ones asked for, and the traps in memory with the bytes they replaced.
#[derive(Debug, Default)]
pub(super) struct Breakpoints {
    units: [Option<u32>; UNITS],
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
            .flatten()
            .copied()
            .filter(move |&a| Some(a) != skip)
    }

    /// The traps that are in memory.
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
    /// planted is a breakpoint, and the PC goes back onto it. Anything else is an `FFH` that is
    /// not ours (erased flash, say) or a reset into the monitor: the wire cannot tell those apart,
    /// only the PC can (§28.4).
    pub(super) fn classify_stop(&mut self) -> Result<(), Error> {
        let pc = self.pc()? as u32;
        let at = pc.wrapping_sub(1);
        if self.state.breakpoints.is_planted(at) {
            self.load_context()?.set(PC_ID, at);
            self.state.halt_reason = Some(HaltReason::Breakpoint(BreakpointCause::Hardware));
        } else {
            tracing::info!(
                "rl78: the target stopped by itself at PC={pc:05X}H, not at a breakpoint: an FFH \
                 the debugger did not plant (erased flash?), or a reset"
            );
        }
        Ok(())
    }

    /// Before the target runs or steps from a planted trap, the instruction under it has to run:
    /// lift that trap alone and step it. Returns whether it stepped.
    pub(super) fn step_off_breakpoint(&mut self) -> Result<bool, Error> {
        if self.state.breakpoints.is_idle() {
            return Ok(false);
        }
        let pc = self.pc()? as u32;
        if !self.state.breakpoints.wanted(None).any(|a| a == pc) {
            return Ok(false);
        }
        self.sync_breakpoints(Some(pc))?;
        self.step_raw()?;
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
    fn erase_forgets_traps() {
        let mut bp = Breakpoints::default();
        bp.planted.insert(0x0410, 0x12);
        bp.planted.insert(0x0900, 0x34);
        bp.erased(0x0400..0x0800);
        assert!(!bp.is_planted(0x0410));
        assert!(bp.is_planted(0x0900));
    }
}
