//! Stops at an exact address with no flash write, from the two execution-address comparators at
//! `F0081H` and `F0083H`.
//!
//! A comparator matches the start of an executed instruction and stops the program at the first
//! instruction boundary at least four CPU clocks later. So matching an instruction four clocks
//! ahead of an address stops the program on it, and matching one of four clocks or more, such as
//! `RET`, stops it on whatever runs next. A breakpoint the target is about to meet is reached that
//! way when the code on the way there is known, which [`Rl78::next_leg`] works out from the PC:
//!
//! - **Straight there.** The target is on the path the code takes from the PC whatever the data,
//!   calls included: each callee is run to its return with comparators on its `RET`s. The program
//!   is stopped an instruction short of the target, or of a call, and stepped the rest of the way.
//!   That absorbs a stop that comes early (wait states, an interrupt) and one that an instruction
//!   holding interrupts pending puts off.
//! - **Out first.** The target cannot be reached before the current function returns:
//!   comparators on its `RET`s, then straight there from the return address.
//!
//! Anything else (a conditional branch on the way, an indirect jump or call, more `RET`s than
//! comparators, the target inside a callee or an interrupt handler) gets an `FFH` trap as before.

use std::collections::BTreeSet;

use super::{
    CODE_BLOCK, Rl78, SPH_ID, SPL_ID,
    isa::{self, Flow, Insn},
};
use crate::{BreakpointCause, Error, HaltReason};

const COMPARATORS: u32 = 0xF_0081;
/// A comparator's reset value: `00001H` is never an instruction's start.
const OFF: u16 = 0x0001;
/// The highest address a comparator reaches: it has 15 bits.
const REACH: u32 = 0x8000;

/// The interrupt vectors, after the reset vector and the word at `00002H`.
const VECTORS: std::ops::Range<u32> = 0x04..0x80;
/// Below this are the vectors and the `CALLT` table: a vector that points there, at `0000H` as
/// unused ones do, has no handler.
const CODE_START: u32 = 0xC0;

/// Instructions walked for one decision, at most.
const WALK_LIMIT: usize = 4096;
/// Legs in one run, and stops at a `RET` that returned somewhere else.
const LEG_LIMIT: usize = 16;
const REARM_LIMIT: usize = 64;

/// A run to one breakpoint that is not in memory, by comparators.
#[derive(Debug)]
pub(super) struct Plan {
    target: u32,
    leg: Leg,
    legs: usize,
    rearms: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Leg {
    /// Along `path`, whose last instruction is the target or a call: run with a comparator on
    /// `arm` to stop short of the end, or, with none, step the whole way.
    Aim { arm: Option<u32>, path: Vec<u32> },
    /// Run until a function returns: comparators on its `RET`s.
    Return { rets: Vec<u32>, done: Returned },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Returned {
    /// The callee of a call: back at `to` with SP at `sp`.
    To { to: u32, sp: u16 },
    /// The current function, whose frame is at or above `sp`.
    Out { sp: u16 },
}

/// What the code does from an address whatever the data, as far as the target, a call, or the
/// first instruction whose successor depends on the data.
struct Straight {
    path: Vec<(u32, Insn)>,
    end: End,
}

enum End {
    Target,
    Call { callee: u32, to: u32 },
    Other,
}

impl Rl78<'_> {
    /// Start a run that stops at `target` by comparators. False, having done nothing, when the
    /// code on the way there does not allow it.
    pub(super) fn run_to_by_comparators(&mut self, target: u32) -> Result<bool, Error> {
        if target >= REACH || self.pc()? as u32 == target {
            return Ok(false);
        }
        let Some(leg) = self.next_leg(target)? else {
            tracing::debug!("rl78: no way to {target:05X}H by comparators: a trap instead");
            return Ok(false);
        };
        tracing::debug!("rl78: running to {target:05X}H by comparators: {leg:x?}");
        self.sync_breakpoints(&[target])?;
        self.state.plan = Some(Plan {
            target,
            leg: leg.clone(),
            legs: 1,
            rearms: 0,
        });
        self.start_leg(leg)?;
        Ok(true)
    }

    /// The target stopped while a plan runs.
    pub(super) fn plan_stopped(&mut self) -> Result<(), Error> {
        self.disarm()?;
        let Some(mut plan) = self.state.plan.take() else {
            return self.classify_stop();
        };
        let pc = self.pc()? as u32;
        if self.state.breakpoints.is_planted(pc.wrapping_sub(1)) {
            // A breakpoint of the user's on the way.
            return self.classify_stop();
        }
        match plan.leg.clone() {
            Leg::Aim { path, .. } => {
                if !path.contains(&pc) {
                    tracing::debug!("rl78: a comparator stopped the target off its path");
                    return self.plan_fallback(plan.target);
                }
                self.state.plan = Some(plan);
                self.step_along(&path)
            }
            Leg::Return { rets, done } => {
                let sp = self.user_sp()?;
                let back = match done {
                    Returned::To { to, sp: at } => pc == to && sp == at,
                    Returned::Out { sp: at } => sp > at,
                };
                if back {
                    self.state.plan = Some(plan);
                    return self.leg_done();
                }
                if plan.rearms >= REARM_LIMIT || !self.after_a_call(pc)? {
                    return self.plan_fallback(plan.target);
                }
                // A return from a deeper call of the same function.
                plan.rearms += 1;
                self.state.plan = Some(plan);
                self.start_leg(Leg::Return { rets, done })
            }
        }
    }

    /// Give up on comparators: put the target's trap in and run on.
    fn plan_fallback(&mut self, target: u32) -> Result<(), Error> {
        tracing::debug!("rl78: running to {target:05X}H by a trap instead");
        self.state.plan = None;
        self.resume_plain()
    }

    fn resume_plain(&mut self) -> Result<(), Error> {
        self.sync_breakpoints(&[])?;
        let sync = self.store_context()?;
        self.interface.execute(sync, false)?;
        self.state.running = true;
        self.state.halt_reason = None;
        Ok(())
    }

    fn start_leg(&mut self, leg: Leg) -> Result<(), Error> {
        let arms = match &leg {
            Leg::Aim { arm: None, path } => return self.step_along(path),
            Leg::Aim { arm: Some(at), .. } => [*at, OFF.into()],
            Leg::Return { rets, .. } => [rets[0], rets.get(1).copied().unwrap_or(OFF.into())],
        };
        if let Some(plan) = &mut self.state.plan {
            plan.leg = leg;
        }
        self.arm(arms)?;
        let sync = self.store_context()?;
        self.interface.execute(sync, false)?;
        self.state.running = true;
        self.state.halt_reason = None;
        Ok(())
    }

    /// Single steps from somewhere on `path` to its end.
    fn step_along(&mut self, path: &[u32]) -> Result<(), Error> {
        let end = *path.last().expect("a path is never empty");
        loop {
            let pc = self.pc()? as u32;
            if self.state.breakpoints.is_planted(pc) {
                // The user's breakpoint, met before the target.
                self.state.plan = None;
                self.state.halt_reason = Some(HaltReason::Breakpoint(BreakpointCause::Hardware));
                return Ok(());
            }
            if pc == end {
                return self.leg_done();
            }
            let Some(at) = path.iter().position(|&a| a == pc) else {
                let target = self.state.plan.as_ref().map_or(end, |p| p.target);
                return self.plan_fallback(target);
            };
            self.step_raw()?;
            if self.pc()? as u32 != path[at + 1] {
                let target = self.state.plan.as_ref().map_or(end, |p| p.target);
                return self.plan_fallback(target);
            }
        }
    }

    /// A leg reached its end: the target, or the next leg.
    fn leg_done(&mut self) -> Result<(), Error> {
        let Some(mut plan) = self.state.plan.take() else {
            return Ok(());
        };
        if self.pc()? as u32 == plan.target {
            self.state.halt_reason = Some(HaltReason::Breakpoint(BreakpointCause::Hardware));
            return Ok(());
        }
        plan.legs += 1;
        let next = if plan.legs > LEG_LIMIT {
            None
        } else {
            self.next_leg(plan.target)?
        };
        match next {
            Some(leg) => {
                let target = plan.target;
                self.state.plan = Some(plan);
                if let Leg::Aim { arm: None, .. } = leg {
                    tracing::trace!("rl78: stepping on to {target:05X}H");
                }
                self.start_leg(leg)
            }
            None => self.plan_fallback(plan.target),
        }
    }

    /// The first leg towards `target` from the PC, if the code allows the whole way there.
    fn next_leg(&mut self, target: u32) -> Result<Option<Leg>, Error> {
        let pc = self.pc()? as u32;
        let sp = self.user_sp()?;
        let Some(handlers) = self.interrupt_code()? else {
            tracing::debug!("rl78: what the interrupt handlers run is unknown");
            return Ok(None);
        };
        if handlers.contains(&target) {
            tracing::debug!("rl78: {target:05X}H is in an interrupt handler");
            return Ok(None);
        }
        if let Some(leg) = self.straight_there(pc, sp, target)? {
            return Ok(Some(leg));
        }
        // Out first: the target is nowhere the function can go before it returns.
        let mut seen = BTreeSet::new();
        let mut rets = Vec::new();
        let mut calls = Vec::new();
        if !self.explore(pc, &mut seen, &mut rets, &mut calls)? {
            tracing::debug!("rl78: where the function at {pc:05X}H goes is unknown");
            return Ok(None);
        }
        if seen.contains(&target) {
            tracing::debug!("rl78: {target:05X}H is behind a branch");
            return Ok(None);
        }
        let Some(callees) = self.closure(&calls)? else {
            tracing::debug!("rl78: what the function at {pc:05X}H calls is unknown");
            return Ok(None);
        };
        if callees.contains(&target) || rets.is_empty() || rets.len() > 2 {
            tracing::debug!(
                "rl78: {target:05X}H is in a callee, or the function has {} RETs",
                rets.len()
            );
            return Ok(None);
        }
        Ok(Some(Leg::Return {
            rets,
            done: Returned::Out { sp },
        }))
    }

    /// The first leg of a way to `target` that is the same whatever the data, calls included.
    fn straight_there(&mut self, pc: u32, sp: u16, target: u32) -> Result<Option<Leg>, Error> {
        let mut first = None;
        let mut at = pc;
        for _ in 0..LEG_LIMIT {
            let straight = self.straight(at, target)?;
            let leg = match straight.end {
                End::Target => {
                    return Ok(Some(first.unwrap_or_else(|| aim(&straight.path))));
                }
                End::Other => return Ok(None),
                End::Call { callee, to } => {
                    let Some(code) = self.closure(&[callee])? else {
                        return Ok(None);
                    };
                    let mut rets = Vec::new();
                    self.explore(callee, &mut BTreeSet::new(), &mut rets, &mut Vec::new())?;
                    if code.contains(&target) || rets.is_empty() || rets.len() > 2 {
                        return Ok(None);
                    }
                    if straight.path.len() == 1 {
                        // At the call: the callee's return is the leg.
                        Leg::Return {
                            rets,
                            done: Returned::To { to, sp },
                        }
                    } else {
                        aim(&straight.path)
                    }
                }
            };
            first.get_or_insert(leg);
            let End::Call { to, .. } = straight.end else {
                unreachable!()
            };
            at = to;
        }
        Ok(None)
    }

    /// Walk from `at` while the next instruction does not depend on the data.
    fn straight(&mut self, mut at: u32, target: u32) -> Result<Straight, Error> {
        let mut path = Vec::new();
        loop {
            if path.len() >= WALK_LIMIT || path.iter().any(|&(a, _)| a == at) {
                return Ok(Straight {
                    path,
                    end: End::Other,
                });
            }
            if at == target {
                path.push((at, self.insn(at)?.unwrap_or(STOPPED)));
                return Ok(Straight {
                    path,
                    end: End::Target,
                });
            }
            let Some(insn) = self.insn(at)? else {
                return Ok(Straight {
                    path,
                    end: End::Other,
                });
            };
            path.push((at, insn));
            let next = at + insn.len;
            match insn.flow {
                Flow::Next => at = next,
                Flow::Jump(to) => at = to,
                Flow::Call(callee) => {
                    return Ok(Straight {
                        path,
                        end: End::Call { callee, to: next },
                    });
                }
                Flow::CallTable(entry) => {
                    let end = match self.code_word(entry)? {
                        Some(callee) => End::Call { callee, to: next },
                        None => End::Other,
                    };
                    return Ok(Straight { path, end });
                }
                _ => {
                    return Ok(Straight {
                        path,
                        end: End::Other,
                    });
                }
            }
        }
    }

    /// Every instruction reachable from `from` before it returns, not following calls: their
    /// targets go into `calls`, the returns into `rets`. False if an indirect jump or call, or
    /// something that is no instruction, makes that unknowable.
    fn explore(
        &mut self,
        from: u32,
        seen: &mut BTreeSet<u32>,
        rets: &mut Vec<u32>,
        calls: &mut Vec<u32>,
    ) -> Result<bool, Error> {
        let mut todo = vec![from];
        while let Some(at) = todo.pop() {
            if !seen.insert(at) {
                continue;
            }
            if seen.len() > WALK_LIMIT {
                return Ok(false);
            }
            let Some(insn) = self.insn(at)? else {
                tracing::debug!("rl78: no instruction at {at:05X}H");
                return Ok(false);
            };
            let next = at + insn.len;
            match insn.flow {
                Flow::Next | Flow::Wait => todo.push(next),
                Flow::Jump(to) => todo.push(to),
                Flow::Branch(to) => todo.extend([to, next]),
                Flow::Skip => {
                    let Some(skipped) = self.insn(next)? else {
                        return Ok(false);
                    };
                    todo.extend([next, next + skipped.len]);
                }
                Flow::Call(callee) => {
                    calls.push(callee);
                    todo.push(next);
                }
                Flow::CallTable(entry) => {
                    let Some(callee) = self.code_word(entry)? else {
                        return Ok(false);
                    };
                    calls.push(callee);
                    todo.push(next);
                }
                Flow::Return => rets.push(at),
                Flow::CallIndirect | Flow::JumpIndirect => {
                    tracing::debug!("rl78: an indirect jump or call at {at:05X}H");
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }

    /// The code that functions at `entries` can run, through their calls. `None` if that is
    /// unknowable.
    fn closure(&mut self, entries: &[u32]) -> Result<Option<BTreeSet<u32>>, Error> {
        let mut seen = BTreeSet::new();
        let mut todo = entries.to_vec();
        let mut done = BTreeSet::new();
        while let Some(entry) = todo.pop() {
            if !done.insert(entry) {
                continue;
            }
            let mut calls = Vec::new();
            if !self.explore(entry, &mut seen, &mut Vec::new(), &mut calls)? {
                return Ok(None);
            }
            todo.extend(calls);
        }
        Ok(Some(seen))
    }

    /// The code the interrupt handlers can run, `None` if that is unknowable.
    fn interrupt_code(&mut self) -> Result<Option<BTreeSet<u32>>, Error> {
        let mut handlers = Vec::new();
        for vector in VECTORS.step_by(2) {
            if let Some(handler) = self.code_word(vector)?
                && handler >= CODE_START
                && self.code_flash().contains(&handler)
            {
                handlers.push(handler);
            }
        }
        self.closure(&handlers)
    }

    /// Whether `pc` follows a call: where a `RET` lands.
    fn after_a_call(&mut self, pc: u32) -> Result<bool, Error> {
        for len in 2..=4 {
            let at = pc.wrapping_sub(len);
            if let Some(insn) = self.insn(at)?
                && insn.len == len
                && matches!(
                    insn.flow,
                    Flow::Call(_) | Flow::CallTable(_) | Flow::CallIndirect
                )
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn code_flash(&self) -> std::ops::Range<u32> {
        0..self.sequence.code_flash_mirror().end
    }

    /// The instruction at `at`, as the program has it: `None` outside code flash or for bytes
    /// that are no instruction.
    fn insn(&mut self, at: u32) -> Result<Option<Insn>, Error> {
        let mut code = [0; 6];
        if !self.code(at, &mut code)? {
            return Ok(None);
        }
        Ok(isa::decode(&code, at))
    }

    /// The 16-bit word at `at` in code flash.
    fn code_word(&mut self, at: u32) -> Result<Option<u32>, Error> {
        let mut word = [0; 2];
        Ok(self
            .code(at, &mut word)?
            .then(|| u32::from(u16::from_le_bytes(word))))
    }

    /// Code flash with the traps hidden, kept until flash is written. False past its end.
    fn code(&mut self, at: u32, out: &mut [u8]) -> Result<bool, Error> {
        let flash = self.code_flash();
        if !flash.contains(&at) {
            return Ok(false);
        }
        for (a, byte) in (at..).zip(out.iter_mut()) {
            if !flash.contains(&a) {
                *byte = 0xFF;
                continue;
            }
            let block = a & !(CODE_BLOCK - 1);
            if !self.state.code_image.contains_key(&block) {
                let mut bytes = [0; CODE_BLOCK as usize];
                self.read_bytes(u64::from(block), &mut bytes)?;
                self.state.code_image.insert(block, bytes);
            }
            *byte = self.state.code_image[&block][(a - block) as usize];
        }
        Ok(true)
    }

    fn user_sp(&mut self) -> Result<u16, Error> {
        let ctx = self.load_context()?;
        Ok(u16::from(ctx.regs[usize::from(SPH_ID)] as u8) << 8
            | u16::from(ctx.regs[usize::from(SPL_ID)] as u8))
    }

    fn arm(&mut self, at: [u32; 2]) -> Result<(), Error> {
        let mut regs = [0; 4];
        regs[..2].copy_from_slice(&(at[0] as u16).to_le_bytes());
        regs[2..].copy_from_slice(&(at[1] as u16).to_le_bytes());
        self.interface.write_mem(COMPARATORS, &regs)?;
        self.state.armed = true;
        Ok(())
    }

    pub(super) fn disarm(&mut self) -> Result<(), Error> {
        if self.state.armed {
            self.arm([OFF.into(), OFF.into()])?;
            self.state.armed = false;
        }
        Ok(())
    }
}

/// Stands in for an instruction at the target that does not decode: it is never executed.
const STOPPED: Insn = Insn {
    len: 1,
    flow: Flow::Wait,
    clocks: 0,
    holds: false,
};

/// A leg along `path` to its last instruction: a comparator to stop an instruction short of it,
/// more for each instruction on the way that can hold the stop off, then steps.
fn aim(path: &[(u32, Insn)]) -> Leg {
    let addresses: Vec<u32> = path.iter().map(|&(a, _)| a).collect();
    let end = path.len() - 1;
    let mut stop = end.saturating_sub(1);
    while stop > 0 {
        // The latest match whose stop, four clocks on, is no later than `stop`.
        let mut clocks = 0;
        let mut arm = None;
        for j in (0..stop).rev() {
            clocks += u32::from(path[j].1.clocks);
            if clocks >= 4 {
                arm = Some(j);
                break;
            }
        }
        let Some(arm) = arm else {
            break;
        };
        let holds = path[arm..stop].iter().filter(|(_, i)| i.holds).count();
        if stop + holds <= end {
            return Leg::Aim {
                arm: Some(path[arm].0),
                path: addresses,
            };
        }
        stop -= 1;
    }
    Leg::Aim {
        arm: None,
        path: addresses,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn insn(clocks: u8, holds: bool) -> Insn {
        Insn {
            len: 1,
            flow: Flow::Next,
            clocks,
            holds,
        }
    }

    fn path(clocks: &[u8]) -> Vec<(u32, Insn)> {
        (0..)
            .zip(clocks)
            .map(|(a, &c)| (a, insn(c, false)))
            .collect()
    }

    #[test]
    fn aim_stops_one_instruction_short() {
        // Ones from 0: a match on 1 stops at 5, one short of the end at 6.
        let leg = aim(&path(&[1, 1, 1, 1, 1, 1, 1]));
        assert_eq!(
            leg,
            Leg::Aim {
                arm: Some(1),
                path: (0..7).collect()
            }
        );
        // A three-clock BR at 2: 2 and 3 make four, a match on 2 stops at 4.
        let leg = aim(&path(&[1, 1, 3, 1, 1, 1]));
        assert_eq!(
            leg,
            Leg::Aim {
                arm: Some(2),
                path: (0..6).collect()
            }
        );
    }

    #[test]
    fn aim_steps_when_the_way_is_short() {
        let leg = aim(&path(&[1, 1, 1, 1]));
        assert_eq!(
            leg,
            Leg::Aim {
                arm: None,
                path: (0..4).collect()
            }
        );
        assert_eq!(
            aim(&path(&[1])),
            Leg::Aim {
                arm: None,
                path: vec![0]
            }
        );
    }

    #[test]
    fn aim_leaves_room_for_held_stops() {
        // EI at 3 can put the stop off by an instruction, to the end at worst.
        let mut p = path(&[1, 1, 1, 1, 1, 1, 1, 1]);
        p[3].1.holds = true;
        assert_eq!(
            aim(&p),
            Leg::Aim {
                arm: Some(2),
                path: (0..8).collect()
            }
        );
        // Two would put it past the end: aim one shorter.
        p[4].1.holds = true;
        assert_eq!(
            aim(&p),
            Leg::Aim {
                arm: Some(1),
                path: (0..8).collect()
            }
        );
    }
}
