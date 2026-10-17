//! Renesas RL78 support.
//!
//! The RL78's debug monitor is a 512-byte mask ROM running on the target's own CPU, entered as an
//! interrupt. That shapes everything here:
//!
//! - **Halting is an interrupt.** The monitor's prologue (`0EFE00H`) does `SEL RB0`, `PUSH AX`,
//!   `PUSH HL`, so the interrupted program's state is split between an interrupt frame on its
//!   stack, the bytes the monitor transmits on entry, and RAM. None of them alone is the register
//!   file; see [`Rl78::load_context`].
//! - **Resuming is `RETI`.** There is no "run to address": the resume address is chosen by
//!   writing the interrupt frame at SP before `5CH`.
//! - **Every monitor entry locks the session**, so the unlock is repeated after every halt and
//!   step.
//! - **Only `F0000H`–`FFFFFH` is directly reachable.** Everything below it, code flash included,
//!   is read by a short routine staged in RAM and called through the monitor's call gate. That
//!   RAM belongs to the user's program, so the bytes a routine overwrites are saved before it
//!   runs and put back before the target runs again.

use std::{
    collections::BTreeMap,
    ops::Range,
    time::{Duration, Instant},
};

use crate::{
    CoreInformation, CoreInterface, CoreRegister, CoreStatus, CoreType, Error, HaltReason,
    InstructionSet, MemoryInterface,
    core::{Architecture, RegisterId, RegisterValue},
    memory::valid_32bit_address,
};

mod breakpoints;
pub mod communication_interface;
mod comparators;
mod flash;
mod g23;
mod isa;
pub mod protocol;
pub mod registers;
pub mod sequences;

pub use flash::Rl78Flash;
pub(crate) use flash::attach_or_recover;

#[cfg(test)]
mod scripted;

use communication_interface::{Rl78Error, Rl78OcdInterface, Rrm};
use probe_rs_target::Rl78Monitor;
use protocol::Sync;
use registers::*;
use sequences::Rl78DebugSequence;

/// All of RAM on the RL78/G15: `FFB00H`–`FFEFFH`.
const RAM_BASE: u32 = 0xF_FB00;
const RAM_SIZE: usize = 0x400;

/// Where host routines are staged. Low, deliberately: a routine runs on the interrupted
/// program's stack, and placed high its first push would land on itself. Low, it stays clear of
/// the monitor's own stack (SP = `FFC00H` on a fresh attach, growing down), which caps a routine
/// at a little under 250 bytes.
const STUB_BASE: u32 = 0xF_FB00;
const STUB_MAX: usize = 0xF0;

/// A bare `5BH` makes the ROM `CALL !!0FFED0H`. A branch to the staged routine goes here, and the
/// routine returns with `RET`.
const CALL_GATE: u32 = 0xF_FED0;

/// Where a routine leaves its results (`5BH` replies only with the `00H` prompt, so results come
/// back through an ordinary read) and the flash routine finds its data, with its operands in the
/// [`STUB_BUF_BELOW`] bytes under it. Chosen per halt, clear of the monitor's stack: low
/// by preference, above the boot ROM's stack (`FFC00H` down, on a fresh attach) and below where
/// programs keep theirs (the top of RAM); high when the program's stack is low.
const STUB_BUFS: [u32; 2] = [0xF_FC10, 0xF_FDC0];
const STUB_BUF_SIZE: usize = 256;
const STUB_BUF_BELOW: usize = 10;

/// Memory below `F0000H` is read in aligned blocks of this size and kept until the target next
/// runs: GDB reads code a byte at a time around the PC, and each read is a routine. Every memory
/// area below `F0000H` (code flash, data flash, the OCD ROM) is a multiple of it in size and
/// alignment, so a block never reaches past the area it was asked for into reserved space.
const CODE_BLOCK: u32 = 64;

const STUB_TIMEOUT: Duration = Duration::from_secs(1);

/// Bytes below the monitor's SP that its own calls use while a routine runs: the call gate's
/// return address, and the ROM's transmit routine after it.
const MONITOR_STACK_BELOW: u32 = 8;

/// The four register banks, bank 3 first.
const BANKS_ADDR: u32 = 0xF_FEE0;
const SP_ADDR: u32 = 0xF_FFF8;
/// CS, ES, PMC and MEM are contiguous.
const CS_ADDR: u32 = 0xF_FFFC;

/// The interrupt frame the monitor leaves at SP: the AX its prologue pushed, then the PC and PSW
/// the debug interrupt pushed. HL is pushed too, but popped again before the command loop runs,
/// so by the time the host reads SP it points at the AX slot.
const FRAME_LEN: usize = 6;

const PSW_RBS0: u8 = 1 << 3;
const PSW_RBS1: u8 = 1 << 5;

/// Copy `count` bytes from `ES:[HL]` to the buffer, to reach below `F0000H`, which the monitor's
/// own read cannot: it addresses through `[HL]` with 16-bit addressing.
///
/// ```text
///         mov   es, #seg          ; [1]
///         movw  hl, #addr16       ; [3][4]
///         movw  de, #buf          ; [6][7]; [DE] takes no ES prefix, so F-segment
///         mov   b, #count         ; [9], 0 means 256
/// loop:   mov   a, es:[hl]
///         mov   [de], a
///         incw  hl
///         incw  de
///         dec   b
///         bnz   $loop
///         ret
/// ```
const STUB_READ20: [u8; 19] = [
    0x41, 0x00, // mov  es, #seg
    0x36, 0x00, 0x00, // movw hl, #addr16
    0x34, 0x00, 0x00, // movw de, #buf
    0x53, 0x00, // mov  b, #count
    0x11, 0x8B, // mov  a, es:[hl]
    0x99, // mov  [de], a
    0xA7, // incw hl
    0xA5, // incw de
    0x93, // dec  b
    0xDF, 0xF8, // bnz  loop
    0xD7, // ret
];
const READ20_SEG: usize = 1;
const READ20_ADDR: usize = 3;
const READ20_BUF: usize = 6;
const READ20_COUNT: usize = 9;

/// Offset of a bank register within one read of `FFEE0H`–`FFEFFH`. Banks are numbered 0..3 but
/// laid out 3..0.
fn bank_offset(bank: usize, reg: usize) -> usize {
    (3 - bank) * 8 + reg
}

/// The interrupted program's registers, valid while it is halted.
#[derive(Debug, Clone)]
struct Context {
    /// SP while the monitor runs. The frame is here and the user's SP is six bytes above.
    monitor_sp: u16,
    /// Raw registers, in GDB order.
    regs: [u32; NUM_RAW],
    dirty: u64,
}

impl Context {
    fn user_bank(&self) -> usize {
        let psw = self.regs[usize::from(PSW_ID)] as u8;
        usize::from(psw & PSW_RBS0 != 0) | usize::from(psw & PSW_RBS1 != 0) << 1
    }

    /// Change a register. Writing the value it already has is not a change: GDB's `G` packet
    /// writes every register, SP included, and SP cannot actually be moved while halted.
    fn set(&mut self, id: u16, value: u32) {
        if self.regs[usize::from(id)] != value {
            self.regs[usize::from(id)] = value;
            self.dirty |= 1 << id;
        }
    }

    /// Write `id` back on the way out even if the debugger did not change it.
    fn touch(&mut self, id: u16) {
        self.dirty |= 1 << id;
    }

    fn is_dirty(&self, id: u16) -> bool {
        self.dirty & (1 << id) != 0
    }
}

/// RL78 state that outlives a [`Rl78`] handle.
#[derive(Debug, Default)]
pub struct Rl78CoreState {
    running: bool,
    halt_reason: Option<HaltReason>,
    /// B, C, H and L as the monitor reported them at the last entry.
    sync: Sync,
    /// The register file, read lazily after each halt.
    context: Option<Box<Context>>,
    /// The user's RAM under what the debugger borrowed this halt.
    ram_shadow: RamShadow,
    /// Memory below `F0000H` read this halt, in [`CODE_BLOCK`]s.
    code_cache: BTreeMap<u32, [u8; CODE_BLOCK as usize]>,
    /// Code flash as the program has it, traps hidden, kept until flash is written.
    code_image: BTreeMap<u32, [u8; CODE_BLOCK as usize]>,
    /// A run to a breakpoint by the execution-address comparators.
    plan: Option<comparators::Plan>,
    /// A comparator holds an address.
    armed: bool,
    /// The flash routine is staged at `STUB_BASE`, with the call gate pointing at it.
    flash_resident: bool,
    stub_buf: Option<u32>,
    /// `FSSET` for the clock the program left running, read once per halt.
    fsset: Option<u8>,
    /// Halted where an attach under reset leaves the part: the boot ROM's idle loop, before the
    /// program has run at all.
    at_boot_rom: bool,
    /// Breakpoints asked for and traps in memory. Traps in flash outlive a reset.
    breakpoints: Box<breakpoints::Breakpoints>,
    /// The session's attach halted a running program, and nothing has run, stepped, reset or
    /// reflashed it since: the end of the session lets it run on, as it found it.
    resume_at_detach: bool,
    /// Whether the program answers pseudo-RRM: `None` until it is first tried while running,
    /// and again after the program is reflashed. It outlives resets.
    rrm: Option<bool>,
}

/// The bytes of the user's RAM that the debugger saved before first overwriting them this halt:
/// a routine's code, the call gate, the part of the buffer the routine fills, and bank 0's
/// registers, which the routines use.
#[derive(Debug, Default)]
struct RamShadow(BTreeMap<u32, u8>);

impl RamShadow {
    fn unsaved(&self, range: Range<u32>) -> Vec<Range<u32>> {
        let mut runs: Vec<Range<u32>> = Vec::new();
        for a in range.filter(|a| !self.0.contains_key(a)) {
            match runs.last_mut() {
                Some(run) if run.end == a => run.end += 1,
                _ => runs.push(a..a + 1),
            }
        }
        runs
    }

    fn save(&mut self, start: u32, bytes: &[u8]) {
        for (a, &b) in (start..).zip(bytes) {
            self.0.insert(a, b);
        }
    }

    fn get(&self, address: u32) -> Option<u8> {
        self.0.get(&address).copied()
    }

    /// Change a saved byte; false if `address` is not saved.
    fn update(&mut self, address: u32, value: u8) -> bool {
        match self.0.get_mut(&address) {
            Some(b) => {
                *b = value;
                true
            }
            None => false,
        }
    }

    /// The saved bytes as contiguous runs, in address order.
    fn runs(&self) -> Vec<(u32, Vec<u8>)> {
        let mut runs: Vec<(u32, Vec<u8>)> = Vec::new();
        for (&a, &b) in &self.0 {
            match runs.last_mut() {
                Some((start, bytes)) if *start + bytes.len() as u32 == a => bytes.push(b),
                _ => runs.push((a, vec![b])),
            }
        }
        runs
    }

    fn len(&self) -> usize {
        self.0.len()
    }
}

impl Rl78CoreState {
    /// A fresh state.
    pub fn new() -> Self {
        Self::default()
    }

    pub(crate) fn attached(&mut self, attached: flash::Attached) {
        let (sync, at_boot_rom) = match attached {
            flash::Attached::Running(sync) => (sync, false),
            flash::Attached::UnderReset(sync) => (sync, true),
        };
        *self = Self {
            sync,
            halt_reason: Some(HaltReason::Request),
            at_boot_rom,
            resume_at_detach: !at_boot_rom,
            breakpoints: std::mem::take(&mut self.breakpoints),
            rrm: self.rrm,
            ..Self::default()
        };
    }
}

/// An RL78 core.
pub struct Rl78<'probe> {
    interface: &'probe mut dyn Rl78OcdInterface,
    state: &'probe mut Rl78CoreState,
    sequence: std::sync::Arc<dyn Rl78DebugSequence>,
}

impl<'probe> Rl78<'probe> {
    /// Create a core handle.
    pub fn new(
        interface: &'probe mut dyn Rl78OcdInterface,
        state: &'probe mut Rl78CoreState,
        sequence: std::sync::Arc<dyn Rl78DebugSequence>,
    ) -> Result<Self, Error> {
        Ok(Self {
            interface,
            state,
            sequence,
        })
    }

    /// Halted where an attach under reset leaves the part, the program not yet started, and
    /// the debugger has not moved the PC to start it somewhere itself.
    fn in_boot_rom(&self) -> bool {
        self.state.at_boot_rom
            && !self
                .state
                .context
                .as_ref()
                .is_some_and(|ctx| ctx.is_dirty(PC_ID))
    }

    /// Start the program from the attach state as a reset would, by pointing the monitor's
    /// return at the reset vector's target with PSW, CS and ES at their reset values. The G23
    /// monitor answers no halt after a normal boot, so its programs are started this way.
    fn start_at_entry(&mut self) -> Result<u32, Error> {
        let mut vector = [0; 2];
        self.read_bytes(0, &mut vector)?;
        let entry = u32::from(u16::from_le_bytes(vector));
        if entry == 0xFFFF {
            return Err(Error::Other("code flash has no reset vector".into()));
        }
        let ctx = self.load_context()?;
        ctx.set(PC_ID, entry);
        ctx.set(PSW_ID, 0x06);
        ctx.set(CS_ID, 0x00);
        ctx.set(ES_ID, 0x0F);
        self.state.at_boot_rom = false;
        tracing::info!("rl78: starting the program at its entry {entry:05X}H");
        Ok(entry)
    }

    fn require_halted(&self, what: &'static str) -> Result<(), Error> {
        if self.state.running {
            return Err(Rl78Error::NotHalted(what).into());
        }
        Ok(())
    }

    /// Read the interrupted program's register file.
    ///
    /// This is not "read `FFEE0H`–`FFEFFH`". The monitor's prologue does `SEL RB0`, so while it
    /// runs, bank 0's RAM holds the monitor's registers, not the user's:
    ///
    /// | bank 0 | source |
    /// |---|---|
    /// | X, A | the interrupt frame: the prologue pushed AX after `SEL RB0` |
    /// | B, C, H, L | the entry sync: the monitor sends them because it is about to overwrite them |
    /// | D, E | RAM: the monitor's command loop never touches DE |
    ///
    /// That holds whichever bank the program was using, since the prologue saves bank 0 in every
    /// case. Banks 1 to 3 are untouched and read straight from RAM. PSW and SP come from the
    /// frame, not from `FFFFAH`/`FFFF8H`, which hold the monitor's own values.
    fn load_context(&mut self) -> Result<&mut Context, Error> {
        if self.state.context.is_none() && self.g23() {
            self.require_halted("reading registers")?;
            let ctx = self.load_context_g23()?;
            self.state.context = Some(Box::new(ctx));
        }
        if self.state.context.is_none() {
            self.require_halted("reading registers")?;
            let mut sp = [0; 2];
            self.interface.read_mem(SP_ADDR, &mut sp)?;
            let monitor_sp = u16::from_le_bytes(sp);
            let mut frame = [0; FRAME_LEN];
            self.interface
                .read_mem(protocol::ADDR16_BASE | u32::from(monitor_sp), &mut frame)?;
            let mut banks = [0; 32];
            self.read_f_segment(BANKS_ADDR, &mut banks)?;
            let mut sfr = [0; 4];
            self.interface.read_mem(CS_ADDR, &mut sfr)?;

            let s = self.state.sync;
            let b0 = bank_offset(0, 0);
            banks[b0] = frame[0];
            banks[b0 + 1] = frame[1];
            banks[b0 + 2] = s.c;
            banks[b0 + 3] = s.b;
            banks[b0 + 6] = s.l;
            banks[b0 + 7] = s.h;

            let mut regs = [0; NUM_RAW];
            for bank in 0..4 {
                for r in 0..8 {
                    regs[bank * 8 + r] = u32::from(banks[bank_offset(bank, r)]);
                }
            }
            let user_sp = monitor_sp.wrapping_add(FRAME_LEN as u16);
            regs[usize::from(PSW_ID)] = u32::from(frame[5]);
            regs[usize::from(PC_ID)] = u32::from_le_bytes([frame[2], frame[3], frame[4] & 0x0F, 0]);
            regs[usize::from(SPL_ID)] = u32::from(user_sp as u8);
            regs[usize::from(SPH_ID)] = u32::from(user_sp >> 8);
            regs[usize::from(CS_ID)] = u32::from(sfr[0]);
            regs[usize::from(ES_ID)] = u32::from(sfr[1]);
            regs[usize::from(PMC_ID)] = u32::from(sfr[2]);
            regs[usize::from(MEM_ID)] = u32::from(sfr[3]);

            tracing::debug!(
                "rl78: halted at PC={:05X}H PSW={:02X}H SP={user_sp:04X}H",
                regs[usize::from(PC_ID)],
                frame[5]
            );
            self.state.context = Some(Box::new(Context {
                monitor_sp,
                regs,
                dirty: 0,
            }));
        }
        Ok(self.state.context.as_mut().expect("loaded above"))
    }

    /// The G23 monitor's version of [`load_context`](Self::load_context): bank 0's X, A, C, B,
    /// L and H, the PC and the PSW are in its context block, ES is in bank 0's C, and D, E and
    /// SP are the program's as they stand.
    fn load_context_g23(&mut self) -> Result<Context, Error> {
        let mut block = [0; g23::CONTEXT_LEN];
        self.interface.read_mem(g23::CONTEXT, &mut block)?;
        let mut banks = [0; 32];
        self.read_f_segment(BANKS_ADDR, &mut banks)?;
        let mut sp = [0; 2];
        self.interface.read_mem(SP_ADDR, &mut sp)?;
        let mut sfr = [0; 4];
        self.interface.read_mem(CS_ADDR, &mut sfr)?;

        let b0 = bank_offset(0, 0);
        sfr[1] = banks[b0 + 2];
        banks[b0..b0 + 4].copy_from_slice(&[block[0], block[1], block[4], block[5]]);
        banks[b0 + 6..b0 + 8].copy_from_slice(&block[2..4]);

        let mut regs = [0; NUM_RAW];
        for bank in 0..4 {
            for r in 0..8 {
                regs[bank * 8 + r] = u32::from(banks[bank_offset(bank, r)]);
            }
        }
        regs[usize::from(PSW_ID)] = u32::from(block[9]);
        regs[usize::from(PC_ID)] = u32::from_le_bytes([block[6], block[7], block[8] & 0x0F, 0]);
        regs[usize::from(SPL_ID)] = u32::from(sp[0]);
        regs[usize::from(SPH_ID)] = u32::from(sp[1]);
        for (i, id) in [CS_ID, ES_ID, PMC_ID, MEM_ID].into_iter().enumerate() {
            regs[usize::from(id)] = u32::from(sfr[i]);
        }
        tracing::debug!(
            "rl78: halted at PC={:05X}H PSW={:02X}H SP={:02X}{:02X}H",
            regs[usize::from(PC_ID)],
            block[9],
            sp[1],
            sp[0]
        );
        Ok(Context {
            monitor_sp: u16::from_le_bytes(sp),
            regs,
            dirty: 0,
        })
    }

    /// The G23 monitor's version of [`store_context`](Self::store_context).
    fn store_context_g23(&mut self, ctx: &Context) -> Result<(), Error> {
        let r = |id: u16| ctx.regs[usize::from(id)] as u8;
        if [0, 1, 2, 3, 6, 7, PC_ID, PSW_ID]
            .into_iter()
            .any(|id| ctx.is_dirty(id))
        {
            let pc = ctx.regs[usize::from(PC_ID)].to_le_bytes();
            let block = [
                r(0),
                r(1),
                r(6),
                r(7),
                r(2),
                r(3),
                pc[0],
                pc[1],
                pc[2] & 0x0F,
                r(PSW_ID),
            ];
            self.interface.write_mem(g23::CONTEXT, &block)?;
        }
        for id in (4..32u16).filter(|&id| !matches!(id, 6 | 7) && ctx.is_dirty(id)) {
            let (bank, reg) = (usize::from(id / 8), usize::from(id % 8));
            self.interface
                .write_mem(BANKS_ADDR + bank_offset(bank, reg) as u32, &[r(id)])?;
        }
        if ctx.is_dirty(ES_ID) {
            self.interface
                .write_mem(BANKS_ADDR + bank_offset(0, 2) as u32, &[r(ES_ID)])?;
        }
        for (i, id) in [CS_ID, PMC_ID, MEM_ID].into_iter().enumerate() {
            if ctx.is_dirty(id) {
                let at = CS_ADDR + [0, 2, 3][i];
                self.interface.write_mem(at, &[r(id)])?;
            }
        }
        if ctx.is_dirty(SPL_ID) || ctx.is_dirty(SPH_ID) {
            self.interface.write_mem(SP_ADDR, &[r(SPL_ID), r(SPH_ID)])?;
        }
        Ok(())
    }

    /// Write back whatever the debugger changed, ready for a resume or a step, and return the
    /// B, C, H and L to load on the way out.
    fn store_context(&mut self) -> Result<Sync, Error> {
        // RAM first: the register banks and the frame live inside it, so restoring it afterwards
        // would undo them.
        self.ram_return()?;

        let Some(ctx) = self.state.context.take() else {
            return Ok(self.state.sync);
        };
        if self.g23() {
            if let Err(e) = self.store_context_g23(&ctx) {
                self.state.context = Some(ctx);
                return Err(e);
            }
            return Ok(self.state.sync);
        }
        if ctx.is_dirty(SPL_ID) || ctx.is_dirty(SPH_ID) {
            self.state.context = Some(ctx);
            return Err(Error::Other(
                "SP cannot be written while halted: the debug interrupt frame lives at SP".into(),
            ));
        }

        let mut sync = self.state.sync;
        let mut frame_dirty = ctx.is_dirty(PC_ID) || ctx.is_dirty(PSW_ID);
        for id in 0..32u16 {
            if !ctx.is_dirty(id) {
                continue;
            }
            let (bank, r) = (usize::from(id / 8), usize::from(id % 8));
            let v = ctx.regs[usize::from(id)] as u8;
            match (bank, r) {
                (0, 0 | 1) => frame_dirty = true,
                (0, 2) => sync.c = v,
                (0, 3) => sync.b = v,
                (0, 6) => sync.l = v,
                (0, 7) => sync.h = v,
                _ => self
                    .interface
                    .write_mem(BANKS_ADDR + bank_offset(bank, r) as u32, &[v])?,
            }
        }
        for (i, id) in [CS_ID, ES_ID, PMC_ID, MEM_ID].into_iter().enumerate() {
            if ctx.is_dirty(id) {
                self.interface
                    .write_mem(CS_ADDR + i as u32, &[ctx.regs[usize::from(id)] as u8])?;
            }
        }
        if frame_dirty {
            let pc = ctx.regs[usize::from(PC_ID)].to_le_bytes();
            let frame = [
                ctx.regs[0] as u8,
                ctx.regs[1] as u8,
                pc[0],
                pc[1],
                pc[2] & 0x0F,
                ctx.regs[usize::from(PSW_ID)] as u8,
            ];
            self.interface
                .write_mem(protocol::ADDR16_BASE | u32::from(ctx.monitor_sp), &frame)?;
        }
        Ok(sync)
    }

    /// Execute one instruction, whatever is at the PC.
    fn step_raw(&mut self) -> Result<(), Error> {
        let sync = self.store_context()?;
        let sync = self
            .interface
            .execute(sync, true)?
            .expect("a step returns the re-entry sync");
        self.entered(sync, HaltReason::Step)
    }

    /// The target stopped (a halt, a step, or by itself): unlock and forget the old context.
    fn entered(&mut self, sync: Sync, reason: HaltReason) -> Result<(), Error> {
        self.state.running = false;
        self.state.sync = sync;
        self.state.context = None;
        self.state.ram_shadow = RamShadow::default();
        self.state.code_cache.clear();
        self.state.flash_resident = false;
        self.state.stub_buf = None;
        self.state.fsset = None;
        self.state.at_boot_rom = false;
        self.state.halt_reason = Some(reason);
        self.interface.unlock()?;
        Ok(())
    }

    fn pc(&mut self) -> Result<u64, Error> {
        Ok(u64::from(self.load_context()?.regs[usize::from(PC_ID)]))
    }

    /// Save the user's RAM in `range` before the debugger overwrites it, once per halt and only
    /// the bytes not saved already.
    fn ram_borrow(&mut self, range: Range<u32>) -> Result<(), Error> {
        let range = range.start.max(RAM_BASE)..range.end.min(RAM_BASE + RAM_SIZE as u32);
        for run in self.state.ram_shadow.unsaved(range) {
            let mut bytes = vec![0; run.len()];
            self.interface.read_mem(run.start, &mut bytes)?;
            self.state.ram_shadow.save(run.start, &bytes);
            tracing::debug!("rl78: saved RAM {:05X}H-{:05X}H", run.start, run.end - 1);
        }
        Ok(())
    }

    fn ram_return(&mut self) -> Result<(), Error> {
        self.state.flash_resident = false;
        let shadow = std::mem::take(&mut self.state.ram_shadow);
        for (start, bytes) in shadow.runs() {
            if let Err(e) = self.interface.write_mem(start, &bytes) {
                tracing::error!(
                    "rl78: could not restore RAM; the program's memory is what the debugger left"
                );
                self.state.ram_shadow = shadow;
                return Err(e.into());
            }
        }
        if shadow.len() > 0 {
            tracing::debug!("rl78: restored {} bytes of RAM", shadow.len());
        }
        Ok(())
    }

    /// Check that RAM the debugger is about to use is clear of the monitor's stack. While the
    /// program is halted, the monitor runs on the program's stack, and a routine or buffer
    /// written over it would wreck the monitor's return address.
    fn check_scratch(&mut self, scratch: Range<u32>) -> Result<(), Error> {
        let stack = self.monitor_stack()?;
        if scratch.start < stack.end && stack.start < scratch.end {
            let sp = stack.start + MONITOR_STACK_BELOW;
            return Err(Error::Other(format!(
                "the program's stack (SP {:05X}H) reaches {:05X}H-{:05X}H, which the debugger \
                 needs for its routines",
                sp + FRAME_LEN as u32,
                scratch.start,
                scratch.end - 1
            )));
        }
        Ok(())
    }

    /// The RAM the monitor's stack uses while it runs a routine.
    fn monitor_stack(&mut self) -> Result<Range<u32>, Error> {
        let sp = protocol::ADDR16_BASE | u32::from(self.load_context()?.monitor_sp);
        let frame = if self.g23() { 0 } else { FRAME_LEN as u32 };
        Ok(sp - MONITOR_STACK_BELOW..sp + frame)
    }

    /// The monitor is the G23's, not the G15's.
    fn g23(&self) -> bool {
        self.interface.monitor() == Rl78Monitor::G23
    }

    /// The routines' buffer for this halt: the first of [`STUB_BUFS`] the monitor's stack leaves
    /// alone, with the operands below it.
    fn stub_buf(&mut self) -> Result<u32, Error> {
        if let Some(buf) = self.state.stub_buf {
            return Ok(buf);
        }
        let stack = self.monitor_stack()?;
        let buf = STUB_BUFS
            .into_iter()
            .find(|&buf| {
                let used = buf - STUB_BUF_BELOW as u32..buf + STUB_BUF_SIZE as u32;
                used.end <= stack.start || stack.end <= used.start
            })
            .expect("the candidates are further apart than the monitor's stack is long");
        self.state.stub_buf = Some(buf);
        Ok(buf)
    }

    fn stage_stub(&mut self, code: &[u8]) -> Result<(), Error> {
        if code.is_empty() || code.len() > STUB_MAX {
            return Err(Error::Other(format!(
                "a {}-byte routine does not fit in 1..={STUB_MAX} bytes",
                code.len()
            )));
        }
        let stub = STUB_BASE..STUB_BASE + code.len() as u32;
        self.check_scratch(stub.clone())?;
        self.ram_borrow(stub)?;
        // The G23's gate is the monitor's own memory, not the program's.
        let gate = if self.g23() { g23::GATE } else { CALL_GATE };
        if !self.g23() {
            self.check_scratch(gate..gate + 4)?;
            self.ram_borrow(gate..gate + 4)?;
        }
        self.state.flash_resident = false;
        self.interface.write_mem(STUB_BASE, code)?;
        // BR !!STUB_BASE
        let s = STUB_BASE.to_le_bytes();
        self.interface
            .write_mem(gate, &[0xEC, s[0], s[1], s[2] & 0x0F])?;
        Ok(())
    }

    /// Stage a routine in RAM and call it through the monitor's call gate. It writes `out`.
    fn run_stub(&mut self, code: &[u8], out: Range<u32>) -> Result<(), Error> {
        self.routine_runs()?;
        self.stage_stub(code)?;
        self.ram_borrow(out)?;
        self.interface.call_stub(STUB_TIMEOUT)?;
        Ok(())
    }

    /// A routine is about to run behind `5BH`. It changes ES (the read routine sets it, and ES
    /// comes back as its reset value 0FH besides), and the program's ES is only in the context:
    /// mark it to be written back, or the program resumes with the routine's. It also works in
    /// bank 0, whose registers are RAM; D and E there are the program's (see
    /// [`load_context`](Self::load_context)), so bank 0 is borrowed like the rest.
    pub(super) fn routine_runs(&mut self) -> Result<(), Error> {
        self.load_context()?.touch(ES_ID);
        let bank0 = BANKS_ADDR + bank_offset(0, 0) as u32;
        self.ram_borrow(bank0..bank0 + 8)
    }

    /// Read anywhere in the 20-bit space by running [`STUB_READ20`] and reading its buffer.
    fn read_far(&mut self, address: u32, data: &mut [u8]) -> Result<(), Error> {
        // What the mirror shows, the monitor reads directly: no routine, no borrowed RAM.
        let mirror = self.sequence.code_flash_mirror();
        if let Some((d, _)) = overlap(address, data.len(), mirror) {
            let (head, rest) = data.split_at_mut(d.start);
            let (mirrored, tail) = rest.split_at_mut(d.len());
            self.read_far_by_routine(address, head)?;
            self.read_f_segment(protocol::ADDR16_BASE + address + d.start as u32, mirrored)?;
            return self.read_far_by_routine(address + d.end as u32, tail);
        }
        self.read_far_by_routine(address, data)
    }

    /// Read below `F0000H` through [`CODE_BLOCK`]s kept for the halt, reading the missing ones
    /// by routine, as many to a run as the buffer holds.
    fn read_far_by_routine(&mut self, address: u32, data: &mut [u8]) -> Result<(), Error> {
        if data.is_empty() {
            return Ok(());
        }
        let end = address + data.len() as u32;
        let missing: Vec<u32> = (address & !(CODE_BLOCK - 1)..end)
            .step_by(CODE_BLOCK as usize)
            .filter(|b| !self.state.code_cache.contains_key(b))
            .collect();
        let per_run = STUB_BUF_SIZE / CODE_BLOCK as usize;
        let mut i = 0;
        while i < missing.len() {
            let start = missing[i];
            let mut n = 1;
            while n < per_run
                && i + n < missing.len()
                && missing[i + n] == start + n as u32 * CODE_BLOCK
            {
                n += 1;
            }
            let mut blocks = vec![0; n * CODE_BLOCK as usize];
            self.read_far_uncached(start, &mut blocks)?;
            let (blocks, _) = blocks.as_chunks::<{ CODE_BLOCK as usize }>();
            for (k, block) in blocks.iter().enumerate() {
                self.state
                    .code_cache
                    .insert(start + k as u32 * CODE_BLOCK, *block);
            }
            i += n;
        }
        for (a, byte) in (address..).zip(data.iter_mut()) {
            *byte = self.state.code_cache[&(a & !(CODE_BLOCK - 1))][(a % CODE_BLOCK) as usize];
        }
        Ok(())
    }

    fn read_far_uncached(&mut self, mut address: u32, data: &mut [u8]) -> Result<(), Error> {
        let buf = self.stub_buf()?;
        for chunk in data.chunks_mut(STUB_BUF_SIZE) {
            let mut code = STUB_READ20;
            code[READ20_SEG] = (address >> 16) as u8 & 0x0F;
            code[READ20_ADDR..READ20_ADDR + 2].copy_from_slice(&(address as u16).to_le_bytes());
            code[READ20_BUF..READ20_BUF + 2].copy_from_slice(&(buf as u16).to_le_bytes());
            code[READ20_COUNT] = chunk.len() as u8; // 256 encodes as 0
            self.run_stub(&code, buf..buf + chunk.len() as u32)?;
            self.interface.read_mem(buf, chunk)?;
            address += chunk.len() as u32;
        }
        Ok(())
    }

    /// Read in `F0000H`–`FFFFFH`, seeing the user's RAM rather than what the debugger borrowed.
    fn read_f_segment(&mut self, address: u32, data: &mut [u8]) -> Result<(), Error> {
        self.interface.read_mem(address, data)?;
        for (a, byte) in (address..).zip(data.iter_mut()) {
            if let Some(saved) = self.state.ram_shadow.get(a) {
                *byte = saved;
            }
        }
        Ok(())
    }

    /// Memory as the program has it: with the bytes that breakpoint traps replaced.
    fn read_bytes(&mut self, address: u64, data: &mut [u8]) -> Result<(), Error> {
        if self.state.running {
            // Without the monitor the register banks are the registers themselves, and there
            // are no traps where pseudo-RRM reaches.
            return self.read_running(address, data);
        }
        self.read_bytes_raw(address, data)?;
        self.state.breakpoints.hide_traps(address as u32, data);
        // In RAM, bank 0 is the monitor's scratch while it runs.
        if let Some((d, offsets)) = banks_overlap(address as u32, data.len()) {
            let ctx = self.load_context()?;
            for (byte, o) in data[d].iter_mut().zip(offsets) {
                *byte = ctx.regs[usize::from(bank_byte_id(o))] as u8;
            }
        }
        Ok(())
    }

    /// Memory as it is, breakpoint traps included.
    fn read_bytes_raw(&mut self, address: u64, data: &mut [u8]) -> Result<(), Error> {
        self.require_halted("memory access")?;
        let start = valid_32bit_address(address)?;
        let end = u64::from(start) + data.len() as u64;
        if end > 0x10_0000 {
            return Err(Error::Other(format!(
                "{address:#x}+{} is outside the 20-bit address space",
                data.len()
            )));
        }
        let split = (protocol::ADDR16_BASE.saturating_sub(start) as usize).min(data.len());
        let (far, near) = data.split_at_mut(split);
        if !far.is_empty() {
            self.read_far(start, far)?;
        }
        if !near.is_empty() {
            self.read_f_segment(start + split as u32, near)?;
        }
        Ok(())
    }

    fn write_bytes(&mut self, address: u64, data: &[u8]) -> Result<(), Error> {
        if self.state.running {
            return self.write_running(address, data);
        }
        let start = valid_32bit_address(address)?;
        if start < protocol::ADDR16_BASE {
            return Err(Rl78Error::Unsupported("writing below F0000H (code flash)").into());
        }
        if start as usize + data.len() > 0x10_0000 {
            return Err(Error::Other(format!(
                "{address:#x}+{} is outside the 20-bit address space",
                data.len()
            )));
        }
        // The register banks are registers: they go into the context, which puts them where
        // they belong on the way out. Written directly, bank 0 would land in the monitor's own
        // registers while its write loop runs on them.
        if let Some((d, offsets)) = banks_overlap(start, data.len()) {
            self.write_memory(start, &data[..d.start])?;
            let ctx = self.load_context()?;
            for (&byte, o) in data[d.clone()].iter().zip(offsets) {
                ctx.set(bank_byte_id(o), u32::from(byte));
            }
            return self.write_memory(start + d.end as u32, &data[d.end..]);
        }
        self.write_memory(start, data)
    }
}

impl Rl78<'_> {
    /// The program's code changed: whether it answers pseudo-RRM may have too.
    pub(super) fn forget_rrm(&mut self) {
        self.state.rrm = None;
    }

    /// Check that `len` bytes at `start` can be reached while the program runs.
    fn running_access(&self, what: &'static str, start: u64, len: usize) -> Result<u32, Error> {
        let start = valid_32bit_address(start)?;
        let end = start as u64 + len as u64;
        let in_window = |lo: u32, hi: u32| start >= lo && end <= u64::from(hi);
        if self.state.rrm == Some(false)
            || !(in_window(0xF_0000, 0xF_0800) || in_window(0xF_DF00, 0x10_0000))
        {
            return Err(Rl78Error::NotWhileRunning(what).into());
        }
        Ok(start)
    }

    /// Memory while the program runs, through pseudo-RRM. If the target stops during the read
    /// (a breakpoint), the halt is taken and the read finished halted.
    fn read_running(&mut self, address: u64, data: &mut [u8]) -> Result<(), Error> {
        let start = self.running_access("reading memory", address, data.len())?;
        let done = self.interface.rrm_read(start, data);
        match self.rrm_answered("reading memory", done)? {
            Rrm::Done => Ok(()),
            Rrm::Stopped(sync) => {
                self.stopped_during_rrm(sync)?;
                self.read_bytes(address, data)
            }
        }
    }

    /// Memory written while the program runs, through pseudo-DMM.
    fn write_running(&mut self, address: u64, data: &[u8]) -> Result<(), Error> {
        let start = self.running_access("writing memory", address, data.len())?;
        let done = self.interface.rrm_write(start, data);
        match self.rrm_answered("writing memory", done)? {
            Rrm::Done => Ok(()),
            Rrm::Stopped(sync) => {
                self.stopped_during_rrm(sync)?;
                self.write_bytes(address, data)
            }
        }
    }

    /// Pseudo-RRM is the program's to enable, with a block pointer at `00002H`. The
    /// debugger does not read the vector: it tries, and a ROM with the path off says nothing to
    /// the commands, none of which is the halt byte. The first silence settles it until the
    /// program is reflashed.
    fn rrm_answered(
        &mut self,
        what: &'static str,
        done: Result<Rrm, Rl78Error>,
    ) -> Result<Rrm, Error> {
        match done {
            Err(Rl78Error::RrmUnanswered(_)) if self.state.rrm.is_none() => {
                self.state.rrm = Some(false);
                Err(Rl78Error::NotWhileRunning(what).into())
            }
            Err(e) => Err(e.into()),
            Ok(done) => {
                self.state.rrm = Some(true);
                Ok(done)
            }
        }
    }

    fn stopped_during_rrm(&mut self, sync: protocol::Sync) -> Result<(), Error> {
        self.entered(sync, HaltReason::Unknown)?;
        self.classify_stop()
    }

    /// Write memory in the F-segment, outside the register banks.
    fn write_memory(&mut self, start: u32, data: &[u8]) -> Result<(), Error> {
        // Where the debugger has borrowed RAM, the user's bytes are the saved copy: change that,
        // and it goes back to the target on resume. Write the rest directly.
        let mut direct: Vec<(u32, Vec<u8>)> = Vec::new();
        for (a, &byte) in (start..).zip(data) {
            if self.state.ram_shadow.update(a, byte) {
                continue;
            }
            match direct.last_mut() {
                Some((s, bytes)) if *s + bytes.len() as u32 == a => bytes.push(byte),
                _ => direct.push((a, vec![byte])),
            }
        }
        for (a, bytes) in direct {
            self.interface.write_mem(a, &bytes)?;
        }
        Ok(())
    }
}

/// Where `len` bytes at `address` overlap the register banks: the range within the data, and
/// the offsets from [`BANKS_ADDR`].
fn banks_overlap(address: u32, len: usize) -> Option<(Range<usize>, Range<usize>)> {
    overlap(address, len, BANKS_ADDR..BANKS_ADDR + 32)
}

fn overlap(address: u32, len: usize, area: Range<u32>) -> Option<(Range<usize>, Range<usize>)> {
    let lo = address.max(area.start);
    let hi = (address + len as u32).min(area.end);
    (lo < hi).then(|| {
        (
            (lo - address) as usize..(hi - address) as usize,
            (lo - area.start) as usize..(hi - area.start) as usize,
        )
    })
}

/// The raw register id of the bank byte at `offset` from [`BANKS_ADDR`]: bank 3 is lowest.
fn bank_byte_id(offset: usize) -> u16 {
    ((3 - offset / 8) * 8 + offset % 8) as u16
}

impl MemoryInterface for Rl78<'_> {
    fn supports_native_64bit_access(&mut self) -> bool {
        false
    }

    fn read_64(&mut self, address: u64, data: &mut [u64]) -> Result<(), Error> {
        let mut buf = vec![0; data.len() * 8];
        self.read_bytes(address, &mut buf)?;
        for (d, c) in data.iter_mut().zip(buf.as_chunks::<8>().0) {
            *d = u64::from_le_bytes(*c);
        }
        Ok(())
    }

    fn read_32(&mut self, address: u64, data: &mut [u32]) -> Result<(), Error> {
        let mut buf = vec![0; data.len() * 4];
        self.read_bytes(address, &mut buf)?;
        for (d, c) in data.iter_mut().zip(buf.as_chunks::<4>().0) {
            *d = u32::from_le_bytes(*c);
        }
        Ok(())
    }

    fn read_16(&mut self, address: u64, data: &mut [u16]) -> Result<(), Error> {
        let mut buf = vec![0; data.len() * 2];
        self.read_bytes(address, &mut buf)?;
        for (d, c) in data.iter_mut().zip(buf.as_chunks::<2>().0) {
            *d = u16::from_le_bytes(*c);
        }
        Ok(())
    }

    fn read_8(&mut self, address: u64, data: &mut [u8]) -> Result<(), Error> {
        self.read_bytes(address, data)
    }

    fn read(&mut self, address: u64, data: &mut [u8]) -> Result<(), Error> {
        self.read_bytes(address, data)
    }

    fn write_64(&mut self, address: u64, data: &[u64]) -> Result<(), Error> {
        let buf: Vec<u8> = data.iter().flat_map(|w| w.to_le_bytes()).collect();
        self.write_bytes(address, &buf)
    }

    fn write_32(&mut self, address: u64, data: &[u32]) -> Result<(), Error> {
        let buf: Vec<u8> = data.iter().flat_map(|w| w.to_le_bytes()).collect();
        self.write_bytes(address, &buf)
    }

    fn write_16(&mut self, address: u64, data: &[u16]) -> Result<(), Error> {
        let buf: Vec<u8> = data.iter().flat_map(|w| w.to_le_bytes()).collect();
        self.write_bytes(address, &buf)
    }

    fn write_8(&mut self, address: u64, data: &[u8]) -> Result<(), Error> {
        self.write_bytes(address, data)
    }

    fn write(&mut self, address: u64, data: &[u8]) -> Result<(), Error> {
        self.write_bytes(address, data)
    }

    fn supports_8bit_transfers(&self) -> Result<bool, Error> {
        Ok(true)
    }

    fn flush(&mut self) -> Result<(), Error> {
        Ok(())
    }
}

impl CoreInterface for Rl78<'_> {
    fn wait_for_core_halted(&mut self, timeout: Duration) -> Result<(), Error> {
        let start = Instant::now();
        while !self.core_halted()? {
            if start.elapsed() >= timeout {
                return Err(Error::Timeout);
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        Ok(())
    }

    fn core_halted(&mut self) -> Result<bool, Error> {
        if self.state.running
            && let Some(sync) = self.interface.poll_stopped()?
        {
            self.entered(sync, HaltReason::Unknown)?;
            if self.state.armed {
                self.plan_stopped()?;
            } else {
                self.classify_stop()?;
            }
        }
        Ok(!self.state.running)
    }

    fn status(&mut self) -> Result<CoreStatus, Error> {
        Ok(if self.core_halted()? {
            CoreStatus::Halted(self.state.halt_reason.unwrap_or(HaltReason::Unknown))
        } else {
            CoreStatus::Running
        })
    }

    fn halt(&mut self, _timeout: Duration) -> Result<CoreInformation, Error> {
        let planned = self.state.plan.take().is_some();
        // Poll first: if it stopped by itself just now, a halt byte would draw a second sync.
        if !self.core_halted()? {
            let sync = self.interface.halt()?;
            self.entered(sync, HaltReason::Request)?;
        }
        self.disarm()?;
        if planned {
            self.state.halt_reason = Some(HaltReason::Request);
        }
        Ok(CoreInformation { pc: self.pc()? })
    }

    fn run(&mut self) -> Result<(), Error> {
        if self.state.running {
            return Ok(());
        }
        self.state.resume_at_detach = false;
        if self.in_boot_rom() && self.g23() {
            self.start_at_entry()?;
        } else if self.in_boot_rom() {
            // Resuming here would only run the boot ROM's idle loop, with the watchdog running
            // whatever the option byte says. Boot the program instead: a normal reset, after
            // which the debug stub in flash arms the monitor again.
            tracing::info!("rl78: continuing from the attach: booting the program");
            return self.reset();
        }
        // A breakpoint just set, a step's say, may be reached without writing it into flash.
        let pending = self.state.breakpoints.single_pending();
        let skip: Vec<u32> = pending.into_iter().collect();
        if self.step_off_breakpoint(&skip)? && self.at_breakpoint()? {
            // The next instruction is a breakpoint too: the target would trap at once.
            self.state.halt_reason = Some(HaltReason::Breakpoint(crate::BreakpointCause::Hardware));
            return Ok(());
        }
        if let Some(target) = pending
            && self.run_to_by_comparators(target)?
        {
            return Ok(());
        }
        self.sync_breakpoints(&[])?;
        let sync = self.store_context()?;
        self.interface.execute(sync, false)?;
        self.state.running = true;
        self.state.halt_reason = None;
        Ok(())
    }

    fn reset(&mut self) -> Result<(), Error> {
        if self.g23() {
            self.reset_and_halt(Duration::ZERO)?;
            return self.run();
        }
        // A normal boot into the program. Resuming after an attach would not do: that runs from
        // the ROM's idle loop, and with the watchdog the boot ROM left running. Breakpoints go
        // into flash first, so that the program meets them; the user's RAM goes back too, for
        // anything the program keeps across a reset.
        if !self.state.running {
            self.disarm()?;
            self.sync_breakpoints(&[])?;
            self.ram_return()?;
        }
        self.interface.reset()?;
        *self.state = Rl78CoreState {
            running: true,
            breakpoints: std::mem::take(&mut self.state.breakpoints),
            rrm: self.state.rrm,
            ..Rl78CoreState::default()
        };
        Ok(())
    }

    fn reset_and_halt(&mut self, _timeout: Duration) -> Result<CoreInformation, Error> {
        // RESET with TOOL0 low, then the CAH mode byte: the part comes up in the monitor. RAM is
        // not ours to restore after a reset, so the saved copy is dropped.
        let sync = self.interface.attach()?;
        self.state.attached(flash::Attached::UnderReset(sync));
        Ok(CoreInformation { pc: self.pc()? })
    }

    fn step(&mut self) -> Result<CoreInformation, Error> {
        self.require_halted("step")?;
        self.disarm()?;
        self.state.resume_at_detach = false;
        if self.in_boot_rom() && self.g23() {
            self.start_at_entry()?;
            self.state.halt_reason = Some(HaltReason::Step);
        } else if self.in_boot_rom() {
            self.boot_to_entry()?;
        } else if self.state.breakpoints.is_idle() {
            self.step_raw()?;
        } else {
            self.step_over_traps(&[])?;
        }
        Ok(CoreInformation { pc: self.pc()? })
    }

    fn read_core_reg(&mut self, address: RegisterId) -> Result<RegisterValue, Error> {
        let ctx = self.load_context()?;
        let id = address.0;
        let r = |i: usize| ctx.regs[i];
        let bank = ctx.user_bank() * 8;
        let value = match id {
            0..=39 => r(usize::from(id)),
            SP_ID => protocol::ADDR16_BASE | r(usize::from(SPH_ID)) << 8 | r(usize::from(SPL_ID)),
            _ if (PAIR_BASE..PAIR_BASE + 4).contains(&id) => {
                let i = bank + 2 * usize::from(id - PAIR_BASE);
                r(i) | r(i + 1) << 8
            }
            _ if (BYTE_BASE..BYTE_BASE + 8).contains(&id) => r(bank + usize::from(id - BYTE_BASE)),
            _ => return Err(Error::Register(format!("no RL78 register {id:#x}"))),
        };
        Ok(RegisterValue::U32(value))
    }

    fn write_core_reg(&mut self, address: RegisterId, value: RegisterValue) -> Result<(), Error> {
        let value: u32 = value.try_into()?;
        let ctx = self.load_context()?;
        let id = address.0;
        let bank = (ctx.user_bank() * 8) as u16;
        match id {
            PC_ID => ctx.set(id, value & 0xF_FFFF),
            0..=39 => ctx.set(id, value & 0xFF),
            SP_ID => {
                ctx.set(SPL_ID, value & 0xFF);
                ctx.set(SPH_ID, value >> 8 & 0xFF);
            }
            _ if (PAIR_BASE..PAIR_BASE + 4).contains(&id) => {
                let i = bank + 2 * (id - PAIR_BASE);
                ctx.set(i, value & 0xFF);
                ctx.set(i + 1, value >> 8 & 0xFF);
            }
            _ if (BYTE_BASE..BYTE_BASE + 8).contains(&id) => {
                ctx.set(bank + (id - BYTE_BASE), value & 0xFF)
            }
            _ => return Err(Error::Register(format!("no RL78 register {id:#x}"))),
        }
        Ok(())
    }

    fn available_breakpoint_units(&mut self) -> Result<u32, Error> {
        // FFH traps, put in place when the target next runs or steps.
        Ok(breakpoints::UNITS as u32)
    }

    fn hw_breakpoints(&mut self) -> Result<Vec<Option<u64>>, Error> {
        Ok(self.breakpoint_units())
    }

    fn enable_breakpoints(&mut self, _state: bool) -> Result<(), Error> {
        Ok(())
    }

    fn set_hw_breakpoint(&mut self, unit_index: usize, addr: u64) -> Result<(), Error> {
        self.set_breakpoint_unit(unit_index, addr)?;
        self.apply_breakpoints_now()
    }

    fn clear_hw_breakpoint(&mut self, unit_index: usize) -> Result<(), Error> {
        self.clear_breakpoint_unit(unit_index);
        self.apply_breakpoints_now()
    }

    fn registers(&self) -> &'static crate::CoreRegisters {
        &RL78_CORE_REGISTERS
    }

    fn program_counter(&self) -> &'static CoreRegister {
        &PC
    }

    fn frame_pointer(&self) -> &'static CoreRegister {
        &SP
    }

    fn stack_pointer(&self) -> &'static CoreRegister {
        &SP
    }

    fn return_address(&self) -> &'static CoreRegister {
        // The return address is on the stack; the CFI return column is PC.
        &PC
    }

    fn hw_breakpoints_enabled(&self) -> bool {
        false
    }

    fn architecture(&self) -> Architecture {
        Architecture::Rl78
    }

    fn core_type(&self) -> CoreType {
        CoreType::Rl78
    }

    fn instruction_set(&mut self) -> Result<InstructionSet, Error> {
        Ok(InstructionSet::Rl78)
    }

    fn fpu_support(&mut self) -> Result<bool, Error> {
        Ok(false)
    }

    fn floating_point_register_count(&mut self) -> Result<usize, Error> {
        Ok(0)
    }

    fn reset_catch_set(&mut self) -> Result<(), Error> {
        Err(Error::NotImplemented("reset catch on RL78"))
    }

    fn reset_catch_clear(&mut self) -> Result<(), Error> {
        Err(Error::NotImplemented("reset catch on RL78"))
    }

    fn debug_core_stop(&mut self) -> Result<(), Error> {
        if self.state.armed {
            // An armed comparator would stop the program with no debugger to answer.
            let running = self.state.running;
            self.halt(Duration::ZERO)?;
            if running {
                let sync = self.store_context()?;
                self.interface.execute(sync, false)?;
                self.state.running = true;
            }
        }
        self.lift_all_breakpoints()?;
        // A program the attach halted, for a memory read say, runs on as it was found. On Arm a
        // read would not have stopped it at all.
        if self.state.resume_at_detach && !self.state.running {
            tracing::debug!("rl78: resuming the program the attach halted");
            self.run()?;
        }
        Ok(())
    }
}

impl From<Rl78Error> for Error {
    fn from(e: Rl78Error) -> Self {
        match e {
            Rl78Error::Probe(e) => e.into(),
            other => Error::Rl78(other),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ram_shadow_saves_each_byte_once_and_returns_runs() {
        let mut shadow = RamShadow::default();
        assert_eq!(shadow.unsaved(0xF_FB00..0xF_FB04), vec![0xF_FB00..0xF_FB04]);
        shadow.save(0xF_FB01, &[1, 2]);
        assert_eq!(
            shadow.unsaved(0xF_FB00..0xF_FB05),
            [0xF_FB00..0xF_FB01, 0xF_FB03..0xF_FB05]
        );
        shadow.save(0xF_FB10, &[9]);
        assert!(shadow.update(0xF_FB02, 7));
        assert!(
            !shadow.update(0xF_FB03, 7),
            "not saved: written to the target instead"
        );
        assert_eq!(shadow.get(0xF_FB02), Some(7));
        assert_eq!(shadow.runs(), [(0xF_FB01, vec![1, 7]), (0xF_FB10, vec![9])]);
        assert_eq!(shadow.len(), 3);
    }

    #[test]
    fn read20_stub_bytes() {
        // ret at the end, the operand slots where the patcher expects them
        assert_eq!(STUB_READ20[18], 0xD7);
        assert_eq!(STUB_READ20[READ20_SEG - 1], 0x41);
        assert_eq!(STUB_READ20[READ20_ADDR - 1], 0x36);
        assert_eq!(STUB_READ20[READ20_COUNT - 1], 0x53);
    }
}
