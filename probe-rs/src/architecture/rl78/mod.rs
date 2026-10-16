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
//!   RAM belongs to the user's program, so it is saved before the first routine runs and put back
//!   before the target runs again.
//!
//! Section references (§N) are to `g15_ocd_protocol_notes.md` in the rl78_debug_re repository.

use std::{
    ops::Range,
    time::{Duration, Instant},
};

use crate::{
    CoreInformation, CoreInterface, CoreRegister, CoreStatus, CoreType, Error, HaltReason,
    InstructionSet, MemoryInterface,
    core::{Architecture, RegisterId, RegisterValue},
    memory::valid_32bit_address,
};

pub mod communication_interface;
pub mod protocol;
pub mod registers;
pub mod sequences;

#[cfg(test)]
mod scripted;

use communication_interface::{Rl78Error, Rl78OcdInterface};
use protocol::Sync;
use registers::*;
use sequences::Rl78DebugSequence;

/// All of RAM on the RL78/G15: `FFB00H`–`FFEFFH`. The debugger borrows parts of it, and every
/// byte belongs to the user's program.
const RAM_BASE: u32 = 0xF_FB00;
const RAM_SIZE: usize = 0x400;

/// Where host routines are staged. Low, deliberately: a routine runs on the interrupted
/// program's stack, and placed high its first push would land on itself. Low, it stays clear of
/// the monitor's own stack (SP = `FFC00H` on a fresh attach, growing down), which caps a routine
/// at a little under 250 bytes.
const STUB_BASE: u32 = 0xF_FB00;
const STUB_MAX: usize = 0xF0;

/// A bare `5BH` makes the ROM `CALL !!0FFED0H` (§12.3): an ordinary call gate. A branch to the
/// staged routine goes here, and the routine returns with `RET`.
const CALL_GATE: u32 = 0xF_FED0;

/// Where a routine leaves its results. `5BH` replies only with the `00H` prompt, so results come
/// back through an ordinary read.
const STUB_BUF: u32 = 0xF_FD00;
const STUB_BUF_SIZE: usize = 256;

/// The four register banks, bank 3 first: bank 0 sits at the high end [arch:p20].
const BANKS_ADDR: u32 = 0xF_FEE0;
/// SPL, SPH [arch:p23]
const SP_ADDR: u32 = 0xF_FFF8;
/// CS, ES, PMC and MEM are contiguous.
const CS_ADDR: u32 = 0xF_FFFC;

/// The interrupt frame the monitor leaves at SP: the AX its prologue pushed, then the PC and PSW
/// the debug interrupt pushed. HL is pushed too, but popped again before the command loop runs,
/// so by the time the host reads SP it points at the AX slot (§18).
const FRAME_LEN: usize = 6;

/// PSW register-bank select bits [arch:p16].
const PSW_RBS0: u8 = 1 << 3;
const PSW_RBS1: u8 = 1 << 5;

/// Copy `count` bytes from `ES:[HL]` to `FFD00H`. This is what Renesas's 365-byte RAM kernel
/// existed to provide, in 19 bytes: reaching below `F0000H`, which the monitor's own read cannot
/// do because it addresses through `[HL]` with 16-bit addressing (§5.1).
///
/// ```text
///         mov   es, #seg          ; [1]
///         movw  hl, #addr16       ; [3][4]
///         movw  de, #0FD00H       ; [DE] takes no ES prefix, so FFD00H
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
    0x34, 0x00, 0xFD, // movw de, #0FD00H
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
    /// Which raw registers the debugger changed.
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

    fn is_dirty(&self, id: u16) -> bool {
        self.dirty & (1 << id) != 0
    }
}

/// RL78 state that outlives a [`Rl78`] handle.
#[derive(Debug, Default)]
pub struct Rl78CoreState {
    /// The target is executing user code.
    running: bool,
    /// Why it last stopped.
    halt_reason: Option<HaltReason>,
    /// B, C, H and L as the monitor reported them at the last entry.
    sync: Sync,
    /// The register file, read lazily after each halt.
    context: Option<Context>,
    /// The user's RAM, saved before the debugger first overwrote any of it this halt.
    ram_shadow: Option<Box<[u8]>>,
}

impl Rl78CoreState {
    /// A fresh state.
    pub fn new() -> Self {
        Self::default()
    }

    /// The probe has just attached: the target is halted in the monitor.
    pub(crate) fn attached(&mut self, sync: Sync) {
        *self = Self {
            sync,
            halt_reason: Some(HaltReason::Request),
            ..Self::default()
        };
    }
}

/// An RL78 core.
pub struct Rl78<'probe> {
    interface: &'probe mut dyn Rl78OcdInterface,
    state: &'probe mut Rl78CoreState,
    _sequence: std::sync::Arc<dyn Rl78DebugSequence>,
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
            _sequence: sequence,
        })
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
    /// | D, E | RAM: the monitor's command loop never touches DE (§27.2, from the ROM) |
    ///
    /// That holds whichever bank the program was using, since the prologue saves bank 0 in every
    /// case. Banks 1 to 3 are untouched and read straight from RAM. PSW and SP come from the
    /// frame, not from `FFFFAH`/`FFFF8H`, which hold the monitor's own values.
    fn load_context(&mut self) -> Result<&mut Context, Error> {
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
            self.state.context = Some(Context {
                monitor_sp,
                regs,
                dirty: 0,
            });
        }
        Ok(self.state.context.as_mut().expect("loaded above"))
    }

    /// Write back whatever the debugger changed, ready for a resume or a step, and return the
    /// B, C, H and L to load on the way out.
    fn store_context(&mut self) -> Result<Sync, Error> {
        // RAM first: the register banks and the frame live inside it, so restoring it afterwards
        // would undo them. e2 studio uses the same order: RAM, banks, ES, then 5CH.
        self.ram_return()?;

        let Some(ctx) = self.state.context.take() else {
            return Ok(self.state.sync);
        };
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

    /// The target stopped (a halt, a step, or by itself): unlock and forget the old context.
    fn entered(&mut self, sync: Sync, reason: HaltReason) -> Result<(), Error> {
        self.state.running = false;
        self.state.sync = sync;
        self.state.context = None;
        self.state.ram_shadow = None;
        self.state.halt_reason = Some(reason);
        self.interface.unlock()?;
        Ok(())
    }

    fn pc(&mut self) -> Result<u64, Error> {
        Ok(u64::from(self.load_context()?.regs[usize::from(PC_ID)]))
    }

    /// Save the user's RAM, once per halt, before anything overwrites it. Lazily, so that a
    /// session that never runs a routine never pays for it: then the only user memory disturbed
    /// is the debug interrupt frame, which is exactly what Renesas reserves [g15:p687].
    fn ram_borrow(&mut self) -> Result<(), Error> {
        if self.state.ram_shadow.is_none() {
            let mut ram = vec![0; RAM_SIZE].into_boxed_slice();
            self.interface.read_mem(RAM_BASE, &mut ram)?;
            self.state.ram_shadow = Some(ram);
            tracing::debug!("rl78: saved {RAM_SIZE} bytes of RAM");
        }
        Ok(())
    }

    fn ram_return(&mut self) -> Result<(), Error> {
        if let Some(ram) = self.state.ram_shadow.take() {
            if let Err(e) = self.interface.write_mem(RAM_BASE, &ram) {
                tracing::error!(
                    "rl78: could not restore RAM; the program's memory is what the debugger left"
                );
                self.state.ram_shadow = Some(ram);
                return Err(e.into());
            }
            tracing::debug!("rl78: restored {RAM_SIZE} bytes of RAM");
        }
        Ok(())
    }

    /// Stage a routine in RAM and call it through the monitor's call gate.
    fn run_stub(&mut self, code: &[u8]) -> Result<(), Error> {
        if code.is_empty() || code.len() > STUB_MAX {
            return Err(Error::Other(format!(
                "a {}-byte routine does not fit in 1..={STUB_MAX} bytes",
                code.len()
            )));
        }
        self.ram_borrow()?;
        self.interface.write_mem(STUB_BASE, code)?;
        // BR !!STUB_BASE
        let s = STUB_BASE.to_le_bytes();
        self.interface
            .write_mem(CALL_GATE, &[0xEC, s[0], s[1], s[2] & 0x0F])?;
        self.interface.call_stub()?;
        Ok(())
    }

    /// Read anywhere in the 20-bit space by running [`STUB_READ20`] and reading its buffer.
    fn read_far(&mut self, mut address: u32, data: &mut [u8]) -> Result<(), Error> {
        for chunk in data.chunks_mut(STUB_BUF_SIZE) {
            let mut code = STUB_READ20;
            code[READ20_SEG] = (address >> 16) as u8 & 0x0F;
            code[READ20_ADDR..READ20_ADDR + 2].copy_from_slice(&(address as u16).to_le_bytes());
            code[READ20_COUNT] = chunk.len() as u8; // 256 encodes as 0
            self.run_stub(&code)?;
            self.interface.read_mem(STUB_BUF, chunk)?;
            address += chunk.len() as u32;
        }
        Ok(())
    }

    /// Read in `F0000H`–`FFFFFH`, seeing the user's RAM rather than what the debugger borrowed.
    fn read_f_segment(&mut self, address: u32, data: &mut [u8]) -> Result<(), Error> {
        self.interface.read_mem(address, data)?;
        if let Some(ram) = &self.state.ram_shadow
            && let Some((d, r)) = ram_overlap(address, data.len())
        {
            data[d].copy_from_slice(&ram[r]);
        }
        Ok(())
    }

    fn read_bytes(&mut self, address: u64, data: &mut [u8]) -> Result<(), Error> {
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
        self.require_halted("memory access")?;
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
        match &mut self.state.ram_shadow {
            // While RAM is borrowed, the user's RAM is the saved copy: change that, and it goes
            // back to the target on resume. Write the rest directly.
            Some(ram) => {
                if let Some((d, r)) = ram_overlap(start, data.len()) {
                    ram[r].copy_from_slice(&data[d]);
                }
                let ram_end = RAM_BASE + RAM_SIZE as u32;
                let end = start + data.len() as u32;
                if start < RAM_BASE {
                    let n = (RAM_BASE.min(end) - start) as usize;
                    self.interface.write_mem(start, &data[..n])?;
                }
                if end > ram_end {
                    let from = ram_end.max(start);
                    self.interface
                        .write_mem(from, &data[(from - start) as usize..])?;
                }
            }
            None => self.interface.write_mem(start, data)?,
        }
        Ok(())
    }
}

/// Where `len` bytes at `address` overlap RAM: the range within the data, and within RAM.
fn ram_overlap(address: u32, len: usize) -> Option<(Range<usize>, Range<usize>)> {
    let lo = address.max(RAM_BASE);
    let hi = (address + len as u32).min(RAM_BASE + RAM_SIZE as u32);
    (lo < hi).then(|| {
        (
            (lo - address) as usize..(hi - address) as usize,
            (lo - RAM_BASE) as usize..(hi - RAM_BASE) as usize,
        )
    })
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
            // A breakpoint, or a watchdog reset: their syncs are identical (§28.4), and only
            // the PC tells them apart. That test arrives with breakpoints.
            self.entered(sync, HaltReason::Unknown)?;
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
        // Poll first: if it stopped by itself just now, a halt byte would draw a second sync.
        if !self.core_halted()? {
            let sync = self.interface.halt()?;
            self.entered(sync, HaltReason::Request)?;
        }
        Ok(CoreInformation { pc: self.pc()? })
    }

    fn run(&mut self) -> Result<(), Error> {
        if self.state.running {
            return Ok(());
        }
        let sync = self.store_context()?;
        self.interface.execute(sync, false)?;
        self.state.running = true;
        self.state.halt_reason = None;
        Ok(())
    }

    fn reset(&mut self) -> Result<(), Error> {
        // A normal boot into the program. Resuming after an attach would not do: that runs from
        // the ROM's idle loop, and with the watchdog the boot ROM left running.
        self.interface.reset()?;
        *self.state = Rl78CoreState {
            running: true,
            ..Rl78CoreState::default()
        };
        Ok(())
    }

    fn reset_and_halt(&mut self, _timeout: Duration) -> Result<CoreInformation, Error> {
        // RESET with TOOL0 low, then the CAH mode byte: the part comes up in the monitor. RAM is
        // not ours to restore after a reset, so the saved copy is dropped.
        let sync = self.interface.attach()?;
        self.state.attached(sync);
        Ok(CoreInformation { pc: self.pc()? })
    }

    fn step(&mut self) -> Result<CoreInformation, Error> {
        self.require_halted("step")?;
        let sync = self.store_context()?;
        let sync = self
            .interface
            .execute(sync, true)?
            .expect("a step returns the re-entry sync");
        self.entered(sync, HaltReason::Step)?;
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
        // The G15 has no breakpoint hardware (§42). Breakpoints are FFH traps in flash, and
        // arrive with flash programming.
        Ok(0)
    }

    fn hw_breakpoints(&mut self) -> Result<Vec<Option<u64>>, Error> {
        Ok(vec![])
    }

    fn enable_breakpoints(&mut self, _state: bool) -> Result<(), Error> {
        Ok(())
    }

    fn set_hw_breakpoint(&mut self, _unit_index: usize, _addr: u64) -> Result<(), Error> {
        Err(Rl78Error::Unsupported("breakpoints").into())
    }

    fn clear_hw_breakpoint(&mut self, _unit_index: usize) -> Result<(), Error> {
        Ok(())
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
    fn ram_overlap_clips() {
        // Four bytes below RAM, four inside.
        assert_eq!(ram_overlap(RAM_BASE - 4, 8), Some((4..8, 0..4)));
        // Straddling the top.
        assert_eq!(ram_overlap(RAM_BASE + 0x3FE, 4), Some((0..2, 0x3FE..0x400)));
        assert_eq!(ram_overlap(0xF_FF00, 4), None);
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
