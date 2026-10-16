//! The virtual G15: an RL78/G15 (R5F12068) as a debugger sees it through TOOL0 and RESET.
//!
//! Instructions run on rl78sim. The on-chip debug monitor, a 512-byte mask ROM at
//! `0EFE00H`–`0EFFFFH`, is Renesas's code and is not used: it is modelled here from its decode in
//! `g15_ocd_protocol_notes.md` (rl78_debug_re; section numbers below are to it). The model keeps
//! the monitor's working registers where the ROM keeps them, in bank 0, so the RAM image of
//! bank 0 after a halt is the monitor's scratch, as on hardware (§47.4).
//!
//! What it models:
//!
//! - RESET and TOOL0: a reset with TOOL0 low starts the boot ROM's serial mode, where `CAH`
//!   enters the monitor (§4); TOOL0 high boots the program.
//! - The monitor's path A (§27): entry as `SEL RB0`, `PUSH AX` and the B C H L 00 sync; the
//!   locked loop, where anything but `55H` resends the sync; unlock against `000C4H`; `56H`, `57H`
//!   and `58H` on `F0000H + HL`; `5BH` as `CALL !!0FFED0H` returning to `0EFFB5H`; `5CH` as
//!   B C H L, the echo of L, `POP AX` and `RETI`, with `F0085H` bit 0 making it a single step.
//! - Path B, the interrupt a byte raises in a running program once the debug stub has armed the
//!   monitor (`F0080H = C5H`, `FFFAFH` bit 6): `00H` halts.
//! - `FFH` traps into the monitor with PC one past it (§24, §27.5); the ROM's idle loop at
//!   `0EFFFCH` traps again at once.
//! - The watchdog: running after a `CAH` attach whatever the option byte says (§47.1), counting
//!   only while the program runs; overflow, a write to `WDTE` other than `ACH`, or an illegal
//!   instruction with the monitor disarmed is an internal reset into a normal boot.
//! - A break on TOOL0 while the monitor is listening is a `00H` it answers; a reset cuts the
//!   answer off, and what is left arrives after the next flush (§47.2).
//! - The code flash sequencer (§7.1): write and block erase, with the error flags. A command the
//!   manual does not allow panics, as a driver bug.
//!
//! Not modelled: Protocol B, pseudo-RRM/DMM (path B's other commands), interrupts, other
//! peripherals, data flash, and §48.3's slowdown after a `CAH` attach.

use std::collections::VecDeque;
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use probe_rs::architecture::rl78::communication_interface::{Rl78Error, Rl78Uart};
use rl78sim::cpu::{Cpu, Stop};
use rl78sim::isa::Core;
use rl78sim::mem::{Io, MemMap, Memory, RomWrites};

/// Code flash, `00000H`–`01FFFH` [g15:p56].
pub const FLASH_SIZE: u32 = 0x2000;
/// RAM, `FFB00H`–`FFEFFH`; the register banks are its top 32 bytes.
pub const RAM_START: u32 = 0xF_FB00;

const WDTE: u32 = 0xF_FFAB;
/// The OCD serial engine's control register; bit 6 enables the monitor (§14.1, §27.4).
const OCD_CTRL: u32 = 0xF_FFAF;
/// The debug-engine handshake: the stub writes `C5H` (§27.6).
const ENGINE_MODE: u32 = 0xF_0080;
/// Bit 0 arms a single step (§23.1).
const STEP_ENABLE: u32 = 0xF_0085;
/// Bit 0 picks the byte the ROM's idle loop writes to `F0080H` (§27.5). Reads 03H after `CAH`.
const ENGINE_SELECT: u32 = 0xF_0086;
const SP: u32 = 0xF_FFF8;
const PSW: u32 = 0xF_FFFA;
const ES: u32 = 0xF_FFFD;
/// Bank 0: X A C B E D L H.
const BANK0: u32 = 0xF_FEF8;
const SECURITY_ID: u32 = 0x0_00C4;

// The flash sequencer's registers, 2nd SFRs [g15:p74].
const FSSET: u32 = 0xF_00BE;
const FLPMC: u32 = 0xF_00C0;
const FSSQ: u32 = 0xF_00C1;
const FLAPL: u32 = 0xF_00C2;
const FLAPH: u32 = 0xF_00C3;
const FLSEDL: u32 = 0xF_00C4;
const FLSEDH: u32 = 0xF_00C5;
const FSASTL: u32 = 0xF_00C6;
const FSASTH: u32 = 0xF_00C7;
const FLWLL: u32 = 0xF_00C8;
const FLWHH: u32 = 0xF_00CB;
/// A code flash block, the erase unit [g15:p672].
const BLOCK: u32 = 0x400;
const OCD_OPTION: u32 = 0x0_00C3;
const WDT_OPTION: u32 = 0x0_00C0;
/// FRQSEL, the on-chip oscillator's frequency at reset [g15:p651].
const FREQ_OPTION: u32 = 0x0_00C2;
const CKC: u32 = 0xF_FFA4;
const HOCODIV: u32 = 0xF_00A8;

const CALL_GATE: u32 = 0xF_FED0;
/// Where the ROM's `CALL !!0FFED0H` returns to.
const CALL_RETURN: u32 = 0xE_FFB5;
/// The ROM's idle loop, just past the `FFH` at `0EFFFBH`.
const IDLE_LOOP: u32 = 0xE_FFFC;
const ROM: std::ops::Range<u32> = 0xE_FE00..0xF_0000;

/// The CPU clock: HOCO at 16 MHz with option byte `000C2H = F9H`.
pub const CLOCK_HZ: u64 = 16_000_000;
/// The watchdog after a `CAH` attach overflows within 20-100 ms (§47.1); 50 ms here.
const WDT_PERIOD_ATTACHED: u64 = CLOCK_HZ / 20;
/// What a reset costs, in clocks.
const RESET_CLOCKS: u64 = 1_000;
/// Instructions a running program gets each time the host looks at the line.
const QUANTUM: u32 = 20_000;
/// A routine behind `5BH` that has not returned by then is taken to have run away.
const ROUTINE_LIMIT: u32 = 1_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Expect {
    Command,
    SecurityId,
    SetAddr,
    WriteData,
    Execute,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    /// RESET held low.
    Reset,
    /// Reset released with TOOL0 low: the boot ROM waits for a mode byte.
    BootSerial,
    /// The program runs.
    Running,
    /// The program executed `HALT` or `STOP` and waits for an interrupt.
    Sleeping,
    /// In the monitor's path A command loop.
    Monitor,
}

/// The target. Tests hold a [`VirtualG15`] handle to it; so does the probe.
pub struct Model {
    pub cpu: Cpu,
    mode: Mode,
    tool0_low: bool,
    /// Bytes on their way to the host.
    rx: VecDeque<u8>,
    /// Bytes cut off by a reset, which the host's next flush does not catch (§47.2).
    late: VecDeque<u8>,
    expect: Expect,
    /// Bytes collected for a multi-byte command.
    args: Vec<u8>,
    /// Bytes still to come for `58H`.
    write_left: u16,
    /// The watchdog counts. `wdt_mark` is the clock count of the last feed.
    wdt_running: bool,
    wdt_period: u64,
    wdt_mark: u64,
    /// Internal resets so far, for tests.
    pub resets: u32,
    /// Booted through the boot ROM's `CAH` route rather than from the reset vector.
    debug_boot: bool,
}

/// The peripherals the debugger meets: the program's stores to `WDTE` (the register itself keeps
/// reading `9AH` or `1AH`), and the flash sequencer.
#[derive(Default)]
struct Peripherals {
    wdte_writes: Vec<u8>,
    flash: FlashSequencer,
}

impl Io for Peripherals {
    fn read(&mut self, _mem: &mut Memory, a: u32) -> Option<u8> {
        match a {
            FSASTH => Some(u8::from(self.flash.sqend) << 6),
            FSASTL => Some(self.flash.errors),
            _ => None,
        }
    }

    fn write(&mut self, mem: &mut Memory, a: u32, v: u8) -> bool {
        match a {
            WDTE => self.wdte_writes.push(v),
            FSSQ if v & 0x80 != 0 => self.flash.start(mem, v),
            // SQEND clears when SQST does [g15:p677].
            FSSQ => self.flash.sqend = false,
            _ => return false,
        }
        a == WDTE
    }
}

/// The code flash sequencer [g15:p669]-[g15:p680]. It does a command at once, where hardware
/// keeps the CPU waiting. A command the manual does not allow panics: hardware would do
/// something undefined, and the driver that sent it has a bug.
#[derive(Default)]
pub struct FlashSequencer {
    sqend: bool,
    /// FSASTL: SEQER, WRER, ERER.
    errors: u8,
    /// Words written and blocks erased, for tests.
    pub words_written: u32,
    pub blocks_erased: u32,
}

impl FlashSequencer {
    fn start(&mut self, mem: &mut Memory, fssq: u8) {
        let b = |a: u32| mem.b[a as usize];
        let fsset = b(FSSET) & 0x1F;
        // The CPU clock in MHz, rounded up, less one [g15:p675].
        let want = (CLOCK_HZ / 1_000_000 - 1) as u8;
        assert_eq!(
            fsset,
            want,
            "virtual G15: FSSET {fsset:02X}H for a {} MHz clock; the manual wants {want:02X}H",
            CLOCK_HZ / 1_000_000
        );
        let flpmc = b(FLPMC);
        assert_eq!(
            flpmc & 0x20,
            0,
            "virtual G15: data flash (FLPMC.SELDFL) is not modelled"
        );
        let flap = u32::from(b(FLAPL)) | u32::from(b(FLAPH) & 0x1F) << 8;
        // FLSEDL's bits 1-0 are fixed at 0 [g15:p671].
        let flsed = u32::from(b(FLSEDL) & 0xFC) | u32::from(b(FLSEDH) & 0x1F) << 8;
        self.sqend = true;
        self.errors = 0;
        // FWEDIS = 0 and FLSPM = 1, or the sequencer refuses [g15:p674].
        if flpmc & 0x0A != 0x02 {
            self.errors = 0x10;
            return;
        }
        match fssq & 0x07 {
            1 => {
                assert_eq!(flap % 4, 0, "virtual G15: write to {flap:05X}H, not a word");
                let word: Vec<u8> = (FLWLL..=FLWHH).map(b).collect();
                let old: Vec<u8> = (flap..flap + 4).map(b).collect();
                // Programming only clears bits.
                if old.iter().zip(&word).any(|(o, w)| !o & w != 0) {
                    self.errors = 0x02;
                    return;
                }
                mem.poke(flap, &word);
                self.words_written += 1;
            }
            4 => {
                // Table 19-9: FLAP is a block start, FLSED a block start with bits 9-2 set.
                assert!(
                    flap % BLOCK == 0 && flsed % BLOCK == 0x3FC && flap <= flsed,
                    "virtual G15: block erase with FLAP {flap:05X}H, FLSED {flsed:05X}H [g15:p671]"
                );
                for block in (flap..=flsed).step_by(BLOCK as usize) {
                    mem.poke(block, &[0xFF; BLOCK as usize]);
                    self.blocks_erased += 1;
                }
            }
            _ => panic!("virtual G15: FSSQ {fssq:02X}H is a prohibited command [g15:p676]"),
        }
    }
}

impl fmt::Debug for Model {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Model")
            .field("mode", &self.mode)
            .field("pc", &format_args!("{:05X}H", self.cpu.pc))
            .field("expect", &self.expect)
            .field("rx", &self.rx)
            .finish_non_exhaustive()
    }
}

fn g15_map() -> MemMap {
    MemMap {
        rom_end: FLASH_SIZE,
        mirror_start: 0xF_0800,
        mirror_len: 0x1800,
        mirror_src: 0x0_0800,
        ram_start: RAM_START,
        // Hardware ignores a store to flash; a routine doing one is still worth a look, but the
        // monitor's own 58H writes go through `poke` and are dropped there.
        rom_writes: RomWrites::Ignore,
        strict: true,
        sfr2_reads_11: false,
        // 2nd SFRs F0000H-F07FFH; the mirror starts at F0800H [g15:p62].
        sfr2_end: 0xF_0800,
    }
}

impl Model {
    fn new() -> Self {
        let mut mem = Memory::new(g15_map());
        mem.set_io(Box::new(Peripherals::default()));
        let cpu = Cpu::new(mem, Core::S2);
        Self {
            cpu,
            mode: Mode::Reset,
            tool0_low: false,
            rx: VecDeque::new(),
            late: VecDeque::new(),
            expect: Expect::Command,
            args: Vec::new(),
            write_left: 0,
            wdt_running: false,
            wdt_period: WDT_PERIOD_ATTACHED,
            wdt_mark: 0,
            resets: 0,
            debug_boot: false,
        }
    }

    // ---- memory as the monitor and the tests see it ----------------------------------------

    fn mirror(&self, a: u32) -> Option<u32> {
        let m = &self.cpu.mem.map;
        (m.mirror_start..m.mirror_start + m.mirror_len)
            .contains(&a)
            .then(|| a - m.mirror_start + m.mirror_src)
    }

    /// A byte as a data read sees it, without side effects.
    pub fn peek(&self, a: u32) -> u8 {
        let a = a & 0xF_FFFF;
        self.cpu.mem.b[self.mirror(a).unwrap_or(a) as usize]
    }

    /// Store a byte the way a `MOV [HL],A` in the monitor would.
    fn monitor_store(&mut self, a: u32, v: u8) {
        if a < FLASH_SIZE || self.mirror(a).is_some() {
            return;
        }
        if a == WDTE {
            self.wdte_written(v);
        } else {
            self.cpu.mem.poke(a, &[v]);
        }
    }

    fn peripherals(&mut self) -> &mut Peripherals {
        self.cpu
            .mem
            .io_mut()
            .expect("the peripherals are installed")
    }

    /// The flash sequencer, for its counts.
    pub fn flash(&mut self) -> &FlashSequencer {
        &self.peripherals().flash
    }

    /// Load bytes anywhere, flash included, without side effects.
    pub fn poke(&mut self, a: u32, data: &[u8]) {
        self.cpu.mem.poke(a, data);
    }

    pub fn peek16(&self, a: u32) -> u16 {
        u16::from(self.peek(a)) | u16::from(self.peek(a + 1)) << 8
    }

    fn r(&self, i: u32) -> u8 {
        self.cpu.mem.b[(BANK0 + i) as usize]
    }

    fn set_r(&mut self, i: u32, v: u8) {
        self.cpu.mem.b[(BANK0 + i) as usize] = v;
    }

    const X: u32 = 0;
    const A: u32 = 1;
    const C: u32 = 2;
    const B: u32 = 3;
    const L: u32 = 6;
    const H: u32 = 7;

    fn hl(&self) -> u16 {
        u16::from(self.r(Self::L)) | u16::from(self.r(Self::H)) << 8
    }

    fn set_hl(&mut self, v: u16) {
        self.set_r(Self::L, v as u8);
        self.set_r(Self::H, (v >> 8) as u8);
    }

    fn sp(&self) -> u32 {
        0xF_0000 | u32::from(self.cpu.mem.get16(SP))
    }

    fn set_sp(&mut self, sp: u32) {
        self.cpu.mem.put16_at(SP, sp as u16);
    }

    fn push(&mut self, bytes: &[u8]) {
        // bytes[0] lands at the new SP.
        let sp = self.sp() - bytes.len() as u32;
        self.cpu.mem.poke(sp, bytes);
        self.set_sp(sp);
    }

    fn pop(&mut self, n: u32) -> Vec<u8> {
        let sp = self.sp();
        let v = (0..n).map(|i| self.cpu.mem.b[(sp + i) as usize]).collect();
        self.set_sp(sp + n);
        v
    }

    /// The monitor answers a byte on TOOL0. After a plain boot that also takes `000C3H` bits 3
    /// and 1, which a toolchain ships clear: without them the stub's writes do not arm it (§31.5).
    fn armed(&self) -> bool {
        self.peek(ENGINE_MODE) == 0xC5
            && self.peek(OCD_CTRL) & 0x40 != 0
            && (self.debug_boot || self.peek(OCD_OPTION) & 0x0A == 0x0A)
    }

    fn send(&mut self, bytes: &[u8]) {
        self.rx.extend(bytes);
    }

    // ---- resets and the watchdog -------------------------------------------------------------

    /// A normal boot: from the reset vector, the option bytes applied, the monitor disarmed until
    /// the program's debug stub arms it.
    /// What a reset does to the registers the debugger reads: the CPU's, the clock's and the flash
    /// sequencer's [g15:p74].
    fn reset_registers(&mut self) {
        self.cpu.reset();
        let freq = self.peek(FREQ_OPTION) & 0x07;
        let b = &mut self.cpu.mem.b;
        b[CKC as usize] = 0x00;
        // HOCODIV starts as the option byte's FRQSEL [g15:p145].
        b[HOCODIV as usize] = freq;
        for a in [FSSET, FSSQ, FLAPL, FLAPH, FLSEDL, FLSEDH] {
            b[a as usize] = 0;
        }
        b[FLPMC as usize] = 0x08;
    }

    fn boot(&mut self) {
        self.reset_registers();
        self.debug_boot = false;
        for a in [ENGINE_MODE, STEP_ENABLE, ENGINE_SELECT, OCD_CTRL] {
            self.cpu.mem.b[a as usize] = 0;
        }
        self.wdt_running = self.peek(WDT_OPTION) & 0x10 != 0;
        // WDCS, (2^n - 1)/fIL at 15 kHz [g15:p649]; only matters for programs that leave it on.
        let wdcs = [6, 7, 8, 9, 11, 13, 14, 16][usize::from(self.peek(WDT_OPTION) >> 1 & 7)];
        self.wdt_period = CLOCK_HZ * (1 << wdcs) / 15_000;
        self.cpu.mem.b[WDTE as usize] = if self.wdt_running { 0x9A } else { 0x1A };
        self.wdt_mark = self.cpu.n.clocks;
        self.expect = Expect::Command;
        self.mode = Mode::Running;
    }

    fn internal_reset(&mut self, why: &str) {
        self.resets += 1;
        if self.resets <= 3 {
            eprintln!(
                "virtual G15: internal reset ({why}) at PC {:05X}H",
                self.cpu.pc
            );
        }
        // A reset takes time too, or an erased part resetting on its own reset vector would
        // never let the clock move.
        self.cpu.n.clocks += RESET_CLOCKS;
        self.boot();
    }

    /// A store to `WDTE`: `ACH` feeds the watchdog; anything else, a bit operation included,
    /// resets [g15:p311].
    fn wdte_written(&mut self, v: u8) {
        match v {
            0xAC => self.wdt_mark = self.cpu.n.clocks,
            v => self.internal_reset(&format!("WDTE written with {v:02X}H")),
        }
    }

    // ---- the monitor ------------------------------------------------------------------------

    /// The debug interrupt: frame, `SEL RB0`, `PUSH AX`, and path A's sync (§18, §27).
    fn enter_monitor(&mut self, pc: u32) {
        self.cpu.pc = pc;
        let psw = self.peek(PSW);
        self.push(&[pc as u8, (pc >> 8) as u8, (pc >> 16) as u8 & 0x0F, psw]);
        // The debug interrupt clears IE; SEL RB0.
        self.cpu.mem.b[PSW as usize] = psw & !0x80 & !0x28;
        let (x, a) = (self.r(Self::X), self.r(Self::A));
        self.push(&[x, a]);
        // PUSH HL / POP HL leave HL just below the frame.
        let sp = self.sp();
        self.cpu.mem.b[(sp - 2) as usize] = self.r(Self::L);
        self.cpu.mem.b[(sp - 1) as usize] = self.r(Self::H);
        self.mode = Mode::Monitor;
        self.expect = Expect::Command;
        let c = self.r(Self::C);
        self.set_r(Self::X, c);
        self.send_sync();
    }

    /// B, C, H, L and the 00H prompt; C becomes the lock flag (0EFF4AH).
    fn send_sync(&mut self) {
        let x = self.r(Self::X);
        self.set_r(Self::C, x);
        let sync = [self.r(Self::B), x, self.r(Self::H), self.r(Self::L), 0];
        self.send(&sync);
        self.set_r(Self::C, 1);
        self.set_r(Self::A, 0);
    }

    fn prompt(&mut self) {
        self.set_r(Self::A, 0);
        self.send(&[0]);
    }

    fn monitor_rx(&mut self, byte: u8) {
        match self.expect {
            Expect::Command => self.command(byte),
            Expect::SecurityId => {
                self.args.push(byte);
                if self.args.len() == 10 {
                    let diff = (0..10u32).fold(0u8, |acc, i| {
                        acc | self.args[i as usize].wrapping_sub(self.peek(SECURITY_ID + i))
                    });
                    self.set_r(Self::X, diff);
                    self.set_r(Self::B, 0);
                    self.set_hl(SECURITY_ID as u16 + 10);
                    let (c, reply) = if diff == 0 { (0, 0xF2) } else { (1, 0xF3) };
                    self.set_r(Self::C, c);
                    self.set_r(Self::A, reply);
                    self.send(&[reply]);
                    self.expect = Expect::Command;
                }
            }
            Expect::SetAddr => {
                self.args.push(byte);
                if self.args.len() == 3 {
                    self.set_r(Self::L, self.args[0]);
                    self.set_r(Self::H, self.args[1]);
                    self.set_r(Self::B, self.args[2]);
                    self.expect = Expect::Command;
                    self.prompt();
                }
            }
            Expect::WriteData => {
                let hl = self.hl();
                self.monitor_store(0xF_0000 | u32::from(hl), byte);
                if self.mode != Mode::Monitor {
                    return; // the store reset the part
                }
                self.set_hl(hl.wrapping_add(1));
                self.set_r(Self::B, self.r(Self::B).wrapping_sub(1));
                self.write_left -= 1;
                if self.write_left == 0 {
                    self.expect = Expect::Command;
                    self.prompt();
                }
            }
            Expect::Execute => {
                self.args.push(byte);
                if self.args.len() == 4 {
                    let [b, c, h, l] = [self.args[0], self.args[1], self.args[2], self.args[3]];
                    self.set_r(Self::B, b);
                    self.set_r(Self::C, c);
                    self.set_r(Self::H, h);
                    self.set_r(Self::L, l);
                    self.send(&[l]);
                    self.expect = Expect::Command;
                    self.leave_monitor();
                }
            }
        }
    }

    fn command(&mut self, byte: u8) {
        self.set_r(Self::A, byte.wrapping_sub(0x55));
        if byte == 0x55 {
            self.send(&[0xF1]);
            self.args.clear();
            self.expect = Expect::SecurityId;
            return;
        }
        if self.r(Self::C) != 0 {
            // Locked: anything else is answered with the sync again.
            self.send_sync();
            return;
        }
        self.args.clear();
        match byte {
            0x56 => self.expect = Expect::SetAddr,
            0x57 => loop {
                let hl = self.hl();
                let v = self.peek(0xF_0000 | u32::from(hl));
                self.send(&[v]);
                self.set_hl(hl.wrapping_add(1));
                let b = self.r(Self::B).wrapping_sub(1);
                self.set_r(Self::B, b);
                if b == 0 {
                    break;
                }
            },
            0x58 => {
                self.write_left = match self.r(Self::B) {
                    0 => 256,
                    n => u16::from(n),
                };
                self.expect = Expect::WriteData;
            }
            0x5B => {
                self.call_gate();
                self.prompt();
            }
            0x5C => self.expect = Expect::Execute,
            _ => self.prompt(),
        }
    }

    /// `CALL !!0FFED0H` from 0EFFB1H, run until the routine returns to 0EFFB5H.
    fn call_gate(&mut self) {
        let r = CALL_RETURN;
        self.push(&[r as u8, (r >> 8) as u8, (r >> 16) as u8, 0]);
        self.cpu.pc = CALL_GATE;
        for _ in 0..ROUTINE_LIMIT {
            if self.cpu.pc == CALL_RETURN {
                return;
            }
            if let Some(stop) = self.cpu.step() {
                panic!(
                    "virtual G15: a routine behind 5BH stopped: {stop:?} at PC {:05X}H",
                    self.cpu.pc
                );
            }
        }
        panic!(
            "virtual G15: a routine behind 5BH ran {ROUTINE_LIMIT} instructions without returning"
        );
    }

    /// `MOV A,FFFAEH`, `POP AX`, `RETI` (0EFE98H), then run or step.
    fn leave_monitor(&mut self) {
        let ax = self.pop(2);
        self.set_r(Self::X, ax[0]);
        self.set_r(Self::A, ax[1]);
        let f = self.pop(4);
        self.cpu.pc = u32::from(f[0]) | u32::from(f[1]) << 8 | u32::from(f[2] & 0x0F) << 16;
        self.cpu.mem.b[PSW as usize] = f[3];
        self.mode = Mode::Running;
        if self.peek(STEP_ENABLE) & 1 != 0 {
            self.execute_one();
            if self.mode == Mode::Running {
                let pc = self.cpu.pc;
                self.enter_monitor(pc);
            }
        }
    }

    // ---- the program ------------------------------------------------------------------------

    /// One instruction of the program, and what it did to the watchdog and the monitor.
    fn execute_one(&mut self) {
        let pc = self.cpu.pc;
        if ROM.contains(&pc) {
            self.rom_step(pc);
            return;
        }
        let stop = self.cpu.step();
        let writes = std::mem::take(&mut self.peripherals().wdte_writes);
        for v in writes {
            self.wdte_written(v);
            if self.mode != Mode::Running {
                return;
            }
        }
        if self.wdt_running && self.cpu.n.clocks - self.wdt_mark > self.wdt_period {
            self.internal_reset("watchdog overflow");
            return;
        }
        match stop {
            None | Some(Stop::SelfLoop { .. }) => {}
            Some(Stop::Illegal { pc, bytes }) if bytes[0] == 0xFF && self.armed() => {
                self.enter_monitor(pc + 1);
            }
            Some(Stop::Illegal { pc, .. }) => {
                self.cpu.pc = pc;
                self.internal_reset("illegal instruction");
            }
            Some(Stop::Exit(_)) => self.mode = Mode::Sleeping,
            Some(stop) => panic!("virtual G15: the program stopped: {stop:?} after PC {pc:05X}H"),
        }
    }

    /// The ROM's idle loop (0EFFDFH-0EFFFCH, §27.5), one instruction at a time.
    fn rom_step(&mut self, pc: u32) {
        let next = match pc {
            0xE_FFFC => 0xE_FFDF,
            0xE_FFDF => {
                self.cpu.mem.b[ES as usize] = 0;
                0xE_FFE1
            }
            0xE_FFE1 => 0xE_FFE5,
            0xE_FFE5 => 0xE_FFE8,
            0xE_FFE8 => 0xE_FFEA,
            0xE_FFEA => 0xE_FFED,
            0xE_FFED if self.peek(ENGINE_SELECT) & 1 != 0 => 0xE_FFF0,
            0xE_FFED => 0xE_FFF7,
            0xE_FFF0 => 0xE_FFF2,
            0xE_FFF2 => 0xE_FFF7,
            0xE_FFF7 => 0xE_FFF8,
            0xE_FFF8 => {
                let v = if self.peek(ENGINE_SELECT) & 1 != 0 {
                    0xC5
                } else {
                    0xCA
                };
                self.cpu.mem.b[ENGINE_MODE as usize] = v;
                0xE_FFFB
            }
            0xE_FFFB => {
                self.enter_monitor(IDLE_LOOP);
                return;
            }
            _ => panic!(
                "virtual G15: resumed into the monitor ROM at {pc:05X}H, which is not modelled"
            ),
        };
        self.cpu.pc = next;
    }

    fn run_quantum(&mut self) {
        for _ in 0..QUANTUM {
            if self.mode != Mode::Running {
                return;
            }
            self.execute_one();
        }
    }

    /// A byte arriving on TOOL0.
    fn receive(&mut self, byte: u8) {
        match self.mode {
            Mode::Reset => {}
            Mode::BootSerial => match byte {
                0xCA => self.ca_entry(),
                0x00 | 0x3A => panic!("virtual G15: Protocol B is not modelled"),
                _ => {}
            },
            Mode::Monitor => self.monitor_rx(byte),
            Mode::Running | Mode::Sleeping => {
                if !self.armed() {
                    return; // nothing listens
                }
                let pc = self.cpu.pc;
                if byte == 0x00 {
                    // Path B bridges to path A: the halt (§23.2, §27.3).
                    self.enter_monitor(pc);
                } else if !matches!(self.peek16(0x0002), 0x0000 | 0xFFFF) {
                    panic!("virtual G15: pseudo-RRM/DMM ({byte:02X}H) is not modelled");
                }
                // Otherwise path B returns at once and says nothing (0EFE97H).
            }
        }
    }

    /// The boot ROM's `CAH` route into the monitor (§4, §27.5).
    fn ca_entry(&mut self) {
        if self.peek(OCD_OPTION) & 0x80 == 0 {
            return; // 0EFFE5H spins until the on-chip debug option byte enables debugging
        }
        self.reset_registers();
        self.debug_boot = true;
        for i in 0..8 {
            self.set_r(i, 0);
        }
        self.cpu.mem.b[ENGINE_SELECT as usize] = 0x03;
        self.cpu.mem.b[ENGINE_MODE as usize] = 0xC5;
        self.cpu.mem.b[OCD_CTRL as usize] = 0x65;
        // §47.1: the watchdog runs, whatever 000C0H says.
        self.wdt_running = true;
        self.wdt_period = WDT_PERIOD_ATTACHED;
        self.wdt_mark = self.cpu.n.clocks;
        self.cpu.mem.b[WDTE as usize] = 0x9A;
        // The boot ROM's stack: the frame lands at FFC00H.
        self.set_sp(0xF_FC06);
        self.mode = Mode::Running;
        self.cpu.pc = 0xE_FFFB;
        self.rom_step(0xE_FFFB);
    }
}

/// The virtual target, as the probe's link and as the test's handle.
#[derive(Clone, Debug)]
pub struct VirtualG15(Arc<Mutex<Model>>);

impl VirtualG15 {
    /// A G15 with erased flash and the on-chip debug option byte set to enable debugging.
    pub fn new() -> Self {
        let mut m = Model::new();
        // A blank part has erased flash; give it the option bytes a debugger needs: watchdog
        // off, RESET pin enabled, 16 MHz, debugging enabled with its in-use bits (§31).
        m.poke(WDT_OPTION, &[0xEE, 0xFF, 0xF9, 0x8F]);
        m.poke(SECURITY_ID, &[0; 10]);
        Self(Arc::new(Mutex::new(m)))
    }

    /// The model. A test that panicked holding it leaves it poisoned; the session's teardown
    /// still needs it, and a second panic there would abort every test in the binary.
    pub fn lock(&self) -> MutexGuard<'_, Model> {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Let a running program run for `ms` milliseconds of its time.
    pub fn run_for_ms(&self, ms: u64) {
        let mut m = self.lock();
        let until = m.cpu.n.clocks + CLOCK_HZ / 1000 * ms;
        while m.mode == Mode::Running && m.cpu.n.clocks < until {
            m.execute_one();
        }
    }

    pub fn in_monitor(&self) -> bool {
        self.lock().mode == Mode::Monitor
    }
}

impl Rl78Uart for VirtualG15 {
    fn write(&mut self, data: &[u8]) -> Result<(), Rl78Error> {
        let mut m = self.lock();
        for &b in data {
            m.receive(b);
        }
        Ok(())
    }

    fn read(&mut self, buf: &mut [u8], timeout: Duration) -> Result<usize, Rl78Error> {
        let mut m = self.lock();
        // A running program gets time while the host waits: a quantum for a poll, more for a
        // wait, up to about what the wait would have been worth on hardware.
        let quanta = 1 + timeout.as_millis().min(100) as u32 / 10;
        for _ in 0..quanta {
            if !m.rx.is_empty() {
                break;
            }
            m.run_quantum();
        }
        let n = buf.len().min(m.rx.len());
        for (d, s) in buf.iter_mut().zip(m.rx.drain(..n)) {
            *d = s;
        }
        Ok(n)
    }

    fn set_reset(&mut self, asserted: bool) -> Result<(), Rl78Error> {
        let mut m = self.lock();
        if asserted {
            // Whatever the target was sending is cut off; its remains outlive the next flush.
            let cut: Vec<u8> = m.rx.drain(..).collect();
            m.late.extend(cut);
            m.mode = Mode::Reset;
        } else if m.mode == Mode::Reset {
            if m.tool0_low {
                m.expect = Expect::Command;
                m.mode = Mode::BootSerial;
            } else {
                m.boot();
            }
        }
        Ok(())
    }

    fn set_tool0_low(&mut self, low: bool) -> Result<(), Rl78Error> {
        let mut m = self.lock();
        if low && !m.tool0_low && matches!(m.mode, Mode::Monitor | Mode::Running | Mode::Sleeping) {
            // A break: received as a 00H with a framing error.
            m.receive(0x00);
        }
        m.tool0_low = low;
        Ok(())
    }

    fn flush_input(&mut self) -> Result<(), Rl78Error> {
        let mut m = self.lock();
        m.rx.clear();
        let late: Vec<u8> = m.late.drain(..).collect();
        m.rx.extend(late);
        Ok(())
    }
}
