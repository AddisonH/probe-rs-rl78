//! The RL78 driver against scripted transcripts.
//!
//! [`ScriptedUart`] stands in for the probe: each test lists the bytes the driver must send and
//! the target's replies, in order, and the uart panics on anything it was not told to expect. That
//! pins down orderings that matter on the wire (RAM restored before the resume, RESET before
//! TOOL0, a poll before a halt) without a board. The scenarios come from runs on an RL78/G15 FPB;
//! section numbers are to `g15_ocd_protocol_notes.md` in the rl78_debug_re repository.

use std::collections::VecDeque;
use std::time::Duration;

use super::{
    Rl78, Rl78CoreState,
    communication_interface::{Rl78Error, Rl78OcdInterface, Rl78Uart, UartOcd},
    registers::*,
    sequences::DefaultRl78Sequence,
};
use crate::{CoreInterface, CoreStatus, Error, HaltReason, MemoryInterface, core::RegisterId};

#[derive(Debug, PartialEq)]
enum Line {
    Reset(bool),
    Tool0Low(bool),
    Flush,
}

#[derive(Debug)]
enum Step {
    /// The driver sends this; the target answers that.
    Exchange(Vec<u8>, Vec<u8>),
    /// A control-line change or a flush.
    Line(Line),
    /// Bytes the target sends without being asked.
    Unsolicited(Vec<u8>),
}

/// A uart that plays the target's side of a script.
#[derive(Debug, Default)]
struct ScriptedUart {
    steps: VecDeque<Step>,
    rx: VecDeque<u8>,
}

impl ScriptedUart {
    fn take_line(&mut self, got: Line) {
        match self.steps.pop_front() {
            Some(Step::Line(want)) if want == got => {}
            other => panic!("driver did {got:?}; the script expected {other:?}"),
        }
    }

    fn assert_done(&self) {
        assert!(
            self.steps.is_empty(),
            "script not finished: {:02x?}",
            self.steps
        );
    }
}

impl Rl78Uart for ScriptedUart {
    fn write(&mut self, data: &[u8]) -> Result<(), Rl78Error> {
        match self.steps.pop_front() {
            Some(Step::Exchange(tx, rx)) => {
                assert_eq!(
                    data, tx,
                    "driver sent {data:02x?}; the script expected {tx:02x?}"
                );
                self.rx.extend(rx);
            }
            other => panic!("driver sent {data:02x?}; the script expected {other:02x?}"),
        }
        Ok(())
    }

    fn read(&mut self, buf: &mut [u8], _timeout: Duration) -> Result<usize, Rl78Error> {
        if self.rx.is_empty()
            && let Some(Step::Unsolicited(_)) = self.steps.front()
            && let Some(Step::Unsolicited(bytes)) = self.steps.pop_front()
        {
            self.rx.extend(bytes);
        }
        let n = buf.len().min(self.rx.len());
        for (d, s) in buf.iter_mut().zip(self.rx.drain(..n)) {
            *d = s;
        }
        Ok(n)
    }

    fn set_reset(&mut self, asserted: bool) -> Result<(), Rl78Error> {
        self.take_line(Line::Reset(asserted));
        Ok(())
    }

    fn set_tool0_low(&mut self, low: bool) -> Result<(), Rl78Error> {
        self.take_line(Line::Tool0Low(low));
        Ok(())
    }

    fn flush_input(&mut self) -> Result<(), Rl78Error> {
        self.take_line(Line::Flush);
        self.rx.clear();
        Ok(())
    }
}

/// Builds the target's side of a session, one monitor transaction at a time.
#[derive(Default)]
struct Script(ScriptedUart);

impl Script {
    fn exchange(&mut self, tx: &[u8], rx: &[u8]) -> &mut Self {
        self.0
            .steps
            .push_back(Step::Exchange(tx.to_vec(), rx.to_vec()));
        self
    }

    fn line(&mut self, l: Line) -> &mut Self {
        self.0.steps.push_back(Step::Line(l));
        self
    }

    fn unsolicited(&mut self, rx: &[u8]) -> &mut Self {
        self.0.steps.push_back(Step::Unsolicited(rx.to_vec()));
        self
    }

    fn set_addr(&mut self, addr: u32, len: usize) -> &mut Self {
        let a = addr - 0xF_0000;
        self.exchange(&[0x56, a as u8, (a >> 8) as u8, len as u8], &[0x00])
    }

    /// `56H` + `57H`, in the 256-byte pieces the driver uses.
    fn read(&mut self, addr: u32, data: &[u8]) -> &mut Self {
        for (i, chunk) in data.chunks(256).enumerate() {
            self.set_addr(addr + 256 * i as u32, chunk.len());
            self.exchange(&[0x57], chunk);
        }
        self
    }

    /// `56H` + `58H`.
    fn write(&mut self, addr: u32, data: &[u8]) -> &mut Self {
        for (i, chunk) in data.chunks(256).enumerate() {
            self.set_addr(addr + 256 * i as u32, chunk.len());
            let mut tx = vec![0x58];
            tx.extend_from_slice(chunk);
            self.exchange(&tx, &[0x00]);
        }
        self
    }

    fn unlock(&mut self) -> &mut Self {
        self.exchange(&[0x55], &[0xF1]).exchange(&[0; 10], &[0xF2])
    }

    /// A boot-mode reset and the `CAH` entry. RESET goes low before TOOL0 (§47.2).
    fn attach(&mut self, sync: [u8; 4]) -> &mut Self {
        self.line(Line::Reset(true))
            .line(Line::Tool0Low(true))
            .line(Line::Reset(false))
            .line(Line::Tool0Low(false))
            .line(Line::Flush);
        let mut reply = sync.to_vec();
        reply.push(0x00);
        self.exchange(&[0xCA], &reply).unlock()
    }

    /// What the driver reads to rebuild the register file: SP, the frame there, the banks, and
    /// CS/ES/PMC/MEM.
    fn context(&mut self, monitor_sp: u16, frame: [u8; 6], banks: [u8; 32]) -> &mut Self {
        self.read(0xF_FFF8, &monitor_sp.to_le_bytes())
            .read(0xF_0000 | u32::from(monitor_sp), &frame)
            .read(0xF_FEE0, &banks)
            .read(0xF_FFFC, &[0, 0, 0, 0])
    }
}

/// A session that has just attached with entry sync `sync`, then runs `script`.
struct Session {
    ocd: UartOcd<ScriptedUart>,
    state: Rl78CoreState,
}

impl Session {
    /// A target halted in its program, as after an attach, a run and a halt: what most of these
    /// scripts start from. The run and the halt are not scripted.
    fn attached(sync: [u8; 4], script: impl FnOnce(&mut Script)) -> Self {
        let mut s = Self::fresh(sync, script);
        s.state.at_boot_rom = false;
        s
    }

    /// A target just attached under reset, halted in the boot ROM before its program has run.
    fn fresh(sync: [u8; 4], script: impl FnOnce(&mut Script)) -> Self {
        let mut s = Script::default();
        s.attach(sync);
        script(&mut s);
        let mut ocd = UartOcd::new(s.0, [0; 10]);
        let entry = ocd.attach().unwrap();
        let mut state = Rl78CoreState::new();
        state.attached(super::flash::Attached::UnderReset(entry));
        Self { ocd, state }
    }

    fn core(&mut self) -> Rl78<'_> {
        Rl78::new(
            &mut self.ocd,
            &mut self.state,
            DefaultRl78Sequence::create(),
        )
        .unwrap()
    }

    fn assert_done(mut self) {
        self.ocd.link_mut().assert_done();
    }
}

/// The monitor's SP on a fresh attach (§28), and the frame of a program halted in its RAM loop at
/// FFB9CH with PSW 0EH: register bank 1.
const MONITOR_SP: u16 = 0xFBFA;
const FRAME_BANK1: [u8; 6] = [0xA1, 0xA0, 0x9C, 0xFB, 0x0F, 0x0E];

/// FFEE0H-FFEFFH as read in that halt: banks 3, 2, 1, then 0. Bank 0's image is the monitor's
/// scratch except D and E.
const BANKS_BANK1: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, // bank 3
    0, 0, 0, 0, 0, 0, 0, 0, // bank 2
    0x11, 0x10, 0x13, 0x12, 0x15, 0x14, 0x17, 0x16, // bank 1
    0x00, 0x00, 0x00, 0x01, 0xD1, 0xD0, 0xFE, 0xFE, // bank 0, in RAM
];

fn reg(core: &mut Rl78, id: u16) -> u32 {
    core.read_core_reg(RegisterId(id))
        .unwrap()
        .try_into()
        .unwrap()
}

#[test]
fn attach_asserts_reset_before_tool0() {
    // The script's order is the assertion: holding TOOL0 low first is a break the monitor
    // answers, and the reset truncates the answer into the next reply (§47.2).
    Session::attached([0; 4], |_| {}).assert_done();
}

#[test]
fn bank0_is_rebuilt_while_the_program_uses_bank1() {
    // Hardware run of §47.4: bank 0 held AX=A0A1 BC=B0B1 DE=D0D1 HL=E0E1, bank 1 1011..1617.
    // The sync carries bank 0's B, C, H and L; the frame its X and A.
    let mut s = Session::attached([0xB0, 0xB1, 0xE0, 0xE1], |s| {
        s.context(MONITOR_SP, FRAME_BANK1, BANKS_BANK1);
    });
    let mut core = s.core();
    let bank0: Vec<u32> = (0..8).map(|i| reg(&mut core, i)).collect();
    assert_eq!(bank0, [0xA1, 0xA0, 0xB1, 0xB0, 0xD1, 0xD0, 0xE1, 0xE0]);
    let bank1: Vec<u32> = (8..16).map(|i| reg(&mut core, i)).collect();
    assert_eq!(bank1, [0x11, 0x10, 0x13, 0x12, 0x15, 0x14, 0x17, 0x16]);
    // The current-bank view follows PSW's RBS bits.
    assert_eq!(reg(&mut core, PAIR_BASE), 0x1011);
    assert_eq!(reg(&mut core, PAIR_BASE + 3), 0x1617);
    assert_eq!(reg(&mut core, PC_ID), 0xF_FB9C);
    // The user's SP is above the six bytes the monitor's entry left.
    assert_eq!(reg(&mut core, SP_ID), 0xF_FC00);
    drop(core);
    s.assert_done();
}

/// What the 19-byte read routine looks like staged for `count` bytes at `addr`, into the low
/// buffer at FFC10H.
fn read20(addr: u32, count: u8) -> Vec<u8> {
    let mut code = super::STUB_READ20.to_vec();
    code[1] = (addr >> 16) as u8;
    code[3] = addr as u8;
    code[4] = (addr >> 8) as u8;
    code[6] = 0x10;
    code[7] = 0xFC;
    code[9] = count;
    code
}

#[test]
fn code_flash_is_read_by_a_routine_and_ram_is_given_back() {
    let ram: Vec<u8> = (0..0x400).map(|i| i as u8).collect();
    let mut after = ram.clone();
    after[0x80] = 0xAA;
    let mut s = Session::attached([0; 4], |s| {
        // Before borrowing RAM, the driver checks the monitor's stack is clear of what it will
        // use, which takes the register context (and SP with it).
        s.context(MONITOR_SP, [0, 0, 0x80, 0xFB, 0x0F, 0x06], [0; 32]);
        // The first routine saves all of RAM, then is staged low, behind a branch at the call
        // gate, called with 5BH, and its buffer read back: low, at FFC10H, clear of the
        // monitor's stack at FFBFAH.
        s.read(0xF_FB00, &ram)
            .write(0xF_FB00, &read20(0x000C0, 4))
            .write(0xF_FED0, &[0xEC, 0x00, 0xFB, 0x0F])
            .exchange(&[0x5B], &[0x00])
            .read(0xF_FC10, &[0xEF, 0xF7, 0xF9, 0x85]);
        // A read of RAM while it is borrowed goes to the target, but shows the saved copy.
        s.read(0xF_FB00, &[0x41, 0x00]);
        // Resuming puts RAM back first (with the debugger's write to it), then clears the step
        // enable at F0085H, then returns from the interrupt.
        s.write(0xF_FB00, &after)
            .write(0xF_0085, &[0x00])
            .exchange(&[0x5C, 0, 0, 0, 0], &[0x00]);
    });
    let mut core = s.core();
    let mut option_bytes = [0; 4];
    core.read_8(0xC0, &mut option_bytes).unwrap();
    assert_eq!(option_bytes, [0xEF, 0xF7, 0xF9, 0x85]);
    let mut seen = [0; 2];
    core.read_8(0xF_FB00, &mut seen).unwrap();
    assert_eq!(seen, [0x00, 0x01], "the user's RAM, not the routine");
    // No transaction: the write lands in the saved copy, which goes back on resume.
    core.write_8(0xF_FB80, &[0xAA]).unwrap();
    core.run().unwrap();
    drop(core);
    s.assert_done();
}

#[test]
fn step_arms_f0085h_and_unlocks_again() {
    let mut s = Session::attached([0; 4], |s| {
        s.write(0xF_0085, &[0x01])
            // The echo of L, then the re-entry sync: the target trapped after one instruction.
            .exchange(&[0x5C, 0, 0, 0, 0], &[0x00, 1, 2, 3, 4, 0x00])
            // Every monitor entry locks the session.
            .unlock()
            .context(MONITOR_SP, [0, 0, 0xEE, 0x00, 0x00, 0x06], [0; 32]);
    });
    let pc = s.core().step().unwrap().pc;
    assert_eq!(pc, 0xEE);
    s.assert_done();
}

#[test]
fn halt_polls_before_sending_the_halt_byte() {
    // The target stopped by itself (a breakpoint, or a reset into a debug stub) just before the
    // halt request. Sending 00H then would draw a second sync and leave the replies out of step,
    // so the script has no 00H in it: the driver must take the pending sync instead.
    let mut s = Session::attached([0; 4], |s| {
        s.write(0xF_0085, &[0x00])
            .exchange(&[0x5C, 0, 0, 0, 0], &[0x00])
            .unsolicited(&[0, 0, 0, 0, 0])
            .unlock()
            .context(MONITOR_SP, [0, 0, 0x80, 0xFB, 0x0F, 0x06], [0; 32])
            // Not after an FFH: a reset, not a breakpoint.
            .read(0xF_FB7F, &[0x00]);
    });
    let mut core = s.core();
    core.run().unwrap();
    assert_eq!(core.halt(Duration::from_millis(100)).unwrap().pc, 0xF_FB80);
    assert_eq!(
        core.status().unwrap(),
        CoreStatus::Halted(HaltReason::Unknown)
    );
    drop(core);
    s.assert_done();
}

#[test]
fn an_unanswered_halt_says_why() {
    let mut s = Session::attached([0; 4], |s| {
        s.write(0xF_0085, &[0x00])
            .exchange(&[0x5C, 0, 0, 0, 0], &[0x00])
            .exchange(&[0x00], &[]);
    });
    let mut core = s.core();
    core.run().unwrap();
    let err = core.halt(Duration::from_millis(100)).unwrap_err();
    assert!(
        matches!(err, Error::Rl78(Rl78Error::HaltUnanswered)),
        "{err:?}"
    );
    drop(core);
    s.assert_done();
}

#[test]
fn writing_back_an_unchanged_sp_is_allowed() {
    // GDB's G packet writes every register, SP included. Only a real change is refused, because
    // the interrupt frame lives at SP.
    let frame = [0, 0, 0x80, 0xFB, 0x0F, 0x06];
    let mut s = Session::attached([0; 4], |s| {
        s.context(MONITOR_SP, frame, [0; 32])
            .write(0xF_0085, &[0x00])
            .exchange(&[0x5C, 0, 0, 0, 0], &[0x00]);
    });
    let mut core = s.core();
    let sp = core.read_core_reg(RegisterId(SP_ID)).unwrap();
    core.write_core_reg(RegisterId(SP_ID), sp).unwrap();
    core.run().unwrap();
    drop(core);
    s.assert_done();

    let mut s = Session::attached([0; 4], |s| {
        s.context(MONITOR_SP, frame, [0; 32]);
    });
    let mut core = s.core();
    core.write_core_reg(RegisterId(SP_ID), 0xF_FE20u32.into())
        .unwrap();
    assert!(core.run().is_err());
}

#[test]
fn continue_from_a_fresh_attach_boots_the_program() {
    // Not 5CH: that would resume the boot ROM's idle loop. A normal reset instead.
    let mut s = Session::fresh([0; 4], |s| {
        s.line(Line::Reset(true))
            .line(Line::Reset(false))
            .line(Line::Flush);
    });
    s.core().run().unwrap();
    assert!(!s.core().core_halted().unwrap());
    s.assert_done();
}

#[test]
fn reset_boots_the_program_with_tool0_high() {
    let mut s = Session::attached([0; 4], |s| {
        s.line(Line::Reset(true))
            .line(Line::Reset(false))
            .line(Line::Flush);
    });
    s.core().reset().unwrap();
    assert!(!s.core().core_halted().unwrap());
    s.assert_done();
}
