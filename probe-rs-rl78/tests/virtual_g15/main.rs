//! The RL78 driver end to end against the virtual G15 ([`model`]): a probe-rs session over
//! the same `ComProbe` the FT232R uses, with a simulated part on the other end of the line.
//!
//! Each test is a behaviour first seen on the G15 FPB; section numbers are to
//! `g15_ocd_protocol_notes.md` in rl78_debug_re. The programs are assembled with the RL78 LLVM
//! backend's `llvm-mc`; the listings are next to the bytes.

mod model;

use std::sync::Once;
use std::time::Duration;

use model::VirtualG15;
use probe_rs::{
    Core, Error, MemoryInterface, Permissions, RegisterId, Session,
    architecture::rl78::{communication_interface::Rl78Error, registers::*},
    probe::Probe,
};
use probe_rs_rl78::com::ComProbe;

/// Where the test programs go: below the register banks, clear of the debugger's staging area
/// (`FFB00H`), its buffer (`FFD00H`) and the monitor's stack (`FFC00H` down).
const PROG: u64 = 0xF_FE00;
/// A counter the programs keep.
const COUNTER: u64 = 0xF_FE40;
const IDLE_LOOP: u64 = 0xE_FFFC;

/// `mov 0xfffab, #0xac` / `incw !0xffe40` / `br $-8`: feed the watchdog and count.
const FEED_AND_COUNT: [u8; 8] = [0xCE, 0xAB, 0xAC, 0xA2, 0x40, 0xFE, 0xEF, 0xF8];

/// `movw bc, #0` / 1: `incw bc` / `movw ax, bc` / `movw !0xffe40, ax` / `mov 0xfffab, #0xac` /
/// `br $1b`: a count kept in BC and stored where the host can see it.
const COUNT_IN_BC: [u8; 13] = [
    0x32, 0x00, 0x00, 0xA3, 0x13, 0xBF, 0x40, 0xFE, 0xCE, 0xAB, 0xAC, 0xEF, 0xF6,
];

/// `br $.`: a loop that never feeds the watchdog.
const SPIN: [u8; 2] = [0xEF, 0xFE];

fn session(g15: &VirtualG15) -> Session {
    static REGISTER: Once = Once::new();
    REGISTER.call_once(probe_rs_rl78::register_plugin);
    let probe = ComProbe::new(g15.clone(), [0; 10]);
    Probe::from_specific_probe(Box::new(probe))
        .attach("R5F12068", Permissions::default())
        .expect("attach to the virtual G15")
}

fn reg(core: &mut Core<'_>, id: u16) -> u64 {
    core.read_core_reg::<u64>(RegisterId(id)).unwrap()
}

/// Load a program into RAM and point the PC at it.
fn load(core: &mut Core<'_>, code: &[u8]) {
    core.write_8(PROG, code).unwrap();
    core.write_core_reg(RegisterId(PC_ID), PROG).unwrap();
}

fn counter(core: &mut Core<'_>) -> u16 {
    core.read_word_16(COUNTER).unwrap()
}

#[test]
fn attach_halts_in_the_rom_idle_loop() {
    let g15 = VirtualG15::new();
    let mut session = session(&g15);
    let mut core = session.core(0).unwrap();
    assert!(core.core_halted().unwrap());
    assert_eq!(reg(&mut core, PC_ID), IDLE_LOOP);
    // The boot ROM's stack: the monitor's frame is at FFC00H, the program's SP above it.
    assert_eq!(reg(&mut core, SP_ID), 0xF_FC06);
    assert_eq!(reg(&mut core, PSW_ID), 0x06);
}

#[test]
fn memory_round_trip_and_code_flash() {
    let g15 = VirtualG15::new();
    g15.lock().poke(0x0800, b"mirror");
    let mut session = session(&g15);
    let mut core = session.core(0).unwrap();

    let data: Vec<u8> = (0..32).collect();
    core.write_8(PROG, &data).unwrap();
    let mut back = [0; 32];
    core.read_8(PROG, &mut back).unwrap();
    assert_eq!(back[..], data[..]);

    // Below F0000H through a routine behind 5BH; the user's RAM is put back on resume.
    let mut opt = [0; 4];
    core.read_8(0xC0, &mut opt).unwrap();
    assert_eq!(opt, [0xEE, 0xFF, 0xF9, 0x8F]);
    // The same flash through the mirror, by the monitor's own read.
    let mut m = [0; 6];
    core.read_8(0xF_0800, &mut m).unwrap();
    assert_eq!(&m, b"mirror");
    core.read_8(PROG, &mut back).unwrap();
    assert_eq!(back[..], data[..], "the routine's RAM is the user's again");
}

#[test]
fn step_follows_the_program() {
    let g15 = VirtualG15::new();
    let mut session = session(&g15);
    let mut core = session.core(0).unwrap();
    load(&mut core, &FEED_AND_COUNT);
    core.write_word_16(COUNTER, 0).unwrap();
    let pcs: Vec<u64> = (0..4).map(|_| core.step().unwrap().pc).collect();
    assert_eq!(pcs, [PROG + 3, PROG + 6, PROG, PROG + 3]);
    assert_eq!(counter(&mut core), g15.lock().peek16(COUNTER as u32));
    assert_eq!(g15.lock().peek16(COUNTER as u32), 1, "the INCW ran once");

    // F0085H is sticky across an execute (§23.1): a run after a step must clear it, or it is
    // another step.
    core.run().unwrap();
    g15.run_for_ms(1);
    core.halt(Duration::from_millis(100)).unwrap();
    assert!(counter(&mut core) > 100, "ran freely after the steps");
}

/// §48.2: `5CH` loads B, C, H and L from the host. Resuming with anything but the program's own
/// clobbers them; this program would restart its count.
#[test]
fn resume_gives_the_program_its_bc_back() {
    let g15 = VirtualG15::new();
    let mut session = session(&g15);
    let mut core = session.core(0).unwrap();
    load(&mut core, &COUNT_IN_BC);
    let mut last = 0;
    for _ in 0..4 {
        core.run().unwrap();
        g15.run_for_ms(2);
        core.halt(Duration::from_millis(100)).unwrap();
        let n = counter(&mut core);
        assert!(n > last, "the count went from {last} to {n}");
        let bc = reg(&mut core, PAIR_BASE + 1) as u16;
        assert!(
            bc == n || bc == n.wrapping_add(1),
            "BC {bc} against the stored {n}"
        );
        last = n;
    }
}

/// §47.4: the monitor's prologue is `SEL RB0`, so bank 0's RAM image is its scratch, whichever
/// bank the program used. AX comes back from the frame and B, C, H, L from the sync.
#[test]
fn bank_0_is_rebuilt_with_the_program_in_bank_1() {
    // movw ax/bc/de/hl with A0A1 B0B1 D0D1 E0E1; sel rb1; the same with 1011..1617;
    // 1: mov 0xfffab, #0xac; br $1b
    let code = [
        0x30, 0xA1, 0xA0, 0x32, 0xB1, 0xB0, 0x34, 0xD1, 0xD0, 0x36, 0xE1, 0xE0, 0x61, 0xDF, 0x30,
        0x11, 0x10, 0x32, 0x13, 0x12, 0x34, 0x15, 0x14, 0x36, 0x17, 0x16, 0xCE, 0xAB, 0xAC, 0xEF,
        0xFB,
    ];
    let g15 = VirtualG15::new();
    let mut session = session(&g15);
    let mut core = session.core(0).unwrap();
    load(&mut core, &code);
    core.run().unwrap();
    g15.run_for_ms(1);
    core.halt(Duration::from_millis(100)).unwrap();

    let bank0: Vec<u8> = (0..8).map(|i| reg(&mut core, i) as u8).collect();
    assert_eq!(bank0, [0xA1, 0xA0, 0xB1, 0xB0, 0xD1, 0xD0, 0xE1, 0xE0]);
    let bank1: Vec<u8> = (8..16).map(|i| reg(&mut core, i) as u8).collect();
    assert_eq!(bank1, [0x11, 0x10, 0x13, 0x12, 0x15, 0x14, 0x17, 0x16]);
    assert_eq!(reg(&mut core, PAIR_BASE), 0x1011, "AX is bank 1's");
    // What a debugger that read bank 0 from RAM would have shown.
    let raw: Vec<u8> = (0..8).map(|i| g15.lock().peek(0xF_FEF8 + i)).collect();
    assert_ne!(raw, bank0);
}

/// An `FFH` traps into the monitor; the frame holds the address after it (§24, §27.5).
#[test]
fn ffh_traps_into_the_monitor() {
    let g15 = VirtualG15::new();
    let mut session = session(&g15);
    let mut core = session.core(0).unwrap();
    load(&mut core, &[0x00, 0xFF, 0x00]); // nop; FFH; nop
    core.run().unwrap();
    core.wait_for_core_halted(Duration::from_secs(1)).unwrap();
    assert_eq!(reg(&mut core, PC_ID), PROG + 2);
}

/// §47.1: after a `CAH` attach the watchdog runs whatever the option byte says. A program that
/// feeds it keeps running; one that does not is reset, comes back with the monitor disarmed
/// (no debug stub in flash), and the halt goes unanswered.
#[test]
fn watchdog_after_attach() {
    let g15 = VirtualG15::new();
    let mut session = session(&g15);
    let mut core = session.core(0).unwrap();
    load(&mut core, &FEED_AND_COUNT);
    core.run().unwrap();
    g15.run_for_ms(200);
    core.halt(Duration::from_millis(100)).unwrap();
    assert!(counter(&mut core) > 1000);
    assert_eq!(g15.lock().resets, 0);

    load(&mut core, &SPIN);
    core.run().unwrap();
    g15.run_for_ms(200);
    assert!(g15.lock().resets > 0);
    match core.halt(Duration::from_millis(100)) {
        Err(Error::Rl78(Rl78Error::HaltUnanswered)) => {}
        other => panic!("expected an unanswered halt, got {other:?}"),
    }
}

/// §47.2: the boot-mode reset asserts RESET before holding TOOL0 low; the other order leaves the
/// monitor's answer to the break in the line. Attaching repeatedly in one session shows it.
#[test]
fn attach_three_times() {
    let g15 = VirtualG15::new();
    let mut session = session(&g15);
    let mut core = session.core(0).unwrap();
    for _ in 0..3 {
        assert_eq!(
            core.reset_and_halt(Duration::from_millis(100)).unwrap().pc,
            IDLE_LOOP
        );
        core.write_8(PROG, &[1, 2, 3]).unwrap();
    }
}

/// The Phase 2 design: the debug stub in the image arms the monitor at every boot, so a normal
/// reset runs the program with the watchdog as its option byte sets it, and a `00H` halts it
/// with no reset (§31).
#[test]
fn normal_reset_then_hot_attach() {
    let g15 = VirtualG15::new();
    {
        let mut m = g15.lock();
        m.poke(0x0000, &[0xCE, 0x00]); // reset vector -> the stub
        // mov !0xf0080, #0xc5; mov 0xfffaf, #0x40; br !0x00d8
        m.poke(
            0x00CE,
            &[0xCF, 0x80, 0x00, 0xC5, 0xCE, 0xAF, 0x40, 0xED, 0xD8, 0x00],
        );
        // movw sp, #0xfe20; 1: mov 0xfffab, #0xac; incw !0xffe40; br $1b
        m.poke(0x00D8, &[0xCB, 0xF8, 0x20, 0xFE]);
        m.poke(0x00DC, &FEED_AND_COUNT);
    }
    let mut session = session(&g15);
    let mut core = session.core(0).unwrap();
    core.reset().unwrap();
    g15.run_for_ms(20);
    let pc = core.halt(Duration::from_millis(100)).unwrap().pc;
    assert!((0xDC..0xE4).contains(&pc), "halted at {pc:05X}H");
    let n = counter(&mut core);
    assert!(n > 0);
    let mut wdte = [0];
    core.read_8(0xF_FFAB, &mut wdte).unwrap();
    assert_eq!(
        wdte[0], 0x1A,
        "the option byte's watchdog setting (off) applies"
    );
    core.run().unwrap();
    g15.run_for_ms(5);
    core.halt(Duration::from_millis(100)).unwrap();
    assert!(counter(&mut core) > n);
}

/// The model itself: holding TOOL0 low on a part sitting in the monitor, before RESET, leaves
/// bytes behind that the next flush misses (§47.2), which is why the driver resets first.
#[test]
fn model_break_before_reset_leaves_bytes_behind() {
    use probe_rs::architecture::rl78::communication_interface::Rl78Uart;

    let mut g15 = VirtualG15::new();
    let enter = |g15: &mut VirtualG15, tool0_first: bool| {
        if tool0_first {
            g15.set_tool0_low(true).unwrap();
            g15.set_reset(true).unwrap();
        } else {
            g15.set_reset(true).unwrap();
            g15.set_tool0_low(true).unwrap();
        }
        g15.set_reset(false).unwrap();
        g15.set_tool0_low(false).unwrap();
        g15.flush_input().unwrap();
        g15.write(&[0xCA]).unwrap();
        let mut buf = [0; 16];
        g15.read(&mut buf, Duration::ZERO).unwrap()
    };
    assert_eq!(enter(&mut g15, false), 5, "the sync alone");
    assert!(g15.in_monitor());
    assert_eq!(enter(&mut g15, false), 5);
    assert!(
        enter(&mut g15, true) > 5,
        "the break's answer, then the sync"
    );
}
