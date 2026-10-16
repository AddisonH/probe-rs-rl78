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
    BreakpointCause, Core, CoreStatus, Error, HaltReason, MemoryInterface, Permissions, RegisterId,
    Session,
    architecture::rl78::{communication_interface::Rl78Error, registers::*},
    flashing::{DownloadOptions, FlashProgress},
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
    session_with_id(g15, [0; 10])
}

fn session_with_id(g15: &VirtualG15, security_id: [u8; 10]) -> Session {
    attach(g15, security_id, Permissions::default()).expect("attach to the virtual G15")
}

fn attach(
    g15: &VirtualG15,
    security_id: [u8; 10],
    permissions: Permissions,
) -> Result<Session, Error> {
    static REGISTER: Once = Once::new();
    REGISTER.call_once(probe_rs_rl78::register_plugin);
    let probe = ComProbe::new(g15.clone(), security_id);
    Probe::from_specific_probe(Box::new(probe)).attach("R5F12068", permissions)
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
    // Code flash the mirror shows is read through it, with no routine; a read across its start
    // takes the routine for the part below.
    let calls = g15.lock().calls;
    core.read_8(0x0800, &mut m).unwrap();
    assert_eq!(&m, b"mirror");
    assert_eq!(g15.lock().calls, calls);
    let mut across = [0; 8];
    core.read_8(0x07FE, &mut across).unwrap();
    assert_eq!(&across[2..], b"mirror");
    assert_eq!(g15.lock().calls, calls + 1);
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

/// The register banks are memory (`FFEE0H`-`FFEFFH`), and memory there is the program's
/// registers. Bank 0's RAM is the monitor's own registers while it runs (§47.4, §12.3), so a
/// direct write would land in the HL and B of the very loop doing the write.
#[test]
fn register_banks_through_memory() {
    let g15 = VirtualG15::new();
    let mut session = session(&g15);
    let mut core = session.core(0).unwrap();
    // `movw ax, hl` / `movw !0xffe40, ax` / `movw ax, de` / `movw !0xffe42, ax` / FFH
    load(
        &mut core,
        &[0x17, 0xBF, 0x40, 0xFE, 0x15, 0xBF, 0x42, 0xFE, 0xFF],
    );
    let sfrs = peek(&g15, 0xF_FF00, 0x100);

    // Bank 0's E, D, L, H, as a memory test writes the last word of RAM.
    core.write_8(0xF_FEFC, &[0xAC, 0xAB, 0x34, 0x12]).unwrap();
    // Bank 3's X, from the other end.
    core.write_8(0xF_FEE0, &[0x5A]).unwrap();
    let mut back = [0; 4];
    core.read_8(0xF_FEFC, &mut back).unwrap();
    assert_eq!(back, [0xAC, 0xAB, 0x34, 0x12]);
    assert_eq!(reg(&mut core, PAIR_BASE + 3), 0x1234, "HL");
    assert_eq!(reg(&mut core, 3 * 8), 0x5A, "bank 3's X");

    core.run().unwrap();
    core.wait_for_core_halted(Duration::from_secs(1)).unwrap();
    assert_eq!(
        g15.lock().peek16(COUNTER as u32),
        0x1234,
        "the program's HL"
    );
    assert_eq!(
        g15.lock().peek16(COUNTER as u32 + 2),
        0xABAC,
        "the program's DE"
    );
    assert_eq!(g15.lock().peek(0xF_FEE0), 0x5A);
    assert_eq!(
        peek(&g15, 0xF_FF00, 0x100),
        sfrs,
        "nothing written past the banks"
    );
}

/// An `FFH` traps into the monitor with the address after it in the frame (§24, §27.5). One the
/// program holds itself is a software breakpoint, with the PC on it as on ARM's `BKPT`; moved
/// past it, the program goes on.
#[test]
fn ffh_traps_into_the_monitor() {
    let g15 = VirtualG15::new();
    let mut session = session(&g15);
    let mut core = session.core(0).unwrap();
    load(&mut core, &[0x00, 0xFF, 0x00, 0xFF]); // nop; FFH; nop; FFH
    core.run().unwrap();
    core.wait_for_core_halted(Duration::from_secs(1)).unwrap();
    assert_eq!(reg(&mut core, PC_ID), PROG + 1);
    assert_eq!(
        core.status().unwrap(),
        CoreStatus::Halted(HaltReason::Breakpoint(BreakpointCause::Software))
    );
    core.write_core_reg(RegisterId(PC_ID), PROG + 2).unwrap();
    core.run().unwrap();
    core.wait_for_core_halted(Duration::from_secs(1)).unwrap();
    assert_eq!(reg(&mut core, PC_ID), PROG + 3);
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

/// A small image as a toolchain links it: reset vector, option bytes, the security ID and the
/// debug stub's place left erased, `code` at `000D8H`, and constants in another block.
fn image(code: &[u8]) -> Vec<(u64, Vec<u8>)> {
    let mut text = vec![0xCB, 0xF8, 0x20, 0xFE]; // movw sp, #0xfe20
    text.extend(code);
    vec![
        (0x0000, vec![0xD8, 0x00]),
        (0x00C0, vec![0xEE, 0xFF, 0xF9, 0x85]),
        (0x00D8, text),
        (0x0900, (0..=255).collect()),
    ]
}

fn flash(session: &mut Session, image: &[(u64, Vec<u8>)], chip_erase: bool) {
    let mut loader = session.target().flash_loader();
    for (address, data) in image {
        loader.add_data(*address, data).unwrap();
    }
    let mut options = DownloadOptions::default();
    options.verify = true;
    options.do_chip_erase = chip_erase;
    loader.commit(session, options).unwrap();
}

fn peek(g15: &VirtualG15, address: u32, len: u32) -> Vec<u8> {
    let m = g15.lock();
    (address..address + len).map(|a| m.peek(a)).collect()
}

/// Flash by self-programming (§7.1): the blocks the image touches are erased and written, the
/// rest are left alone. The image leaves the security ID erased, so it gets the session's
/// (§48.1) and the next attach still unlocks; and it leaves `000CEH`-`000D7H` free, so it gets
/// the debug stub (§31.3): after a normal reset the program runs and a `00H` halts it.
#[test]
fn flash_an_image() {
    let id = [0x5A, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0xA5];
    let g15 = VirtualG15::new();
    {
        let mut m = g15.lock();
        m.poke(0x00C4, &id);
        m.poke(0x1C00, b"untouched");
    }
    let mut session = session_with_id(&g15, id);
    let image = image(&FEED_AND_COUNT);
    flash(&mut session, &image, false);

    assert_eq!(g15.lock().flash().blocks_erased, 2, "blocks 0 and 2");
    for (address, data) in &image[2..] {
        assert_eq!(peek(&g15, *address as u32, data.len() as u32), *data);
    }
    assert_eq!(
        peek(&g15, 0x0000, 2),
        [0xCE, 0x00],
        "the reset vector, to the stub"
    );
    assert_eq!(
        peek(&g15, 0x00C0, 4),
        [0xEE, 0xFF, 0xF9, 0x8F],
        "debug-in-use bits"
    );
    assert_eq!(peek(&g15, 0x00C4, 10), id);
    assert_eq!(
        peek(&g15, 0x00D5, 3),
        [0xED, 0xD8, 0x00],
        "the stub's BR !000D8H"
    );
    assert_eq!(peek(&g15, 0x1C00, 9), b"untouched");
    assert_eq!(peek(&g15, 0x0400, 4), [0xFF; 4], "erased, not written");

    let mut core = session.core(0).unwrap();
    core.reset_and_halt(Duration::from_millis(100)).unwrap();
    core.reset().unwrap();
    g15.run_for_ms(5);
    let pc = core.halt(Duration::from_millis(100)).unwrap().pc;
    assert!(
        (0xDC..0xE4).contains(&pc),
        "halted in the program at {pc:05X}H"
    );
    assert!(counter(&mut core) > 100, "the flashed program runs");
}

/// Continuing straight after an attach boots the program (a normal reset), rather than resuming
/// the boot ROM's idle loop, where the watchdog runs whatever the option byte says (§47.1).
#[test]
fn continue_after_attach_boots_the_program() {
    let g15 = VirtualG15::new();
    let mut session = session(&g15);
    flash(&mut session, &image(&SPIN), false);
    let mut core = session.core(0).unwrap();
    core.reset_and_halt(Duration::from_millis(100)).unwrap();
    assert_eq!(reg(&mut core, PC_ID), IDLE_LOOP);
    core.run().unwrap();
    g15.run_for_ms(200);
    assert_eq!(
        g15.lock().resets,
        0,
        "the option byte's watchdog (off) applies"
    );
    let pc = core.halt(Duration::from_millis(100)).unwrap().pc;
    assert_eq!(pc, 0xDC, "in the program's loop");

    // Once it has run, continue is an ordinary resume.
    core.run().unwrap();
    g15.run_for_ms(1);
    assert_eq!(core.halt(Duration::from_millis(100)).unwrap().pc, 0xDC);
}

/// A step straight after an attach boots the program and stops at its entry, `000D8H` here: the
/// boot ROM's idle loop is no place to step. The one-shot trap that does it does not outlive the
/// next step.
#[test]
fn step_after_attach_stops_at_the_entry() {
    let g15 = VirtualG15::new();
    let mut session = session(&g15);
    flash(&mut session, &image(&SPIN), false);
    let mut core = session.core(0).unwrap();
    core.reset_and_halt(Duration::from_millis(100)).unwrap();
    assert_eq!(reg(&mut core, PC_ID), IDLE_LOOP);

    assert_eq!(
        core.step().unwrap().pc,
        0xD8,
        "at the program's first instruction"
    );
    assert_eq!(core.status().unwrap(), CoreStatus::Halted(HaltReason::Step));
    assert_eq!(peek(&g15, 0xD8, 1), [0xFF], "the trap that stopped it");
    assert_eq!(core.step().unwrap().pc, 0xDC, "past movw sp");
    assert_eq!(peek(&g15, 0xD8, 1), [0xCB], "the program's own byte again");
}

/// A breakpoint set while the program runs takes effect at once: a debugger sets breakpoints
/// whenever its user clicks, and the traps otherwise only go in when the target next runs.
/// Clearing one while running takes it out the same way, and the program runs on.
#[test]
fn breakpoints_change_while_running() {
    // In the image's constants: planted and taken out, never reached.
    const UNREACHED: u64 = 0x905;
    let g15 = VirtualG15::new();
    let mut session = session(&g15);
    flash(&mut session, &image(&FEED_AND_COUNT), false);
    let mut core = session.core(0).unwrap();
    core.reset_and_halt(Duration::from_millis(100)).unwrap();
    core.run().unwrap();
    g15.run_for_ms(1);

    core.set_hw_breakpoint(UNREACHED).unwrap();
    assert_eq!(g15.lock().peek(UNREACHED as u32), 0xFF, "put in at once");
    assert_eq!(core.status().unwrap(), CoreStatus::Running);
    core.clear_hw_breakpoint(UNREACHED).unwrap();
    assert_eq!(g15.lock().peek(UNREACHED as u32), 0x05, "taken out at once");
    let n = counter_running(&g15);
    g15.run_for_ms(1);
    assert!(counter_running(&g15) > n + 100, "and running on");

    core.set_hw_breakpoint(INCW_IN_FLASH).unwrap();
    core.wait_for_core_halted(Duration::from_secs(1)).unwrap();
    assert_eq!(reg(&mut core, PC_ID), INCW_IN_FLASH);
    assert!(matches!(
        core.status().unwrap(),
        CoreStatus::Halted(HaltReason::Breakpoint(_))
    ));
}

/// The counter, read from the model without disturbing the running program.
fn counter_running(g15: &VirtualG15) -> u16 {
    let m = g15.lock();
    u16::from_le_bytes([m.peek(COUNTER as u32), m.peek(COUNTER as u32 + 1)])
}

/// A session finds a program running with the stub's monitor armed and halts it where it is,
/// with no reset (§31): `probe-rs read` on a running board. Its end lets the program run on, as
/// it found it. A session that reflashes leaves the part halted instead: the old PC means
/// nothing in the new program.
#[test]
fn attach_to_a_running_program_and_leave_it_running() {
    let g15 = VirtualG15::new();
    {
        let mut session = session(&g15);
        flash(&mut session, &image(&FEED_AND_COUNT), false);
        session.core(0).unwrap().reset().unwrap();
    }
    g15.run_for_ms(1);

    {
        let mut session = session(&g15);
        let mut core = session.core(0).unwrap();
        let pc = reg(&mut core, PC_ID);
        assert!(
            (0xDC..0xE4).contains(&pc),
            "halted in the program at {pc:05X}H"
        );
        assert!(counter(&mut core) > 0, "and it had been running");
    }
    let n = counter_running(&g15);
    g15.run_for_ms(1);
    assert!(
        counter_running(&g15) > n + 100,
        "running again after the session"
    );
    assert_eq!(g15.lock().resets, 0);

    {
        let mut session = session(&g15);
        flash(&mut session, &image(&FEED_AND_COUNT), false);
    }
    let n = counter_running(&g15);
    g15.run_for_ms(1);
    assert_eq!(counter_running(&g15), n, "left halted after a reflash");
}

/// A routine the debugger runs (here the read routine, for code flash below the mirror) changes
/// ES; the program must get its own back when it resumes.
#[test]
fn routines_leave_the_programs_es() {
    let g15 = VirtualG15::new();
    let mut session = session(&g15);
    let mut core = session.core(0).unwrap();
    // `mov es, #5` / `br $.`
    load(&mut core, &[0x41, 0x05, 0xEF, 0xFE]);
    core.run().unwrap();
    g15.run_for_ms(1);
    core.halt(Duration::from_millis(100)).unwrap();
    let mut option_bytes = [0; 4];
    core.read_8(0x00C0, &mut option_bytes).unwrap();
    core.run().unwrap();
    g15.run_for_ms(1);
    assert_eq!(g15.lock().peek(0xF_FFFD), 0x05, "the program's ES");
}

/// e2 studio's monitor image (§4, §31): the reset vector on the debug stub, which branches to
/// `0FFFFH`, the option bytes it writes, and the session's security ID.
fn assert_monitor_image(g15: &VirtualG15, id: [u8; 10]) {
    assert_eq!(peek(g15, 0x0000, 2), [0xCE, 0x00]);
    assert_eq!(peek(g15, 0x00C0, 4), [0xFF, 0xFF, 0xF9, 0x8F]);
    assert_eq!(peek(g15, 0x00C4, 10), id);
    assert_eq!(
        peek(g15, 0x00CE, 10),
        [0xCF, 0x80, 0x00, 0xC5, 0xCE, 0xAF, 0x40, 0xED, 0xFF, 0xFF]
    );
    let m = g15.lock();
    let rest = (0x00D8..model::FLASH_SIZE).all(|a| m.peek(a) == 0xFF);
    assert!(rest, "the rest erased");
}

/// A part whose security ID is not the session's cannot be unlocked. Erasing it is the only way
/// in, and probe-rs erases only when told it may.
#[test]
fn locked_part_is_not_erased_without_permission() {
    let g15 = VirtualG15::new();
    g15.lock().poke(0x00C4, &[0x11; 10]);
    let error = attach(&g15, [0; 10], Permissions::default()).unwrap_err();
    assert!(matches!(error, Error::MissingPermissions(_)), "{error}");
    assert!(error.to_string().contains("--allow-erase-all"), "{error}");
    assert_eq!(g15.lock().flash_protocol_writes, 0);
    assert_eq!(peek(&g15, 0x00C4, 10), [0x11; 10]);
}

/// With erase-all permitted, the flash protocol erases the part and writes a monitor image with
/// the session's ID (Protocol B, [proto_b]), and the attach goes through.
#[test]
fn locked_part_is_recovered_with_erase_all() {
    let g15 = VirtualG15::new();
    g15.lock().poke(0x00C4, &[0x11; 10]);
    g15.lock().poke(0x1C00, b"program");
    let id = [0x22; 10];
    let mut session = attach(&g15, id, Permissions::new().allow_erase_all()).unwrap();
    assert_eq!(g15.lock().flash_protocol_writes, 1);
    assert_monitor_image(&g15, id);
    let mut core = session.core(0).unwrap();
    assert!(core.core_halted().unwrap());
    assert_eq!(reg(&mut core, PC_ID), IDLE_LOOP);
}

/// A blank part is recovered the same way, and then flashes and runs like any other.
#[test]
fn blank_part_is_recovered_then_flashed() {
    let g15 = VirtualG15::blank();
    let mut session = attach(&g15, [0; 10], Permissions::new().allow_erase_all()).unwrap();
    assert_monitor_image(&g15, [0; 10]);

    flash(&mut session, &image(&SPIN), false);
    assert_eq!(
        g15.lock().flash_protocol_writes,
        1,
        "flashing is self-programming"
    );
    let mut core = session.core(0).unwrap();
    core.reset_and_halt(Duration::from_millis(100)).unwrap();
    core.run().unwrap();
    g15.run_for_ms(10);
    assert_eq!(core.halt(Duration::from_millis(100)).unwrap().pc, 0xDC);
}

/// The part's own CRC of what it wrote is checked against the image's.
#[test]
fn recovery_checks_the_crc() {
    let g15 = VirtualG15::blank();
    g15.lock().flash_protocol_fault = true;
    let error = attach(&g15, [0; 10], Permissions::new().allow_erase_all()).unwrap_err();
    assert!(
        matches!(error, Error::Rl78(Rl78Error::FlashCrc { .. })),
        "{error:?}"
    );
}

/// `probe-rs erase` runs through the flash sequence: there is no flash algorithm to load.
#[test]
fn erase_all_through_the_sequence() {
    let g15 = VirtualG15::new();
    g15.lock().poke(0x1C00, b"program");
    let mut session = session(&g15);
    probe_rs::flashing::erase_all(&mut session, &mut FlashProgress::empty(), false).unwrap();
    assert_eq!(g15.lock().flash().blocks_erased, 8);
    assert!(peek(&g15, 0, model::FLASH_SIZE).iter().all(|&b| b == 0xFF));
    drop(session);

    // Blank, the part unlocks with the erased ID.
    attach(&g15, [0xFF; 10], Permissions::default()).unwrap();
}

/// A part that attaches is never erased, permitted or not.
#[test]
fn attachable_part_is_not_erased() {
    let g15 = VirtualG15::new();
    g15.lock().poke(0x1C00, b"program");
    attach(&g15, [0; 10], Permissions::new().allow_erase_all()).unwrap();
    assert_eq!(g15.lock().flash_protocol_writes, 0);
    assert_eq!(peek(&g15, 0x1C00, 7), b"program");
}

#[test]
fn flash_with_a_chip_erase() {
    let g15 = VirtualG15::new();
    let mut session = session(&g15);
    flash(&mut session, &image(&FEED_AND_COUNT), true);
    let mut m = g15.lock();
    assert_eq!(m.flash().blocks_erased, 8);
    assert_eq!(m.peek(0x0900 + 0x7F), 0x7F);
}

/// The debugger's routines and buffers live in the program's RAM. While the program is halted
/// the monitor runs on the program's stack, so a buffer over it would wreck the monitor's return
/// address: the buffer goes low in RAM, or high when the stack is low (§49.3). Only a stack down
/// in the routines' own code is refused.
#[test]
fn routines_avoid_the_stack() {
    let g15 = VirtualG15::new();
    g15.lock().poke(0x0100, &(0..=255).collect::<Vec<u8>>());
    let mut session = session(&g15);
    let mut core = session.core(0).unwrap();
    for sp in [0xFE00u16, 0xFD10, 0xFC20, 0xFB10] {
        // movw sp, #sp; 1: mov 0xfffab, #0xac; br $1b
        let [lo, hi] = sp.to_le_bytes();
        load(
            &mut core,
            &[0xCB, 0xF8, lo, hi, 0xCE, 0xAB, 0xAC, 0xEF, 0xFB],
        );
        core.run().unwrap();
        g15.run_for_ms(1);
        core.halt(Duration::from_millis(100)).unwrap();
        let mut code = [0; 256];
        let read = core.read_8(0x100, &mut code);
        if sp == 0xFB10 {
            let err = read.unwrap_err().to_string();
            assert!(err.contains("stack"), "{err}");
        } else {
            read.unwrap();
            assert_eq!(code[..], (0..=255).collect::<Vec<u8>>()[..], "SP {sp:04X}H");
        }
        // The monitor is unharmed.
        assert_eq!(reg(&mut core, SP_ID), 0xF_0000 | u64::from(sp));
        core.step().unwrap();
    }
}

/// Where [`image`] puts `FEED_AND_COUNT`'s `incw`: after `movw sp` at `000D8H` and the feed.
const INCW_IN_FLASH: u64 = 0xDF;

/// A breakpoint in flash is an `FFH` trap (§24): it costs a block rewrite, and the PC comes back
/// onto it. Continuing runs the instruction under it exactly once, then traps again. Ending the
/// session takes it out of flash.
#[test]
fn breakpoint_in_flash() {
    let g15 = VirtualG15::new();
    {
        let mut session = session(&g15);
        flash(&mut session, &image(&FEED_AND_COUNT), false);
        let erased = g15.lock().flash().blocks_erased;
        let mut core = session.core(0).unwrap();
        core.reset_and_halt(Duration::from_millis(100)).unwrap();
        core.set_hw_breakpoint(INCW_IN_FLASH).unwrap();
        core.run().unwrap();
        core.wait_for_core_halted(Duration::from_secs(1)).unwrap();
        assert_eq!(reg(&mut core, PC_ID), INCW_IN_FLASH);
        assert!(matches!(
            core.status().unwrap(),
            CoreStatus::Halted(HaltReason::Breakpoint(_))
        ));
        assert_eq!(g15.lock().flash().blocks_erased, erased + 1, "planting it");
        let mut code = [0; 3];
        core.read_8(INCW_IN_FLASH, &mut code).unwrap();
        assert_eq!(
            code,
            [0xA2, 0x40, 0xFE],
            "reads show the program, not the trap"
        );
        assert_eq!(g15.lock().peek(INCW_IN_FLASH as u32), 0xFF);

        let n = counter(&mut core);
        let calls = g15.lock().calls;
        for i in 1..=3 {
            core.run().unwrap();
            core.wait_for_core_halted(Duration::from_secs(1)).unwrap();
            assert_eq!(reg(&mut core, PC_ID), INCW_IN_FLASH);
            assert_eq!(counter(&mut core), n + i, "one INCW per continue");
        }
        assert_eq!(
            g15.lock().flash().blocks_erased,
            erased + 1,
            "continuing steps a copy: no rewrite"
        );
        assert_eq!(
            g15.lock().calls,
            calls + 3,
            "one routine a continue, to read the code: block 0 is below the mirror"
        );

        core.clear_hw_breakpoint(INCW_IN_FLASH).unwrap();
        core.run().unwrap();
        g15.run_for_ms(1);
        core.halt(Duration::from_millis(100)).unwrap();
        assert!(counter(&mut core) > n + 100, "ran freely once cleared");
        assert_eq!(g15.lock().peek(INCW_IN_FLASH as u32), 0xA2);

        // Set again and left set: the session's end takes it out.
        core.set_hw_breakpoint(INCW_IN_FLASH).unwrap();
        core.run().unwrap();
        core.wait_for_core_halted(Duration::from_secs(1)).unwrap();
        core.run().unwrap();
    }
    assert_eq!(
        g15.lock().peek(INCW_IN_FLASH as u32),
        0xA2,
        "restored at the end"
    );
}

/// A breakpoint in RAM is the same trap, written directly.
#[test]
fn breakpoint_in_ram() {
    let g15 = VirtualG15::new();
    let mut session = session(&g15);
    let mut core = session.core(0).unwrap();
    load(&mut core, &FEED_AND_COUNT);
    core.set_hw_breakpoint(PROG + 3).unwrap();
    core.run().unwrap();
    core.wait_for_core_halted(Duration::from_secs(1)).unwrap();
    assert_eq!(reg(&mut core, PC_ID), PROG + 3);
    let n = counter(&mut core);
    core.run().unwrap();
    core.wait_for_core_halted(Duration::from_secs(1)).unwrap();
    assert_eq!(counter(&mut core), n + 1);
    let mut code = [0; 1];
    core.read_8(PROG + 3, &mut code).unwrap();
    assert_eq!(code, [0xA2]);
    assert_eq!(g15.lock().flash().blocks_erased, 0, "no flash involved");
}

/// Two breakpoints in one block share its rewrites, and clearing one keeps the other. From the
/// first, the next instruction is the second: continuing stops there without running on.
/// A breakpoint in code the mirror shows (`00800H` up): the block is read through the mirror to
/// plant the trap, and a continue reads the instruction the same way, with no routine at all.
#[test]
fn breakpoint_above_the_mirror_start() {
    const CODE: u64 = 0x0800;
    const INCW: u64 = CODE + 7;
    let mut text = vec![0xCB, 0xF8, 0x20, 0xFE]; // movw sp, #0xfe20
    text.extend(FEED_AND_COUNT);
    let image = [
        (0x0000, vec![0x00, 0x08]),
        (0x00C0, vec![0xEE, 0xFF, 0xF9, 0x85]),
        (CODE, text),
    ];
    let g15 = VirtualG15::new();
    let mut session = session(&g15);
    flash(&mut session, &image, false);
    let mut core = session.core(0).unwrap();
    core.reset_and_halt(Duration::from_millis(100)).unwrap();
    core.set_hw_breakpoint(INCW).unwrap();
    core.run().unwrap();
    core.wait_for_core_halted(Duration::from_secs(1)).unwrap();
    assert_eq!(reg(&mut core, PC_ID), INCW);
    let erased = g15.lock().flash().blocks_erased;
    let calls = g15.lock().calls;
    let n = counter(&mut core);
    for i in 1..=3 {
        core.run().unwrap();
        core.wait_for_core_halted(Duration::from_secs(1)).unwrap();
        assert_eq!(reg(&mut core, PC_ID), INCW);
        assert_eq!(counter(&mut core), n + i);
    }
    assert_eq!(g15.lock().flash().blocks_erased, erased, "no rewrites");
    assert_eq!(g15.lock().calls, calls, "no routines");
}

/// Continuing from a breakpoint runs a copy of the instruction under it from below the stack
/// (a displaced step). Calls push the address after the copy, which has to become the address
/// after the original; relative branches and calls land relative to the copy; returns and
/// absolute branches land where they say.
#[test]
fn displaced_steps_over_calls_and_branches() {
    // dc: mov 0xfffab, #0xac
    // df: call !sub          (e9)
    // e2: call $!sub         (e9)
    // e5: br $0xdc
    // e7: nop; nop
    // e9: sub: incw !0xffe40
    // ec: ret
    #[rustfmt::skip]
    const CALLS: [u8; 17] = [
        0xCE, 0xAB, 0xAC, 0xFD, 0xE9, 0x00, 0xFE, 0x04, 0x00, 0xEF, 0xF5, 0x00, 0x00,
        0xA2, 0x40, 0xFE, 0xD7,
    ];
    let g15 = VirtualG15::new();
    let mut session = session(&g15);
    flash(&mut session, &image(&CALLS), false);
    let mut core = session.core(0).unwrap();
    core.reset_and_halt(Duration::from_millis(100)).unwrap();
    for address in [0xDF, 0xE2, 0xE5, 0xEC] {
        core.set_hw_breakpoint(address).unwrap();
    }
    core.run().unwrap();
    core.wait_for_core_halted(Duration::from_secs(1)).unwrap();
    assert_eq!(reg(&mut core, PC_ID), 0xDF);
    let erased = g15.lock().flash().blocks_erased;
    let sp = reg(&mut core, SP_ID);
    let n = counter(&mut core);

    // (PC, SP below the caller's, count) at each stop.
    let expected = [
        (0xEC, 4, 1),
        (0xE2, 0, 1),
        (0xEC, 4, 2),
        (0xE5, 0, 2),
        (0xDF, 0, 2),
        (0xEC, 4, 3),
    ];
    for (pc, pushed, count) in expected {
        core.run().unwrap();
        core.wait_for_core_halted(Duration::from_secs(1)).unwrap();
        assert_eq!(reg(&mut core, PC_ID), pc);
        assert_eq!(reg(&mut core, SP_ID), sp - pushed, "SP at {pc:#x}");
        assert_eq!(counter(&mut core), n + count, "count at {pc:#x}");
    }
    assert_eq!(g15.lock().flash().blocks_erased, erased, "no rewrites");

    // A step from a breakpoint is displaced too.
    assert_eq!(
        core.step().unwrap().pc,
        0xE2,
        "RET, to after the first call"
    );
    assert_eq!(core.step().unwrap().pc, 0xE9, "the relative call");
    assert_eq!(
        g15.lock().flash().blocks_erased,
        erased,
        "still no rewrites"
    );
}

#[test]
fn two_breakpoints_in_one_block() {
    const FEED: u64 = 0xDC;
    let g15 = VirtualG15::new();
    let mut session = session(&g15);
    flash(&mut session, &image(&FEED_AND_COUNT), false);
    let erased = g15.lock().flash().blocks_erased;
    let mut core = session.core(0).unwrap();
    core.reset_and_halt(Duration::from_millis(100)).unwrap();
    core.set_hw_breakpoint(FEED).unwrap();
    core.set_hw_breakpoint(INCW_IN_FLASH).unwrap();
    core.run().unwrap();
    core.wait_for_core_halted(Duration::from_secs(1)).unwrap();
    assert_eq!(reg(&mut core, PC_ID), FEED);
    assert_eq!(
        g15.lock().flash().blocks_erased,
        erased + 1,
        "both in one rewrite"
    );

    // A third in the same block, put in place by a step: the block is rewritten, and the trap
    // that is not changing stays.
    const BRANCH: u64 = 0xE2;
    core.set_hw_breakpoint(BRANCH).unwrap();
    assert_eq!(core.step().unwrap().pc, INCW_IN_FLASH);
    assert_eq!(g15.lock().peek(BRANCH as u32), 0xFF);
    assert_eq!(
        g15.lock().peek(INCW_IN_FLASH as u32),
        0xFF,
        "kept through the rewrite"
    );
    core.clear_hw_breakpoint(BRANCH).unwrap();
    core.set_hw_breakpoint(FEED).unwrap();
    core.reset_and_halt(Duration::from_millis(100)).unwrap();
    core.run().unwrap();
    core.wait_for_core_halted(Duration::from_secs(1)).unwrap();
    assert_eq!(reg(&mut core, PC_ID), FEED);
    let n = counter(&mut core);

    core.run().unwrap();
    core.wait_for_core_halted(Duration::from_secs(1)).unwrap();
    assert_eq!(reg(&mut core, PC_ID), INCW_IN_FLASH);
    assert_eq!(counter(&mut core), n);

    core.clear_hw_breakpoint(FEED).unwrap();
    core.run().unwrap();
    core.wait_for_core_halted(Duration::from_secs(1)).unwrap();
    assert_eq!(
        reg(&mut core, PC_ID),
        INCW_IN_FLASH,
        "the other one still traps"
    );
    assert_eq!(counter(&mut core), n + 1);
}
