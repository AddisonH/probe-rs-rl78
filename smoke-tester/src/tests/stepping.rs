use std::time::Duration;

use linkme::distributed_slice;
use probe_rs::{
    Architecture, BreakpointCause, Core, CoreRegister, CoreRegisters, CoreStatus, Error,
    HaltReason, MemoryInterface, config::MemoryRegion, probe::DebugProbeError,
};

use crate::{CORE_TESTS, TestResult, dut_definition::DutDefinition, skip_test};

/// The test function for one architecture: it zeroes a counter and stops at a breakpoint
/// instruction, counts to 129, sets a flag register to 1 and stops at another.
struct TestProgram {
    code: &'static [u8],
    /// Where a step from the start leaves the PC.
    first_step: u64,
    /// The offsets of the two breakpoint instructions, and their length.
    breaks: [u64; 2],
    break_len: u64,
    counter: fn(&CoreRegisters) -> &CoreRegister,
    flag: fn(&CoreRegisters) -> &CoreRegister,
}

/// `test_function_arm.s`
const ARM: TestProgram = TestProgram {
    code: include_bytes!("test_arm.bin"),
    first_step: 2,
    breaks: [0x6, 0x10],
    break_len: 2,
    counter: |r| r.core_register(0),
    flag: |r| r.core_register(2),
};

/// `test_function_rl78.s`
const RL78: TestProgram = TestProgram {
    code: include_bytes!("test_rl78.bin"),
    first_step: 1,
    breaks: [0x6, 0xE],
    break_len: 1,
    counter: |r| named(r, "ax"),
    flag: |r| named(r, "e"),
};

fn named<'r>(registers: &'r CoreRegisters, name: &str) -> &'r CoreRegister {
    registers
        .core_registers()
        .find(|r| r.name() == name)
        .unwrap_or_else(|| panic!("no register {name}"))
}

#[smoke_tester_macros::test(core)]
fn test_stepping(_definition: &DutDefinition, core: &mut Core) -> TestResult {
    println!("Testing stepping on core {}...", core.id());

    let program = match core.architecture() {
        Architecture::Arm => &ARM,
        Architecture::Rl78 => &RL78,
        _ => {
            skip_test!("Not implemented for architectures other than ARM and RL78");
        }
    };

    let ram_region = core
        .memory_regions()
        .filter_map(MemoryRegion::as_ram_region)
        .find(|r| r.is_executable());

    let Some(ram_region) = ram_region else {
        skip_test!("No RAM configured for core, unable to test stepping");
    };

    let code_load_address = ram_region.range.start;

    core.reset_and_halt(Duration::from_millis(500))?;

    core.write_8(code_load_address, program.code)?;

    let registers = core.registers();
    core.write_core_reg(registers.pc().unwrap(), code_load_address)?;

    let core_information = core.step()?;

    let expected_pc = code_load_address + program.first_step;

    let core_status = core.status()?;

    assert_eq!(
        core_information.pc, expected_pc,
        "After stepping, PC should be at 0x{:08x}, but is at 0x{:08x}. Core state: {:?}",
        expected_pc, core_information.pc, core_status
    );
    if core_status != CoreStatus::Halted(HaltReason::Step) {
        log::warn!("Unexpected core status: {core_status:?}!");
    }

    let r0_value: u64 = core.read_core_reg((program.counter)(registers))?;

    assert_eq!(r0_value, 0);

    println!("R0 value ok!");

    println!(
        "Core halted at {:#08x}, now trying to run...",
        core_information.pc
    );

    // Run up to the software breakpoint (bkpt) at offset 0x6
    let break_address = code_load_address + program.breaks[0];
    core.run()?;

    match core.wait_for_core_halted(Duration::from_millis(100)) {
        Ok(()) => {}
        Err(Error::Probe(DebugProbeError::Timeout)) => {
            println!("Core did not halt after timeout!");
            core.halt(Duration::from_millis(100))?;

            let pc: u64 = core.read_core_reg(core.program_counter())?;

            println!("Core stopped at: {pc:#08x}");

            let r2_val: u64 = core.read_core_reg((program.flag)(registers))?;

            println!("$r2 = {r2_val:#08x}");
        }
        Err(other) => return Err(other.into()),
    }

    println!("Core halted again!");

    let core_status = core.status()?;

    assert!(matches!(
        core_status,
        CoreStatus::Halted(HaltReason::Breakpoint(
            BreakpointCause::Hardware | BreakpointCause::Software | BreakpointCause::Unknown
        ))
    ));

    let pc: u64 = core.read_core_reg(core.program_counter())?;

    assert_eq!(pc, break_address);

    println!("Core halted at {pc:#08x}, now trying to run...");

    // Move the PC past the breakpoint instruction.
    let pc = pc + program.break_len;
    core.write_core_reg(core.program_counter(), pc)?;

    println!("Run core again, with pc = {pc:#010x}");

    // Run to the finish
    core.run()?;

    // Final breakpoint is at offset 0x10

    let break_address = code_load_address + program.breaks[1];

    match core.wait_for_core_halted(Duration::from_millis(100)) {
        Ok(()) => {}
        Err(Error::Probe(DebugProbeError::Timeout)) => {
            println!("Core did not halt after timeout!");
            core.halt(Duration::from_millis(100))?;

            let pc: u64 = core.read_core_reg(core.program_counter())?;

            println!("Core stopped at: {pc:#08x}");

            let r2_val: u64 = core.read_core_reg((program.flag)(registers))?;

            println!("$r2 = {r2_val:#08x}");
        }
        Err(other) => return Err(other.into()),
    }

    let core_status = core.status()?;

    assert!(matches!(
        core_status,
        CoreStatus::Halted(HaltReason::Breakpoint(
            BreakpointCause::Hardware | BreakpointCause::Software | BreakpointCause::Unknown
        ))
    ));

    let pc: u64 = core.read_core_reg(core.program_counter())?;

    assert_eq!(pc, break_address, "{pc:#08x} != {break_address:#08x}");

    // Register r2 should be 1 to indicate end of test.
    let r2_val: u64 = core.read_core_reg((program.flag)(registers))?;
    assert_eq!(1, r2_val);

    Ok(())
}
