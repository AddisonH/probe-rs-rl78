//! RL78 interrupts, as the unwinder sees them.
//!
//! RL78 has no link register. `CALL` pushes the return address into the low three bytes of a
//! four-byte slot and leaves the top byte as it was; an interrupt and `BRK` push the interrupted
//! PSW there instead [g15:p706]. The RL78 LLVM backend describes both with one CIE, CFA = SP + 4
//! and the program counter (its return address column) at CFA - 4, so the unwind information
//! finds every return address by itself.
//!
//! What it cannot say is which frames an interrupt entered. Their return address is the
//! interrupted instruction itself rather than the one after a call, and the byte above it is
//! the interrupted PSW. This handler recognises them by their entry point: a function whose
//! address is in the vector table.

use std::cell::OnceCell;

use gimli::{BaseAddresses, DebugFrame, UnwindSection};
use probe_rs::{CoreRegister, MemoryInterface, RegisterRole, RegisterValue};

use super::{ExceptionInfo, ExceptionInterface};
use crate::{DebugError, DebugInfo, DebugRegisters, StackFrame, get_object_reference};

/// The vector table, `00000H`-`0007FH`: the reset vector, then one 16-bit handler address per
/// interrupt source, ending with `BRK` at `0007EH`.
const VECTOR_TABLE_SIZE: usize = 0x80;
const BRK_VECTOR: u64 = 0x7E;

/// Unwinds RL78 interrupt frames.
#[derive(Default)]
pub struct Rl78ExceptionHandler {
    /// The vector table, read once per unwind. `None` if it could not be read.
    vectors: OnceCell<Option<[u8; VECTOR_TABLE_SIZE]>>,
}

impl Rl78ExceptionHandler {
    /// The vector, `02H`-`7EH`, through which `entry` is reached, if any. The reset vector is
    /// not one: a reset leaves no frame to return to.
    fn vector_of(&self, memory: &mut dyn MemoryInterface, entry: u64) -> Option<u64> {
        let table = self.vectors.get_or_init(|| {
            let mut table = [0; VECTOR_TABLE_SIZE];
            match memory.read(0, &mut table) {
                Ok(()) => Some(table),
                Err(error) => {
                    tracing::warn!("UNWIND: Cannot read the RL78 vector table: {error}");
                    None
                }
            }
        });
        table
            .as_ref()?
            .as_chunks::<2>()
            .0
            .iter()
            .enumerate()
            .skip(1)
            .find(|(_, handler)| u64::from(u16::from_le_bytes(**handler)) == entry)
            .map(|(index, _)| index as u64 * 2)
    }
}

/// The interrupted PC and PSW, from the four bytes below `cfa`.
fn interrupt_frame(memory: &mut dyn MemoryInterface, cfa: u64) -> Result<(u32, u32), DebugError> {
    let mut frame = [0; 4];
    memory.read(cfa - 4, &mut frame)?;
    let pc = u32::from_le_bytes([frame[0], frame[1], frame[2] & 0x0F, 0]);
    Ok((pc, frame[3].into()))
}

fn describe(vector: u64) -> String {
    if vector == BRK_VECTOR {
        "BRK".to_string()
    } else {
        format!("Interrupt (vector {vector:05X}H)")
    }
}

impl ExceptionInterface for Rl78ExceptionHandler {
    fn exception_details(
        &self,
        memory: &mut dyn MemoryInterface,
        stackframe_registers: &DebugRegisters,
        debug_info: &DebugInfo,
    ) -> Result<Option<ExceptionInfo>, DebugError> {
        // The program counter is still the called frame's; every other register has been
        // unwound into the calling frame, so the stack pointer is the called frame's CFA.
        let pc = stackframe_registers.get_register_value_by_role(&RegisterRole::ProgramCounter)?;
        let Ok(fde) = debug_info.frame_section.fde_for_address(
            &BaseAddresses::default(),
            pc,
            DebugFrame::cie_from_offset,
        ) else {
            return Ok(None);
        };
        let Some(vector) = self.vector_of(memory, fde.initial_address()) else {
            return Ok(None);
        };

        let cfa = stackframe_registers.get_register_value_by_role(&RegisterRole::StackPointer)?;
        let (interrupted_pc, psw) = interrupt_frame(memory, cfa)?;

        let mut registers = stackframe_registers.clone();
        registers
            .get_register_mut_by_role(&RegisterRole::ProgramCounter)?
            .value = Some(RegisterValue::U32(interrupted_pc));
        registers
            .get_register_mut_by_role(&RegisterRole::ProcessorStatus)?
            .value = Some(RegisterValue::U32(psw));

        let description = describe(vector);
        Ok(Some(ExceptionInfo {
            raw_exception: vector as u32,
            description: description.clone(),
            handler_frame: StackFrame {
                id: get_object_reference(),
                function_name: description,
                source_location: None,
                registers,
                pc: RegisterValue::U32(interrupted_pc),
                frame_base: None,
                is_inlined: false,
                local_variables: None,
                canonical_frame_address: None,
            },
        }))
    }

    fn raw_exception(&self, _stackframe_registers: &DebugRegisters) -> Result<u32, DebugError> {
        Err(DebugError::NotImplemented(
            "RL78 has no register that names the interrupt being served",
        ))
    }

    fn unwind_undefined_register(
        &self,
        debug_register: &CoreRegister,
        callee_frame_registers: &DebugRegisters,
        unwind_cfa: Option<u64>,
        memory: &mut dyn MemoryInterface,
        register_rule: &mut String,
    ) -> Result<Option<RegisterValue>, DebugError> {
        // The stack pointer of the calling frame is the CFA. The default rule rounds the CFA
        // down to four bytes, which suits Arm; an RL78 stack is only kept even, and is as often
        // at 2 mod 4 as at 0.
        if debug_register.register_has_role(RegisterRole::StackPointer) {
            *register_rule = "SP=CFA (dwarf Undefined)".to_string();
            return Ok(unwind_cfa.map(|cfa| RegisterValue::U32(cfa as u32)));
        }
        super::unwind_undefined_register(
            debug_register,
            callee_frame_registers,
            unwind_cfa,
            memory,
            register_rule,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use probe_rs::test::MockMemory;

    #[test]
    fn interrupt_frame_masks_the_bank_and_reads_psw() {
        // An interrupt at 11234H with PSW 86H and SP FFE00H before it. The upper nibble of
        // the bank byte is not part of the address.
        let mut memory = MockMemory::new();
        memory.add_range(0xFFDFC, vec![0x34, 0x12, 0xF1, 0x86]);
        assert_eq!(
            interrupt_frame(&mut memory, 0xFFE00).unwrap(),
            (0x1_1234, 0x86)
        );
    }

    #[test]
    fn describes_brk_and_interrupts() {
        assert_eq!(describe(0x7E), "BRK");
        assert_eq!(describe(0x2C), "Interrupt (vector 0002CH)");
    }
}
