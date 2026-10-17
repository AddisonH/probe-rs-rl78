//! RL78 registers.
//!
//! Two views of the same register file:
//!
//! - **Raw**, `RegisterId(0..=39)`, in the order and widths GDB's `rl78` architecture fixes for its
//!   `g` packet: the 32 bank bytes (bank 0 first, each `X A C B E D L H`), then PSW, ES, CS, PC,
//!   SPL, SPH, PMC and MEM. 43 bytes in all, PC being four of them. GDB's `rl78` port takes no
//!   target description, so this order is not negotiable.
//! - **Current bank**: `AX BC DE HL` and `X A C B E D L H` of whichever bank PSW selects, and a
//!   20-bit SP. These carry the DWARF register numbers RL78 compilers emit, so the unwinder and
//!   variable locations resolve against them.

use std::sync::LazyLock;

use crate::{
    CoreRegisters,
    core::{CoreRegister, RegisterDataType, RegisterId, RegisterRole, UnwindRule},
};

/// Number of raw registers in GDB's `rl78` layout.
pub const NUM_RAW: usize = 40;

/// First raw id after the bank bytes.
pub const PSW_ID: u16 = 32;
/// ES
pub const ES_ID: u16 = 33;
/// CS
pub const CS_ID: u16 = 34;
/// PC
pub const PC_ID: u16 = 35;
/// SPL
pub const SPL_ID: u16 = 36;
/// SPH
pub const SPH_ID: u16 = 37;
/// PMC
pub const PMC_ID: u16 = 38;
/// MEM
pub const MEM_ID: u16 = 39;

/// Base of the current-bank pair registers AX, BC, DE, HL.
pub const PAIR_BASE: u16 = 0x100;
/// Base of the current-bank byte registers X A C B E D L H.
pub const BYTE_BASE: u16 = 0x110;
/// The 20-bit stack pointer, `F0000H | SPH:SPL`.
pub const SP_ID: u16 = 0x120;

const fn reg(
    roles: &'static [RegisterRole],
    id: u16,
    dwarf_id: Option<u16>,
    bits: usize,
) -> CoreRegister {
    CoreRegister {
        roles,
        id: RegisterId(id),
        dwarf_id,
        data_type: RegisterDataType::UnsignedInteger(bits),
        unwind_rule: UnwindRule::Clear,
    }
}

/// The program counter, 20 bits.
pub const PC: CoreRegister = CoreRegister {
    unwind_rule: UnwindRule::SpecialRule,
    ..reg(
        &[RegisterRole::Core("pc"), RegisterRole::ProgramCounter],
        PC_ID,
        Some(37),
        32,
    )
};

/// The stack pointer as an address: SP always points into the F-segment.
pub const SP: CoreRegister = CoreRegister {
    unwind_rule: UnwindRule::SpecialRule,
    ..reg(
        &[
            RegisterRole::Core("sp"),
            RegisterRole::StackPointer,
            // RL78 code addresses its frame through SP.
            RegisterRole::FramePointer,
        ],
        SP_ID,
        Some(32),
        32,
    )
};

/// PSW
pub const PSW: CoreRegister = reg(
    &[RegisterRole::Core("psw"), RegisterRole::ProcessorStatus],
    PSW_ID,
    None,
    8,
);

const ES: CoreRegister = reg(&[RegisterRole::Core("es")], ES_ID, None, 8);
const CS: CoreRegister = reg(&[RegisterRole::Core("cs")], CS_ID, None, 8);
const SPL: CoreRegister = reg(&[RegisterRole::Core("spl")], SPL_ID, None, 8);
const SPH: CoreRegister = reg(&[RegisterRole::Core("sph")], SPH_ID, None, 8);
const PMC: CoreRegister = reg(&[RegisterRole::Core("pmc")], PMC_ID, None, 8);
const MEM: CoreRegister = reg(&[RegisterRole::Core("mem")], MEM_ID, None, 8);

const PAIRS: [CoreRegister; 4] = [
    reg(&[RegisterRole::Core("ax")], PAIR_BASE, Some(38), 16),
    reg(&[RegisterRole::Core("bc")], PAIR_BASE + 1, Some(39), 16),
    reg(&[RegisterRole::Core("de")], PAIR_BASE + 2, Some(40), 16),
    reg(&[RegisterRole::Core("hl")], PAIR_BASE + 3, Some(41), 16),
];

/// Within a bank, R0..R7 are X A C B E D L H.
pub const BANK_REG_NAMES: [&str; 8] = ["x", "a", "c", "b", "e", "d", "l", "h"];

const BYTES: [CoreRegister; 8] = [
    reg(&[RegisterRole::Core("x")], BYTE_BASE, Some(46), 8),
    reg(&[RegisterRole::Core("a")], BYTE_BASE + 1, Some(47), 8),
    reg(&[RegisterRole::Core("c")], BYTE_BASE + 2, Some(48), 8),
    reg(&[RegisterRole::Core("b")], BYTE_BASE + 3, Some(49), 8),
    reg(&[RegisterRole::Core("e")], BYTE_BASE + 4, Some(50), 8),
    reg(&[RegisterRole::Core("d")], BYTE_BASE + 5, Some(51), 8),
    reg(&[RegisterRole::Core("l")], BYTE_BASE + 6, Some(52), 8),
    reg(&[RegisterRole::Core("h")], BYTE_BASE + 7, Some(53), 8),
];

macro_rules! bank {
    ($b:literal) => {
        [
            reg(
                &[RegisterRole::Core(concat!("rb", $b, "_x"))],
                $b * 8,
                None,
                8,
            ),
            reg(
                &[RegisterRole::Core(concat!("rb", $b, "_a"))],
                $b * 8 + 1,
                None,
                8,
            ),
            reg(
                &[RegisterRole::Core(concat!("rb", $b, "_c"))],
                $b * 8 + 2,
                None,
                8,
            ),
            reg(
                &[RegisterRole::Core(concat!("rb", $b, "_b"))],
                $b * 8 + 3,
                None,
                8,
            ),
            reg(
                &[RegisterRole::Core(concat!("rb", $b, "_e"))],
                $b * 8 + 4,
                None,
                8,
            ),
            reg(
                &[RegisterRole::Core(concat!("rb", $b, "_d"))],
                $b * 8 + 5,
                None,
                8,
            ),
            reg(
                &[RegisterRole::Core(concat!("rb", $b, "_l"))],
                $b * 8 + 6,
                None,
                8,
            ),
            reg(
                &[RegisterRole::Core(concat!("rb", $b, "_h"))],
                $b * 8 + 7,
                None,
                8,
            ),
        ]
    };
}

const BANKS: [[CoreRegister; 8]; 4] = [bank!(0), bank!(1), bank!(2), bank!(3)];

/// All RL78 registers: the current-bank view first, because that is what a person reading
/// registers wants, then the raw file.
pub static RL78_CORE_REGISTERS: LazyLock<CoreRegisters> = LazyLock::new(|| {
    CoreRegisters::new(
        [&PC, &SP, &PSW, &ES, &CS]
            .into_iter()
            .chain(PAIRS.iter())
            .chain(BYTES.iter())
            .chain(BANKS.iter().flatten())
            .chain([&SPL, &SPH, &PMC, &MEM])
            .collect(),
    )
});

/// The raw registers in GDB's `g` packet order, with their widths in bits.
pub fn gdb_raw_layout() -> impl Iterator<Item = (String, usize, RegisterId)> {
    let banks = (0..32u16).map(|i| {
        (
            format!("bank{}_{}", i / 8, BANK_REG_NAMES[usize::from(i % 8)]),
            8,
            RegisterId(i),
        )
    });
    let rest = [
        ("psw", 8, PSW_ID),
        ("es", 8, ES_ID),
        ("cs", 8, CS_ID),
        ("pc", 32, PC_ID),
        ("spl", 8, SPL_ID),
        ("sph", 8, SPH_ID),
        ("pmc", 8, PMC_ID),
        ("mem", 8, MEM_ID),
    ]
    .into_iter()
    .map(|(n, b, id)| (n.to_owned(), b, RegisterId(id)));
    banks.chain(rest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gdb_layout_is_43_bytes() {
        let bytes: usize = gdb_raw_layout().map(|(_, bits, _)| bits / 8).sum();
        assert_eq!(bytes, 43);
        assert_eq!(gdb_raw_layout().count(), NUM_RAW);
    }

    #[test]
    fn ids_are_unique() {
        let mut ids: Vec<_> = RL78_CORE_REGISTERS.all_registers().map(|r| r.id).collect();
        let n = ids.len();
        ids.sort_by_key(|id| id.0);
        ids.dedup();
        assert_eq!(ids.len(), n);
    }
}
