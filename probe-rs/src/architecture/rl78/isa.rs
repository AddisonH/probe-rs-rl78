//! The RL78 instruction set as far as the debugger needs it: each instruction's length, what it
//! does to the PC, and its fewest clocks on the S3 core. `isa.tsv` lists every encoding in the
//! RL78 Family User's Manual: Software, with its clocks on each core; the S2 core's are the same
//! wherever it has the instruction, and it lacks only the S3's multiply and divide.

use std::{collections::HashMap, sync::LazyLock};

/// What an instruction does to the PC.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Flow {
    Next,
    Jump(u32),
    /// To the target or on to the next instruction, on a condition.
    Branch(u32),
    /// On, or past the next instruction, on a condition.
    Skip,
    Call(u32),
    /// `CALLT` or `BRK`: a call to the address held at this one.
    CallTable(u32),
    /// `CALL` through a register.
    CallIndirect,
    /// `RET`, `RETI` or `RETB`.
    Return,
    /// `BR AX`.
    JumpIndirect,
    /// `HALT` or `STOP`.
    Wait,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Insn {
    pub len: u32,
    pub flow: Flow,
    /// Clocks, the fewest the instruction can take.
    pub clocks: u8,
    /// An interrupt request is held pending until the next instruction has finished.
    pub holds: bool,
}

/// The operand bytes after an encoding's fixed ones.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Field {
    Rel8,
    Rel16,
    Abs16,
    Abs20,
    Sfr,
    Other,
}

#[derive(Debug)]
struct Row {
    fixed: Vec<u8>,
    fields: Vec<Field>,
    flow: Flow,
    clocks: u8,
    holds: bool,
}

/// Encodings by their fixed bytes, which are one to three long.
static TABLE: LazyLock<HashMap<Vec<u8>, Row>> = LazyLock::new(|| {
    let mut table = HashMap::new();
    for line in include_str!("isa.tsv").lines().skip(1) {
        let row = parse_row(line).unwrap_or_else(|| panic!("isa.tsv: cannot read {line:?}"));
        if let Some(row) = row {
            // EI and DI are also SET1 and CLR1 PSW.7: the same bytes, and the same row here.
            table.entry(row.fixed.clone()).or_insert(row);
        }
    }
    table
});

/// One line of `isa.tsv`, or `None` for one without clocks.
fn parse_row(line: &str) -> Option<Option<Row>> {
    let cols: Vec<&str> = line.split('\t').collect();
    let (mnemonic, operands, opcode, clocks) = (cols[0], cols[1], cols[2], *cols.get(3)?);
    if clocks.is_empty() {
        return Some(None);
    }
    let clocks = clocks.split('/').next()?.parse().ok()?;

    let mut fixed = Vec::new();
    let mut tokens = opcode.split(' ').peekable();
    while let Some(byte) = tokens.peek().and_then(|t| u8::from_str_radix(t, 16).ok()) {
        fixed.push(byte);
        tokens.next();
    }
    let target = operands.split(", ").find(|o| o.contains("addr"));
    let mut fields = Vec::new();
    while let Some(token) = tokens.next() {
        fields.push(match (token, target) {
            ("adr", _) => Field::Rel8,
            ("adrl", Some("$!addr20")) => Field::Rel16,
            ("adrl", Some("!!addr20")) => Field::Abs20,
            ("adrl", _) => Field::Abs16,
            ("sfr", _) => Field::Sfr,
            _ => Field::Other,
        });
        if matches!(token, "adrl") {
            tokens.next();
            if fields.last() == Some(&Field::Abs20) {
                tokens.next();
            }
        }
    }

    let flow = match mnemonic {
        "BR" if operands == "AX" => Flow::JumpIndirect,
        "BR" => Flow::Jump(0),
        "BC" | "BNC" | "BZ" | "BNZ" | "BH" | "BNH" | "BT" | "BF" | "BTCLR" => Flow::Branch(0),
        "SKC" | "SKNC" | "SKZ" | "SKNZ" | "SKH" | "SKNH" => Flow::Skip,
        "CALL" if target.is_none() => Flow::CallIndirect,
        "CALL" => Flow::Call(0),
        "CALLT" => Flow::CallTable(u32::from_str_radix(operands.get(1..5)?, 16).ok()?),
        "BRK" => Flow::CallTable(0x7E),
        "RET" | "RETI" | "RETB" => Flow::Return,
        "HALT" | "STOP" => Flow::Wait,
        _ => Flow::Next,
    };
    let writes_psw = operands.starts_with("PSW")
        && matches!(mnemonic, "MOV" | "MOV1" | "SET1" | "CLR1" | "POP" | "BTCLR");
    let holds = writes_psw
        || matches!(flow, Flow::Skip)
        || matches!(mnemonic, "EI" | "DI" | "RETI" | "RETB");
    Some(Some(Row {
        fixed,
        fields,
        flow,
        clocks,
        holds,
    }))
}

/// The interrupt flag, mask and priority registers, `FFFE0H`-`FFFEFH`: a write to one holds an
/// interrupt request pending, like the instructions marked so in the table.
fn is_interrupt_control(sfr: u8) -> bool {
    (0xE0..=0xEF).contains(&sfr)
}

/// Decode the instruction at `pc`. `code` holds its bytes and may run past it; six cover the
/// longest. `None` for bytes that are no instruction, `FFH` among them.
pub(super) fn decode(code: &[u8], pc: u32) -> Option<Insn> {
    let row = (1..=3)
        .rev()
        .filter(|&n| n <= code.len())
        .find_map(|n| TABLE.get(&code[..n]))?;
    let mut at = row.fixed.len();
    let mut target = None;
    let mut holds = row.holds;
    for field in &row.fields {
        let byte = |i: usize| code.get(at + i).copied().map(u32::from);
        let (value, size) = match field {
            Field::Rel8 | Field::Sfr | Field::Other => (byte(0)?, 1),
            Field::Rel16 | Field::Abs16 => (byte(0)? | byte(1)? << 8, 2),
            Field::Abs20 => (byte(0)? | byte(1)? << 8 | (byte(2)? & 0x0F) << 16, 3),
        };
        match field {
            Field::Rel8 => target = Some(value as u8 as i8 as i32),
            Field::Rel16 => target = Some(value as u16 as i16 as i32),
            Field::Abs16 if row.flow == Flow::Call(0) || row.flow == Flow::Jump(0) => {
                target = Some(value as i32)
            }
            Field::Abs16 => holds |= value >> 8 == 0xFF && is_interrupt_control(value as u8),
            Field::Abs20 => target = Some(value as i32),
            Field::Sfr => holds |= is_interrupt_control(value as u8),
            Field::Other => {}
        }
        at += size;
    }
    let len = at as u32;
    let relative = row
        .fields
        .iter()
        .any(|f| matches!(f, Field::Rel8 | Field::Rel16));
    let resolve = |t: i32| {
        if relative {
            pc.wrapping_add(len).wrapping_add(t as u32) & 0xF_FFFF
        } else {
            t as u32
        }
    };
    let flow = match (row.flow, target) {
        (Flow::Jump(_), Some(t)) => Flow::Jump(resolve(t)),
        (Flow::Branch(_), Some(t)) => Flow::Branch(resolve(t)),
        (Flow::Call(_), Some(t)) => Flow::Call(resolve(t)),
        (flow, _) => flow,
    };
    Some(Insn {
        len,
        flow,
        clocks: row.clocks,
        holds,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn insn(code: &[u8], pc: u32) -> Insn {
        decode(code, pc).unwrap_or_else(|| panic!("{code:02X?} does not decode"))
    }

    #[test]
    fn lengths_targets_and_clocks() {
        let cases: &[(&[u8], u32, u32, Flow, u8)] = &[
            (&[0xF6], 0x100, 1, Flow::Next, 1),                     // clrw ax
            (&[0xA8, 0x00], 0x788, 2, Flow::Next, 1),               // movw ax, [sp+0]
            (&[0x11, 0x8F, 0x34, 0x12], 0x100, 4, Flow::Next, 2),   // mov a, es:!0x1234
            (&[0xEF, 0xB0], 0x7CA, 2, Flow::Jump(0x77C), 3),        // br $0x77c
            (&[0xED, 0x34, 0x12], 0x100, 3, Flow::Jump(0x1234), 3), // br !0x1234
            (&[0xEC, 0x45, 0x23, 0x01], 0, 4, Flow::Jump(0x12345), 3), // br !!0x12345
            (&[0xDE, 0x05], 0x78E, 2, Flow::Branch(0x795), 2),      // bnc $0x795
            (&[0xDF, 0xC1], 0x7B9, 2, Flow::Branch(0x77C), 2),      // bnz $0x77c
            (&[0x31, 0x52, 0xA4, 0xFC], 0x3CE, 4, Flow::Branch(0x3CE), 3), // bt 0xfffa4.5, $.
            (&[0x61, 0xC3, 0x10], 0x100, 3, Flow::Branch(0x113), 2), // bh
            (&[0x61, 0xE8], 0x100, 2, Flow::Skip, 1),               // skz
            (&[0xFD, 0xDB, 0x03], 0x785, 3, Flow::Call(0x3DB), 3),  // call !0x3db
            (&[0xFE, 0x00, 0x01], 0x100, 3, Flow::Call(0x203), 3),  // call $!addr20
            (&[0xFC, 0x45, 0x23, 0x01], 0, 4, Flow::Call(0x12345), 3), // call !!0x12345
            (&[0x61, 0xFA], 0x100, 2, Flow::CallIndirect, 3),       // call hl
            (&[0x61, 0x84], 0x100, 2, Flow::CallTable(0x80), 5),    // callt [0x80]
            (&[0x61, 0xCC], 0x100, 2, Flow::CallTable(0x7E), 5),    // brk
            (&[0xD7], 0x684, 1, Flow::Return, 6),                   // ret
            (&[0x61, 0xFC], 0x100, 2, Flow::Return, 6),             // reti
            (&[0x61, 0xCB], 0x100, 2, Flow::JumpIndirect, 3),       // br ax
            (&[0x61, 0xED], 0x100, 2, Flow::Wait, 3),               // halt
        ];
        for &(code, pc, len, flow, clocks) in cases {
            let mut window = [0; 6];
            window[..code.len()].copy_from_slice(code);
            let i = insn(&window, pc);
            assert_eq!(
                (i.len, i.flow, i.clocks),
                (len, flow, clocks),
                "{code:02X?}"
            );
        }
        assert_eq!(decode(&[0xFF, 0, 0, 0, 0, 0], 0), None, "the trap byte");
    }

    #[test]
    fn every_encoding_decodes_as_itself() {
        for row in TABLE.values() {
            let mut code = row.fixed.clone();
            code.resize(6, 0);
            let len = decode(&code, 0).map(|i| i.len as usize);
            let operands: usize = row
                .fields
                .iter()
                .map(|f| match f {
                    Field::Rel16 | Field::Abs16 => 2,
                    Field::Abs20 => 3,
                    _ => 1,
                })
                .sum();
            assert_eq!(len, Some(row.fixed.len() + operands), "{:02X?}", row.fixed);
        }
    }

    /// Lengths against a disassembler's, over a whole program: `RL78_ISA_CHECK` names a file of
    /// `address bytes...` lines.
    #[test]
    #[ignore]
    fn lengths_match_a_listing() {
        let Ok(path) = std::env::var("RL78_ISA_CHECK") else {
            return;
        };
        let listing = std::fs::read_to_string(path).unwrap();
        let mut checked = 0;
        for line in listing.lines() {
            let mut words = line.split_whitespace();
            let pc = u32::from_str_radix(words.next().unwrap(), 16).unwrap();
            let bytes: Vec<u8> = words.map(|b| u8::from_str_radix(b, 16).unwrap()).collect();
            let mut code = bytes.clone();
            code.resize(6, 0);
            let len = decode(&code, pc).map(|i| i.len as usize);
            assert_eq!(len, Some(bytes.len()), "{pc:05X}H {bytes:02X?}");
            checked += 1;
        }
        eprintln!("{checked} instructions");
    }

    #[test]
    fn what_holds_an_interrupt_pending() {
        let holds = |code: &[u8]| {
            let mut window = [0; 6];
            window[..code.len()].copy_from_slice(code);
            insn(&window, 0).holds
        };
        assert!(holds(&[0x71, 0x7A, 0xFA]), "ei");
        assert!(holds(&[0x71, 0x7B, 0xFA]), "di");
        assert!(holds(&[0xCE, 0xFA, 0x06]), "mov psw, #6");
        assert!(holds(&[0x61, 0xCD]), "pop psw");
        assert!(holds(&[0x61, 0xF8]), "sknz");
        assert!(holds(&[0xCE, 0xE4, 0x00]), "mov MK0L, #0");
        assert!(holds(&[0x9F, 0xE6, 0xFF]), "mov !0xfffe6, a");
        assert!(!holds(&[0x8E, 0xFA]), "mov a, psw only reads it");
        assert!(!holds(&[0x9E, 0x02]), "mov P2, a");
        assert!(!holds(&[0xB8, 0x02]), "movw [sp+2], ax");
    }
}
