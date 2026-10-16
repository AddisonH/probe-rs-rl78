//! The RL78 on-chip-debug wire protocol, as a codec with no I/O.
//!
//! The whole protocol can be written as
//!
//! ```text
//! (session state, operation, arguments) -> request bytes
//! (session state, operation, response)  -> new session state + result
//! ```
//!
//! so this module holds no transport at all. That is what lets it be checked against the
//! conformance corpus (every distinct request/response pair seen between a host and an RL78/G15)
//! with nothing attached; see the tests at the bottom.
//!
//! **Two protocols share this codec.** Protocol B is Renesas's documented flash protocol for the
//! G10/G15/G1M/G1N. The OCD protocol is undocumented and was recovered from the device ROM. The
//! same byte means different things in each (`00H` is Protocol B's mode entry and the OCD
//! protocol's halt), so every operation is interpreted against [`State::phase`]. Never dispatch
//! on an opcode alone.
//!
//! **Addresses are 20-bit.** A 16-bit address in a `56H` command, as in an `!addr16` operand,
//! means `F0000H + x`. Branches do not follow that rule. Getting it wrong silently relocates
//! everything by `F0000H`, so the conversion happens in exactly one place: [`Op::SetAddrLen`].

/// A 16-bit data address `x` denotes `ADDR16_BASE + x`.
pub const ADDR16_BASE: u32 = 0xF_0000;

/// The longest request: a 256-byte `58H` write plus its opcode.
pub const MAX_REQUEST: usize = 257;

/// Bytes in the re-entry sync the monitor sends on every entry: B, C, H, L, then a `00H` prompt.
pub const SYNC_LEN: usize = 5;

/// Length of the security ID that unlocks a session.
pub const SECURITY_ID_LEN: usize = 10;

/// Which of the two protocols the link is speaking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Protocol B flash programming; entered by a hardware reset with TOOL0 low.
    ProtoB,
    /// On-chip debug; entered from [`Phase::ProtoB`] by the `CAH` mode byte.
    Ocd,
}

/// One protocol operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    /// `00H`: Protocol B mode entry, dedicated UART.
    PbModeEntry,
    /// `3AH`: Protocol B mode entry, single-line UART.
    PbModeEntrySingleLine,
    /// `CAH`: the mode byte that routes to the OCD bootstrap instead of the flash loader.
    PbEnterOcd,
    /// `53H`: code flash CRC.
    PbCodeflashCrc,
    /// `54H`: data flash CRC.
    PbDataflashCrc,
    /// `60H`: erase code flash, then stream the image.
    PbWriteAfterErase,
    /// `63H`: erase data flash, then stream the image.
    PbWriteAfterEraseDf,
    /// No opcode: four raw image bytes while streaming.
    PbDataGroup,
    /// `06H`: host acknowledgement.
    PbAck,
    /// `55H`: unlock challenge, answered with `F1H`.
    UnlockChallenge,
    /// No opcode: the ten security ID bytes, answered with `F2H` (accepted) or `F3H`.
    UnlockSecurityId,
    /// `56H lo hi len`: set the address and length for a read or write. F-segment only.
    SetAddrLen,
    /// `57H`: read `len` bytes from the address set by [`Op::SetAddrLen`].
    Read,
    /// `58H data…`: write `len` bytes to the address set by [`Op::SetAddrLen`].
    Write,
    /// `5BH`: `CALL !!0FFED0H`. With a host routine staged there, this runs it.
    CallKernel,
    /// `5BH 01H`: Renesas's RAM kernel, byte read. Observed; nothing here drives it.
    KernelReadBytes,
    /// `5BH 03H`: Renesas's RAM kernel, word read. Observed; nothing here drives it.
    KernelReadWords,
    /// `5BH 05H`: Renesas's RAM kernel, flash sequencer. Observed; nothing here drives it.
    KernelFlashOp,
    /// `5CH B C H L`: load B, C, H and L, then `RETI` out of the monitor.
    Execute,
    /// `00H`: halt a running target, or poke a monitor that has just re-entered.
    Halt,
    /// `A0H`–`AFH`: pseudo-RRM/DMM address nibble.
    RrmAddrNibble,
    /// `B0H`–`BFH`: pseudo-RRM/DMM data nibble.
    RrmDataNibble,
    /// `D0H`: pseudo-RRM read byte.
    RrmReadByte,
    /// `D1H`: pseudo-RRM read word.
    RrmReadWord,
    /// `D2H`: pseudo-DMM write byte.
    RrmWriteByte,
    /// `90H`–`9FH`: pseudo-DMM write word; the low nibble is the fourth data nibble.
    RrmWriteWord,
    /// `D3H`: sample the PC of the running program.
    RrmReadPc,
}

impl Op {
    /// The operation's name, as the conformance corpus spells it.
    pub fn name(self) -> &'static str {
        self.desc().name
    }

    fn desc(self) -> OpDesc {
        let (name, pb, ocd, unlocked, opcode, flat) = match self {
            Op::PbModeEntry => ("pb_mode_entry", true, false, false, 0x00, true),
            Op::PbModeEntrySingleLine => {
                ("pb_mode_entry_single_line", true, false, false, 0x3A, true)
            }
            Op::PbEnterOcd => ("pb_enter_ocd", true, true, false, 0xCA, true),
            Op::PbCodeflashCrc => ("pb_codeflash_crc", true, false, false, 0x53, true),
            Op::PbDataflashCrc => ("pb_dataflash_crc", true, false, false, 0x54, true),
            Op::PbWriteAfterErase => ("pb_write_after_erase", true, false, false, 0x60, true),
            Op::PbWriteAfterEraseDf => ("pb_write_after_erase_df", true, false, false, 0x63, true),
            Op::PbDataGroup => ("pb_data_group", true, false, false, 0x00, false),
            Op::PbAck => ("pb_ack", true, false, false, 0x06, true),
            Op::UnlockChallenge => ("unlock_challenge", false, true, false, 0x55, true),
            Op::UnlockSecurityId => ("unlock_security_id", false, true, false, 0x00, false),
            Op::SetAddrLen => ("set_addr_len", false, true, true, 0x56, false),
            Op::Read => ("read", false, true, true, 0x57, false),
            Op::Write => ("write", false, true, true, 0x58, false),
            Op::CallKernel => ("call_kernel", false, true, true, 0x5B, true),
            Op::KernelReadBytes => ("kernel_read_bytes", false, true, true, 0x5B, false),
            Op::KernelReadWords => ("kernel_read_words", false, true, true, 0x5B, false),
            Op::KernelFlashOp => ("kernel_flash_op", false, true, true, 0x5B, false),
            Op::Execute => ("execute", false, true, true, 0x5C, false),
            Op::Halt => ("halt", false, true, false, 0x00, true),
            Op::RrmAddrNibble => ("rrm_addr_nibble", false, true, false, 0xA0, false),
            Op::RrmDataNibble => ("rrm_data_nibble", false, true, false, 0xB0, false),
            Op::RrmReadByte => ("rrm_read_byte", false, true, false, 0xD0, false),
            Op::RrmReadWord => ("rrm_read_word", false, true, false, 0xD1, false),
            Op::RrmWriteByte => ("rrm_write_byte", false, true, false, 0xD2, false),
            Op::RrmWriteWord => ("rrm_write_word", false, true, false, 0x90, false),
            Op::RrmReadPc => ("rrm_read_pc", false, true, false, 0xD3, false),
        };
        OpDesc {
            name,
            in_proto_b: pb,
            in_ocd: ocd,
            requires_unlocked: unlocked,
            opcode,
            flat,
        }
    }
}

/// Preconditions come from the corpus, not from intuition: across all its observations every OCD
/// memory, kernel and run-control op appears only with the session unlocked, and halt appears
/// only with it locked (it doubles as the post-execute re-entry poke).
struct OpDesc {
    name: &'static str,
    in_proto_b: bool,
    in_ocd: bool,
    requires_unlocked: bool,
    opcode: u8,
    /// The request is exactly one byte: the opcode.
    flat: bool,
}

/// Why the codec refused an operation or a reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CodecError {
    /// An argument is out of range.
    #[error("argument out of range for {0}")]
    Argument(&'static str),
    /// The operation is not legal in the current session state.
    #[error("{0} is illegal in the current session state")]
    State(&'static str),
    /// The target replied with something the protocol does not allow.
    #[error("inadmissible reply to {0}")]
    Protocol(&'static str),
    /// The session is locked; unlock it first.
    #[error("{0} needs an unlocked session")]
    Locked(&'static str),
    /// The target rejected the security ID (`F3H`).
    #[error("security ID rejected")]
    Rejected,
}

/// Session state a conforming implementation must track.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct State {
    /// Which protocol is being spoken.
    pub phase: Phase,
    /// Every OCD session starts locked, and every monitor entry locks it again.
    pub locked: bool,
    /// The 20-bit address and length set by the last [`Op::SetAddrLen`]. [`Op::Read`] and
    /// [`Op::Write`] carry neither, so they are meaningless without it.
    pub addr: Option<(u32, u16)>,
    /// Protocol B is mid-image: four-byte packets are data.
    pub streaming: bool,
    /// The pseudo-RRM/DMM nibble counter, 0..=7. It lives on the target and is mirrored here to
    /// know when a commit is admissible.
    pub rrm_c: u8,
}

impl Default for State {
    fn default() -> Self {
        Self {
            phase: Phase::ProtoB,
            locked: true,
            addr: None,
            streaming: false,
            rrm_c: 0,
        }
    }
}

/// Arguments to [`State::encode`]. Only the fields an operation uses are read.
#[derive(Debug, Clone, Copy, Default)]
pub struct Args<'a> {
    /// 20-bit address.
    pub addr: u32,
    /// Length, 1..=256.
    pub len: u16,
    /// Write data, the security ID, or a Protocol B data group.
    pub data: &'a [u8],
    /// [`Op::Execute`]: loaded into B, C, H and L before the `RETI`.
    pub regs: Sync,
    /// Pseudo-RRM/DMM: the low nibble of the opcode.
    pub nibble: u8,
}

/// The B, C, H and L registers. The monitor sends them on every entry, because it is about to
/// overwrite them, and [`Op::Execute`] loads them on the way out.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Sync {
    /// B
    pub b: u8,
    /// C
    pub c: u8,
    /// H
    pub h: u8,
    /// L
    pub l: u8,
}

impl Sync {
    /// Decode the first four bytes of a re-entry sync.
    pub fn from_bytes(b: &[u8]) -> Self {
        Self {
            b: b[0],
            c: b[1],
            h: b[2],
            l: b[3],
        }
    }
}

/// How many reply bytes to expect.
///
/// The link is half-duplex with no framing, so some replies are ambiguous in length and the caller
/// must read `min` and then decide. [`Op::Execute`] is the one that matters: one byte means the
/// target is now running, six that it trapped at once, which is what an armed single step does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Shape {
    /// Fewest bytes the reply may have.
    pub min: usize,
    /// Most bytes the reply may have.
    pub max: usize,
}

impl Shape {
    const fn exactly(n: usize) -> Self {
        Self { min: n, max: n }
    }
}

/// A decoded reply. Only the fields relevant to the operation are set.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Reply<'a> {
    /// [`Op::Halt`], [`Op::PbEnterOcd`] and a trapping [`Op::Execute`]: the re-entry sync.
    pub sync: Option<Sync>,
    /// [`Op::UnlockSecurityId`]: the session is now unlocked.
    pub unlocked: bool,
    /// Read data, borrowed from the response buffer.
    pub payload: &'a [u8],
}

fn check_len(len: u16, op: Op) -> Result<u8, CodecError> {
    match len {
        // 1..=256 on the wire; 256 is encoded as 0.
        1..=256 => Ok(len as u8),
        _ => Err(CodecError::Argument(op.name())),
    }
}

impl State {
    /// A fresh link: Protocol B, locked.
    pub fn new() -> Self {
        Self::default()
    }

    fn check_preconditions(&self, op: Op) -> Result<OpDesc, CodecError> {
        let d = op.desc();
        let phase_ok = match self.phase {
            Phase::ProtoB => d.in_proto_b,
            Phase::Ocd => d.in_ocd,
        };
        if !phase_ok {
            return Err(CodecError::State(d.name));
        }
        if d.requires_unlocked && self.locked {
            return Err(CodecError::Locked(d.name));
        }
        Ok(d)
    }

    /// Encode one request. Does not change the state; that happens in [`State::apply_response`]
    /// once the target has confirmed it.
    pub fn encode(&self, op: Op, args: &Args) -> Result<Vec<u8>, CodecError> {
        let d = self.check_preconditions(op)?;
        if d.flat {
            return Ok(vec![d.opcode]);
        }

        let name = d.name;
        match op {
            Op::PbDataGroup => {
                // No opcode. Any four-byte packet while streaming is data, which is why
                // `streaming` must be tracked rather than sniffed from the first byte.
                if !self.streaming {
                    return Err(CodecError::State(name));
                }
                if args.data.len() != 4 {
                    return Err(CodecError::Argument(name));
                }
                Ok(args.data.to_vec())
            }
            Op::UnlockSecurityId => {
                // The ten bytes follow the F1H challenge directly. The ID lives at 000C4H-000CDH;
                // a blank part reads as ten 00s.
                if args.data.len() != SECURITY_ID_LEN {
                    return Err(CodecError::Argument(name));
                }
                Ok(args.data.to_vec())
            }
            Op::SetAddrLen => {
                // 56H reaches F0000H-FFFFFH only.
                if !(ADDR16_BASE..=0xF_FFFF).contains(&args.addr) {
                    return Err(CodecError::Argument(name));
                }
                let a = args.addr - ADDR16_BASE;
                Ok(vec![
                    d.opcode,
                    a as u8,
                    (a >> 8) as u8,
                    check_len(args.len, op)?,
                ])
            }
            Op::Read => {
                if self.addr.is_none() {
                    return Err(CodecError::State(name));
                }
                Ok(vec![d.opcode])
            }
            Op::Write => {
                let Some((_, len)) = self.addr else {
                    return Err(CodecError::State(name));
                };
                if args.data.len() != usize::from(len) {
                    return Err(CodecError::Argument(name));
                }
                let mut out = Vec::with_capacity(1 + args.data.len());
                out.push(d.opcode);
                out.extend_from_slice(args.data);
                Ok(out)
            }
            Op::KernelReadBytes | Op::KernelReadWords => {
                // The vendor kernel takes a real 16-bit offset within segment ES, not the
                // F-segment convention of 56H.
                if args.addr > 0xF_FFFF {
                    return Err(CodecError::Argument(name));
                }
                let inner = if op == Op::KernelReadBytes {
                    0x01
                } else {
                    0x03
                };
                Ok(vec![
                    d.opcode,
                    inner,
                    args.addr as u8,
                    (args.addr >> 8) as u8,
                    (args.addr >> 16) as u8,
                    check_len(args.len, op)?,
                ])
            }
            // Parameters are staged in RAM beforehand, so every observation is the same six bytes.
            Op::KernelFlashOp => Ok(vec![d.opcode, 0x05, 0, 0, 0, 0]),
            Op::Execute => {
                // Not "run to address": the resume address was chosen by writing the interrupt
                // frame at SP beforehand.
                let r = args.regs;
                Ok(vec![d.opcode, r.b, r.c, r.h, r.l])
            }
            Op::RrmAddrNibble | Op::RrmDataNibble => {
                if args.nibble > 0x0F {
                    return Err(CodecError::Argument(name));
                }
                Ok(vec![d.opcode | args.nibble])
            }
            Op::RrmReadByte | Op::RrmReadWord | Op::RrmReadPc | Op::RrmWriteByte => {
                let required = if op == Op::RrmWriteByte { 6 } else { 4 };
                if self.rrm_c != required {
                    return Err(CodecError::State(name));
                }
                Ok(vec![d.opcode])
            }
            Op::RrmWriteWord => {
                if self.rrm_c != 7 {
                    return Err(CodecError::State(name));
                }
                // The low nibble is the fourth data nibble, not a sub-command: this op both
                // supplies it and commits.
                if args.nibble > 0x0F {
                    return Err(CodecError::Argument(name));
                }
                Ok(vec![d.opcode | args.nibble])
            }
            _ => unreachable!("{name} is a flat op"),
        }
    }

    /// How many bytes the reply to that same request will occupy.
    pub fn response_shape(&self, op: Op, args: &Args) -> Result<Shape, CodecError> {
        let d = self.check_preconditions(op)?;
        Ok(match op {
            Op::Read => match self.addr {
                Some((_, len)) => Shape::exactly(usize::from(len)),
                None => return Err(CodecError::State(d.name)),
            },
            // Data bytes, then the 00H prompt.
            Op::KernelReadBytes | Op::KernelReadWords => Shape::exactly(usize::from(args.len) + 1),
            Op::KernelFlashOp => Shape::exactly(2),
            // One byte, the echo of L: the target is running. Six: the echo plus the re-entry
            // sync, because it trapped at once (an armed single step).
            Op::Execute => Shape { min: 1, max: 6 },
            Op::Halt | Op::PbEnterOcd => Shape::exactly(SYNC_LEN),
            Op::PbCodeflashCrc
            | Op::PbDataflashCrc
            | Op::PbWriteAfterErase
            | Op::PbWriteAfterEraseDf => Shape::exactly(2),
            // The last group of an image is answered by its own ACK plus write-complete.
            Op::PbDataGroup => Shape { min: 1, max: 2 },
            // After a CRC command this fetches the result: ACK plus a 16-bit value.
            Op::PbAck => Shape { min: 1, max: 3 },
            // Everything else answers with one status or prompt byte.
            _ => Shape::exactly(1),
        })
    }

    /// Check the reply, update the state, and decode any payload.
    pub fn apply_response<'r>(
        &mut self,
        op: Op,
        args: &Args,
        resp: &'r [u8],
    ) -> Result<Reply<'r>, CodecError> {
        let shape = self.response_shape(op, args)?;
        let name = op.name();
        if resp.len() < shape.min || resp.len() > shape.max {
            return Err(CodecError::Protocol(name));
        }
        let mut reply = Reply::default();

        match op {
            Op::PbEnterOcd => {
                // Not a constant: the ROM entry sequence transmits B, C, H and L and then the
                // prompt. They read as zero only because those registers are zero at entry.
                reply.sync = Some(Sync::from_bytes(resp));
                *self = State {
                    phase: Phase::Ocd,
                    ..State::default()
                };
            }
            Op::UnlockChallenge => {
                if resp[0] != 0xF1 {
                    return Err(CodecError::Protocol(name));
                }
            }
            Op::UnlockSecurityId => match resp[0] {
                0xF2 => {
                    self.locked = false;
                    reply.unlocked = true;
                }
                0xF3 => return Err(CodecError::Rejected),
                _ => return Err(CodecError::Protocol(name)),
            },
            Op::SetAddrLen => {
                if resp[0] != 0x00 {
                    return Err(CodecError::Protocol(name));
                }
                self.addr = Some((args.addr, args.len));
            }
            Op::Read => reply.payload = resp,
            Op::KernelReadBytes | Op::KernelReadWords => {
                if resp[resp.len() - 1] != 0x00 {
                    return Err(CodecError::Protocol(name));
                }
                reply.payload = &resp[..resp.len() - 1];
            }
            Op::Write | Op::CallKernel => {
                if resp[0] != 0x00 {
                    return Err(CodecError::Protocol(name));
                }
            }
            Op::Execute => {
                // Leaving the monitor locks the session: the entry sequence runs again on the way
                // back in.
                self.locked = true;
                self.rrm_c = 0;
                if resp.len() == 6 {
                    reply.sync = Some(Sync::from_bytes(&resp[1..]));
                }
            }
            Op::Halt => {
                // CAUTION: a sync nobody asked for is not the answer to a halt. A watchdog reset
                // produces a byte-identical one (notes section 28.4); the PC tells them apart.
                if resp[4] != 0x00 {
                    return Err(CodecError::Protocol(name));
                }
                reply.sync = Some(Sync::from_bytes(resp));
                self.locked = true;
            }
            Op::PbWriteAfterErase | Op::PbWriteAfterEraseDf => self.streaming = true,
            Op::RrmAddrNibble | Op::RrmDataNibble => self.rrm_c = (self.rrm_c + 1).min(7),
            Op::RrmReadByte | Op::RrmReadWord | Op::RrmReadPc => {
                reply.payload = &resp[..1];
                self.rrm_c = 0;
            }
            Op::RrmWriteByte | Op::RrmWriteWord => {
                let ack = if op == Op::RrmWriteByte { 0xD9 } else { 0xDA };
                if resp[0] != ack {
                    return Err(CodecError::Protocol(name));
                }
                self.rrm_c = 0;
            }
            _ => {}
        }
        Ok(reply)
    }
}

#[cfg(test)]
mod tests {
    //! The codec against the conformance corpus: every distinct request/response pair observed
    //! between a host and an RL78/G15, 1,179 of them from 24,760 transactions. For each, rebuild
    //! the session state, require the encoder to emit exactly the observed request, and require
    //! the observed reply to be accepted. A failure means the codec and the wire disagree; the
    //! wire wins.
    //!
    //! The corpus lives in the rl78_debug_re repository (`conformance/vectors.json`), not here,
    //! because some of its `write` vectors carry Renesas's RAM kernel. Point `RL78_VECTORS` at it,
    //! or check probe-rs out inside that repository.
    use super::*;
    use std::path::PathBuf;

    fn vectors_path() -> Option<PathBuf> {
        let p = std::env::var_os("RL78_VECTORS")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance/vectors.json")
            });
        p.exists().then_some(p)
    }

    fn hex(s: &str) -> Vec<u8> {
        s.split_whitespace()
            .map(|b| u8::from_str_radix(b, 16).unwrap())
            .collect()
    }

    fn addr(v: &serde_json::Value) -> Option<u32> {
        let s = v.as_str()?;
        u32::from_str_radix(s.trim_end_matches(['H', 'h']), 16).ok()
    }

    fn op_for(semantic: &str) -> Option<Op> {
        Some(match semantic {
            "pb_mode_entry" => Op::PbModeEntry,
            "pb_enter_ocd" => Op::PbEnterOcd,
            "pb_codeflash_crc" => Op::PbCodeflashCrc,
            "pb_dataflash_crc" => Op::PbDataflashCrc,
            "pb_write_after_erase" => Op::PbWriteAfterErase,
            "pb_write_after_erase_df" => Op::PbWriteAfterEraseDf,
            "pb_data_group" => Op::PbDataGroup,
            "pb_ack" => Op::PbAck,
            "unlock_challenge" => Op::UnlockChallenge,
            "unlock_security_id" => Op::UnlockSecurityId,
            "set_addr_len" => Op::SetAddrLen,
            "read" => Op::Read,
            "write" => Op::Write,
            "call_kernel" => Op::CallKernel,
            "kernel_read_bytes" => Op::KernelReadBytes,
            "kernel_read_words" => Op::KernelReadWords,
            "kernel_flash_op" => Op::KernelFlashOp,
            "execute" => Op::Execute,
            // The corpus calls 00H in the OCD phase "halt_or_poke", because it is both.
            "halt_or_poke" => Op::Halt,
            _ => return None,
        })
    }

    /// Recover the encoder's arguments from the observed request, as tools/mkvectors_c.py does.
    fn args_for(op: Op, req: &[u8]) -> Args<'_> {
        let mut a = Args::default();
        match op {
            Op::SetAddrLen => {
                a.addr = ADDR16_BASE + (u32::from(req[1]) | u32::from(req[2]) << 8);
                a.len = if req[3] == 0 { 256 } else { u16::from(req[3]) };
            }
            Op::Write => {
                a.data = &req[1..];
                a.len = (req.len() - 1) as u16;
            }
            Op::KernelReadBytes | Op::KernelReadWords | Op::KernelFlashOp => {
                a.addr = u32::from(req[2]) | u32::from(req[3]) << 8 | u32::from(req[4]) << 16;
                a.len = if req[5] == 0 { 256 } else { u16::from(req[5]) };
            }
            Op::Execute => a.regs = Sync::from_bytes(&req[1..]),
            Op::UnlockSecurityId | Op::PbDataGroup => a.data = req,
            _ => {}
        }
        a
    }

    #[test]
    fn conformance_vectors() {
        let Some(path) = vectors_path() else {
            eprintln!("skipping: conformance/vectors.json not found; set RL78_VECTORS");
            return;
        };
        let doc: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let vectors = doc["vectors"].as_array().unwrap();

        let (mut pass, mut observations) = (0, 0u64);
        let mut failures = vec![];
        for v in vectors {
            let semantic = v["semantic"].as_str().unwrap();
            let Some(op) = op_for(semantic) else {
                failures.push(format!("{semantic}: no op"));
                continue;
            };
            let st = &v["state"];
            let mut state = State {
                phase: if st["phase"] == "ocd" {
                    Phase::Ocd
                } else {
                    Phase::ProtoB
                },
                locked: st["locked"].as_bool().unwrap_or(false),
                addr: addr(&st["addr"]).map(|a| (a, st["len"].as_u64().unwrap() as u16)),
                // Not recorded in the corpus; implied for the only op that needs it.
                streaming: op == Op::PbDataGroup,
                rrm_c: 0,
            };
            let req = hex(v["request"].as_str().unwrap());
            let rsp = hex(v["response"].as_str().unwrap());
            let args = args_for(op, &req);
            let evidence = v["evidence"].as_str().unwrap();

            let result = (|| {
                let enc = state.encode(op, &args).map_err(|e| e.to_string())?;
                if enc != req {
                    return Err(format!("encoded {enc:02x?}, wire has {req:02x?}"));
                }
                let shape = state.response_shape(op, &args).map_err(|e| e.to_string())?;
                if !(shape.min..=shape.max).contains(&rsp.len()) {
                    return Err(format!("reply of {} outside {shape:?}", rsp.len()));
                }
                state
                    .apply_response(op, &args, &rsp)
                    .map_err(|e| e.to_string())?;
                Ok(())
            })();
            match result {
                Ok(()) => {
                    pass += 1;
                    observations += v["count"].as_u64().unwrap();
                }
                Err(e) => failures.push(format!("{semantic} ({evidence}): {e}")),
            }
        }
        assert!(
            failures.is_empty(),
            "{} failures:\n{}",
            failures.len(),
            failures.join("\n")
        );
        assert_eq!(
            pass, 1179,
            "the corpus has changed size; update this count deliberately"
        );
        assert_eq!(observations, 24_760);
    }

    /// Properties the corpus cannot show, because a capture only contains things that happened.
    #[test]
    fn negative() {
        let ocd = State {
            phase: Phase::Ocd,
            ..State::default()
        };
        let a = Args {
            addr: 0xF_FFA4,
            len: 1,
            ..Args::default()
        };
        // A locked session cannot touch memory.
        assert_eq!(
            ocd.encode(Op::SetAddrLen, &a),
            Err(CodecError::Locked("set_addr_len"))
        );

        let open = State {
            locked: false,
            ..ocd.clone()
        };
        // 56H cannot address below F0000H.
        let low = Args {
            addr: 0x0_0100,
            ..a
        };
        assert_eq!(
            open.encode(Op::SetAddrLen, &low),
            Err(CodecError::Argument("set_addr_len"))
        );
        // 256 is 0 on the wire.
        let full = Args {
            addr: 0xF_0000,
            len: 256,
            ..a
        };
        assert_eq!(open.encode(Op::SetAddrLen, &full).unwrap()[3], 0);
        // F-segment conversion: FFFA4H goes out as A4 FF.
        assert_eq!(
            open.encode(Op::SetAddrLen, &a).unwrap(),
            [0x56, 0xA4, 0xFF, 1]
        );

        // An OCD op in the flash phase, and the reverse.
        assert!(matches!(
            State::new().encode(Op::UnlockChallenge, &a),
            Err(CodecError::State(_))
        ));
        assert!(matches!(
            ocd.encode(Op::PbCodeflashCrc, &a),
            Err(CodecError::State(_))
        ));

        // 00H is mode entry in one phase and halt in the other.
        assert_eq!(State::new().encode(Op::PbModeEntry, &a).unwrap(), [0x00]);
        assert_eq!(ocd.encode(Op::Halt, &a).unwrap(), [0x00]);

        // RRM commits are gated on the nibble counter.
        let mut rrm = ocd.clone();
        rrm.rrm_c = 3;
        assert!(rrm.encode(Op::RrmReadByte, &a).is_err());
        rrm.rrm_c = 4;
        assert_eq!(rrm.encode(Op::RrmReadByte, &a).unwrap(), [0xD0]);
        rrm.rrm_c = 7;
        let nib = Args { nibble: 0xF, ..a };
        assert_eq!(rrm.encode(Op::RrmWriteWord, &nib).unwrap(), [0x9F]);

        // F3H is a rejection, not a protocol error, and leaves the session locked.
        let mut s = ocd.clone();
        let id = [0u8; 10];
        let ida = Args {
            data: &id,
            ..Args::default()
        };
        assert_eq!(
            s.apply_response(Op::UnlockSecurityId, &ida, &[0xF3]),
            Err(CodecError::Rejected)
        );
        assert!(s.locked);
        assert!(
            s.apply_response(Op::UnlockSecurityId, &ida, &[0xF2])
                .unwrap()
                .unlocked
        );
        assert!(!s.locked);

        // Execute re-locks, and a six-byte reply is a trap with the sync after the echo.
        let r = s
            .apply_response(Op::Execute, &Args::default(), &[0x38, 1, 2, 3, 4, 0])
            .unwrap();
        assert_eq!(
            r.sync,
            Some(Sync {
                b: 1,
                c: 2,
                h: 3,
                l: 4
            })
        );
        assert!(s.locked);
    }
}
