//! The RL78 on-chip-debug wire protocol, as a codec with no I/O.
//!
//! The whole protocol can be written as
//!
//! ```text
//! (session state, operation, arguments) -> request bytes
//! (session state, operation, response)  -> new session state + result
//! ```
//!
//! so this module holds no transport at all, and is tested with nothing attached. The tests here
//! take one case per operation; the rl78_debug_re repository also holds this codec to every
//! distinct request/response pair captured between a host and an RL78/G15.
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
    //! One case per operation, with the bytes the RL78/G15 actually exchanges. Section numbers
    //! are to `g15_ocd_protocol_notes.md` in the rl78_debug_re repository, which also keeps the
    //! full capture corpus and a runner that holds this codec to it.
    use super::*;

    fn ocd(locked: bool) -> State {
        State {
            phase: Phase::Ocd,
            locked,
            ..State::default()
        }
    }

    /// Encode, check the request, apply the reply, and return the decoded reply's sync and
    /// payload.
    fn exchange(
        st: &mut State,
        op: Op,
        args: &Args,
        request: &[u8],
        reply: &[u8],
    ) -> (Option<Sync>, Vec<u8>) {
        assert_eq!(st.encode(op, args).unwrap(), request, "{}", op.name());
        let shape = st.response_shape(op, args).unwrap();
        assert!(
            (shape.min..=shape.max).contains(&reply.len()),
            "{}",
            op.name()
        );
        let r = st.apply_response(op, args, reply).unwrap();
        (r.sync, r.payload.to_vec())
    }

    #[test]
    fn enter_ocd_from_the_boot_rom() {
        // CAH is the mode byte that selects the debugger. The five bytes are B, C, H and L at
        // entry, then the 00H prompt (§16.2): zeros here only because those registers are zero.
        let mut st = State::new();
        let (sync, _) = exchange(
            &mut st,
            Op::PbEnterOcd,
            &Args::default(),
            &[0xCA],
            &[1, 2, 3, 4, 0],
        );
        assert_eq!(
            sync,
            Some(Sync {
                b: 1,
                c: 2,
                h: 3,
                l: 4
            })
        );
        assert_eq!(st.phase, Phase::Ocd);
        assert!(st.locked);
    }

    #[test]
    fn unlock() {
        let mut st = ocd(true);
        exchange(
            &mut st,
            Op::UnlockChallenge,
            &Args::default(),
            &[0x55],
            &[0xF1],
        );
        let id = [0u8; SECURITY_ID_LEN];
        let a = Args {
            data: &id,
            ..Args::default()
        };
        exchange(&mut st, Op::UnlockSecurityId, &a, &id, &[0xF2]);
        assert!(!st.locked);

        // F3H is a rejection, not a protocol error, and leaves the session locked.
        let mut st = ocd(true);
        assert_eq!(
            st.apply_response(Op::UnlockSecurityId, &a, &[0xF3]),
            Err(CodecError::Rejected)
        );
        assert!(st.locked);
        // A challenge answered with anything but F1H is out of step.
        assert!(
            ocd(true)
                .apply_response(Op::UnlockChallenge, &a, &[0x00])
                .is_err()
        );
    }

    #[test]
    fn memory_is_addressed_in_the_f_segment() {
        // 56H takes a 16-bit address meaning F0000H + x [arch:p29]: FFFA4H goes out as A4 FF.
        let mut st = ocd(false);
        let a = Args {
            addr: 0xF_FFA4,
            len: 1,
            ..Args::default()
        };
        exchange(
            &mut st,
            Op::SetAddrLen,
            &a,
            &[0x56, 0xA4, 0xFF, 0x01],
            &[0x00],
        );
        assert_eq!(st.addr, Some((0xF_FFA4, 1)));
        let (_, data) = exchange(&mut st, Op::Read, &Args::default(), &[0x57], &[0x20]);
        assert_eq!(data, [0x20]);

        // 256 bytes encode as 0.
        let a = Args {
            addr: 0xF_FB00,
            len: 256,
            ..Args::default()
        };
        assert_eq!(
            st.encode(Op::SetAddrLen, &a).unwrap(),
            [0x56, 0x00, 0xFB, 0x00]
        );

        // Nothing below F0000H: that is what a routine staged in RAM is for.
        let low = Args {
            addr: 0x0_0100,
            len: 4,
            ..Args::default()
        };
        assert_eq!(
            st.encode(Op::SetAddrLen, &low),
            Err(CodecError::Argument("set_addr_len"))
        );
        // A locked session cannot touch memory at all.
        assert_eq!(
            ocd(true).encode(Op::SetAddrLen, &a),
            Err(CodecError::Locked("set_addr_len"))
        );
    }

    #[test]
    fn write_needs_the_length_it_was_given() {
        let mut st = ocd(false);
        // Read and write carry no address; they need a 56H first.
        assert_eq!(
            st.encode(Op::Read, &Args::default()),
            Err(CodecError::State("read"))
        );
        let a = Args {
            addr: 0xF_0085,
            len: 1,
            ..Args::default()
        };
        exchange(
            &mut st,
            Op::SetAddrLen,
            &a,
            &[0x56, 0x85, 0x00, 0x01],
            &[0x00],
        );
        let w = Args {
            data: &[0x01],
            ..Args::default()
        };
        exchange(&mut st, Op::Write, &w, &[0x58, 0x01], &[0x00]);
        let w2 = Args {
            data: &[0x01, 0x02],
            ..Args::default()
        };
        assert_eq!(
            st.encode(Op::Write, &w2),
            Err(CodecError::Argument("write"))
        );
    }

    #[test]
    fn call_gate() {
        // A bare 5BH is CALL !!0FFED0H; the reply is only the command loop's prompt (§12.3, §46).
        let mut st = ocd(false);
        exchange(&mut st, Op::CallKernel, &Args::default(), &[0x5B], &[0x00]);
        assert!(
            st.apply_response(Op::CallKernel, &Args::default(), &[0x01])
                .is_err()
        );
    }

    #[test]
    fn execute_runs_or_traps() {
        // 5CH loads B, C, H and L and returns from the interrupt (§18, §23).
        let regs = Sync {
            b: 0x00,
            c: 0x00,
            h: 0x08,
            l: 0x38,
        };
        let a = Args {
            regs,
            ..Args::default()
        };

        // A free run is answered by the echo of L alone (§23.1's resume: 5C 00 00 08 38 -> 38).
        let mut st = ocd(false);
        let (sync, _) = exchange(
            &mut st,
            Op::Execute,
            &a,
            &[0x5C, 0x00, 0x00, 0x08, 0x38],
            &[0x38],
        );
        assert_eq!(sync, None);
        assert!(st.locked, "leaving the monitor locks the session");

        // An armed single step traps at once: the echo, then the re-entry sync.
        let mut st = ocd(false);
        let (sync, _) = exchange(
            &mut st,
            Op::Execute,
            &a,
            &[0x5C, 0, 0, 8, 0x38],
            &[0x38, 9, 8, 7, 6, 0],
        );
        assert_eq!(
            sync,
            Some(Sync {
                b: 9,
                c: 8,
                h: 7,
                l: 6
            })
        );
    }

    #[test]
    fn halt() {
        // A lone 00H halts a running target (§23.2, §28). Legal while locked: it doubles as the
        // poke that wakes a monitor that has just re-entered.
        let mut st = ocd(true);
        let (sync, _) = exchange(
            &mut st,
            Op::Halt,
            &Args::default(),
            &[0x00],
            &[0, 3, 0, 0, 0],
        );
        assert_eq!(
            sync,
            Some(Sync {
                b: 0,
                c: 3,
                h: 0,
                l: 0
            })
        );
        assert!(
            st.apply_response(Op::Halt, &Args::default(), &[0, 3, 0, 0, 1])
                .is_err()
        );
    }

    #[test]
    fn the_same_byte_in_two_protocols() {
        // 00H is Protocol B's mode entry in one phase and the debugger's halt in the other.
        let a = Args::default();
        assert_eq!(State::new().encode(Op::PbModeEntry, &a).unwrap(), [0x00]);
        assert_eq!(ocd(true).encode(Op::Halt, &a).unwrap(), [0x00]);
        assert!(matches!(
            State::new().encode(Op::UnlockChallenge, &a),
            Err(CodecError::State(_))
        ));
        assert!(matches!(
            ocd(true).encode(Op::PbCodeflashCrc, &a),
            Err(CodecError::State(_))
        ));
    }

    #[test]
    fn protocol_b_write_after_erase() {
        // [proto_b]: 60H answers ACK and the flash size in 256-byte units, minus one (1FH: 8 KB),
        // then four-byte groups follow with no opcode of their own.
        let mut st = State::new();
        exchange(&mut st, Op::PbModeEntry, &Args::default(), &[0x00], &[0x36]);
        let group = [0xEA, 0x00, 0x00, 0xFB];
        let g = Args {
            data: &group,
            ..Args::default()
        };
        assert!(matches!(
            st.encode(Op::PbDataGroup, &g),
            Err(CodecError::State(_))
        ));
        exchange(
            &mut st,
            Op::PbWriteAfterErase,
            &Args::default(),
            &[0x60],
            &[0x06, 0x1F],
        );
        assert!(st.streaming);
        exchange(&mut st, Op::PbDataGroup, &g, &group, &[0x06]);
        // The last group also carries the write-complete.
        exchange(&mut st, Op::PbDataGroup, &g, &group, &[0x06, 0x06]);
    }

    #[test]
    fn vendor_kernel_reads() {
        // Renesas's RAM kernel takes a true ES:addr16 and answers data then a 00H prompt (§11).
        // Nothing drives it any more; the encoding is kept because the captures are full of it.
        let mut st = ocd(false);
        let a = Args {
            addr: 0x0_00C4,
            len: 10,
            ..Args::default()
        };
        let mut reply = vec![0x11; 10];
        reply.push(0x00);
        let (_, data) = exchange(
            &mut st,
            Op::KernelReadBytes,
            &a,
            &[0x5B, 0x01, 0xC4, 0x00, 0x00, 0x0A],
            &reply,
        );
        assert_eq!(data, [0x11; 10]);
    }

    #[test]
    fn pseudo_rrm_commits_are_gated() {
        // The nibble counter decides which commit is admissible (§30).
        let a = Args::default();
        let mut st = ocd(true);
        for n in [0xF, 0xF, 0xB, 0x0] {
            let a = Args {
                nibble: n,
                ..Args::default()
            };
            exchange(&mut st, Op::RrmAddrNibble, &a, &[0xA0 | n], &[0x00]);
        }
        assert_eq!(st.rrm_c, 4);
        let (_, data) = exchange(&mut st, Op::RrmReadByte, &a, &[0xD0], &[0x42]);
        assert_eq!(data, [0x42]);
        assert_eq!(st.rrm_c, 0);
        assert!(st.encode(Op::RrmReadByte, &a).is_err());

        // The word write's low nibble is the fourth data nibble, not a sub-command.
        st.rrm_c = 7;
        let w = Args {
            nibble: 0xF,
            ..Args::default()
        };
        exchange(&mut st, Op::RrmWriteWord, &w, &[0x9F], &[0xDA]);
    }
}
