//! What a probe has to provide to debug an RL78, and a driver for probes that are a plain UART.
//!
//! The RL78's on-chip debugger is a 512-byte mask ROM running on the target's own CPU, entered as
//! an interrupt. It offers very little: memory access in `F0000H`–`FFFFFH`, a call gate into RAM,
//! a return from the debug interrupt, and a halt. [`Rl78OcdInterface`] is that set, and nothing
//! more; the core driver composes everything else (code flash access, register files, resets)
//! out of it.
//!
//! A probe that is a byte pipe to the target's TOOL0 line, such as the FT232R on a Renesas Fast
//! Prototyping Board, implements the much smaller [`Rl78Uart`] and wraps it in [`UartOcd`], which
//! runs the [`protocol`](super::protocol) codec. A probe with its own firmware (the E2 Lite)
//! implements [`Rl78OcdInterface`] directly.

use std::{fmt, time::Duration, time::Instant};

use super::protocol::{self, Args, CodecError, Op, Phase, SECURITY_ID_LEN, SYNC_LEN, Sync};
use crate::probe::DebugProbeError;

/// An error from the RL78 debug link.
#[derive(Debug, thiserror::Error, docsplay::Display)]
pub enum Rl78Error {
    /// The target's reply broke the protocol: {0}
    Codec(#[from] CodecError),

    /// No complete reply to {op}: got {got} of {expected} bytes.
    Timeout {
        /// The operation that went unanswered.
        op: &'static str,
        /// Bytes received.
        got: usize,
        /// Bytes expected.
        expected: usize,
    },

    /// The target did not enter on-chip-debug mode. Check the wiring, and that the part's
    /// on-chip debug option byte (000C3H) enables debugging.
    NoMonitor,

    /// The security ID was rejected. Set the part's ID with PROBE_RS_RL78_SECURITY_ID.
    SecurityIdRejected,

    /// The core is running; {0} needs it halted.
    NotHalted(&'static str),

    /// The target did not answer the halt. If it was attached under reset, its watchdog is
    /// running whatever the option byte says (WDTE reads 9AH), so a program that does not feed it
    /// is reset, and with no debug stub in flash the part comes back up with the debugger
    /// disarmed. Attach again.
    HaltUnanswered,

    /// {0} is not supported on RL78 yet.
    Unsupported(&'static str),

    /// The probe failed.
    Probe(#[from] DebugProbeError),

    /// {0}
    Other(String),
}

/// The primitives of the RL78 on-chip debugger.
///
/// Addresses are 20-bit. [`read_mem`](Self::read_mem) and [`write_mem`](Self::write_mem) reach
/// `F0000H`–`FFFFFH` only: the monitor addresses memory through `[HL]` with 16-bit addressing.
pub trait Rl78OcdInterface: Send + fmt::Debug {
    /// Reset the target into the debug monitor and unlock it. The target is then halted, and the
    /// returned sync holds its B, C, H and L at entry.
    fn attach(&mut self) -> Result<Sync, Rl78Error>;

    /// Unlock a session the monitor has locked again. Every monitor entry locks: after a halt,
    /// a step, or the target stopping by itself.
    fn unlock(&mut self) -> Result<(), Rl78Error>;

    /// Read memory in `F0000H`–`FFFFFH`. The target must be halted.
    fn read_mem(&mut self, address: u32, data: &mut [u8]) -> Result<(), Rl78Error>;

    /// Write memory in `F0000H`–`FFFFFH`. The target must be halted.
    fn write_mem(&mut self, address: u32, data: &[u8]) -> Result<(), Rl78Error>;

    /// Execute `CALL !!0FFED0H` inside the monitor and return when the routine there returns.
    fn call_stub(&mut self) -> Result<(), Rl78Error>;

    /// Load B, C, H and L and return from the debug interrupt. With `single_step`, the target
    /// executes one instruction and re-enters the monitor, and the new sync is returned;
    /// otherwise it runs freely and `None` is returned. Either way the session is locked again.
    fn execute(&mut self, regs: Sync, single_step: bool) -> Result<Option<Sync>, Rl78Error>;

    /// Halt a running target. Returns the sync, and leaves the session locked.
    fn halt(&mut self) -> Result<Sync, Rl78Error>;

    /// Reset the target into its own program: RESET with TOOL0 high, a normal boot. Whether the
    /// debugger can halt it afterwards depends on the program arming the monitor, which is what
    /// the debug stub at 000CEH does (notes section 31).
    fn reset(&mut self) -> Result<(), Rl78Error>;

    /// Check, without disturbing a running target, whether it re-entered the monitor by itself.
    /// A breakpoint does that, but so does a watchdog reset: the syncs are byte-identical (notes
    /// section 28.4), and only the PC tells them apart.
    fn poll_stopped(&mut self) -> Result<Option<Sync>, Rl78Error>;
}

/// A byte pipe to the target's TOOL0 line, plus control of RESET.
///
/// The UART runs at 115200 baud, 8 data bits, odd parity, 2 stop bits. Implementations must not
/// discard bytes they have accepted for transmission (the vendor's port driver does, and loses
/// the mode byte), and should hold the port with a lock the operating system releases if the
/// process dies.
pub trait Rl78Uart: Send + fmt::Debug {
    /// Queue bytes for transmission.
    fn write(&mut self, data: &[u8]) -> Result<(), Rl78Error>;

    /// Read whatever has arrived, up to `buf.len()` bytes, waiting at most `timeout` for the
    /// first. Returns the number of bytes read, 0 on timeout. Bytes beyond `buf.len()` that the
    /// transport delivered together must be kept for the next call, not dropped.
    fn read(&mut self, buf: &mut [u8], timeout: Duration) -> Result<usize, Rl78Error>;

    /// Drive the target's RESET pin.
    fn set_reset(&mut self, asserted: bool) -> Result<(), Rl78Error>;

    /// Hold TOOL0 low (a UART break) or release it. TOOL0 low as RESET is released selects the
    /// boot ROM, where the mode byte chooses between flash programming and debugging.
    fn set_tool0_low(&mut self, low: bool) -> Result<(), Rl78Error>;

    /// Discard anything received so far.
    fn flush_input(&mut self) -> Result<(), Rl78Error>;
}

/// Reset timing, measured on the RL78/G15 FPB. The settle is not padding: the FT232R ships
/// received bytes on its own schedule, so bytes in its FIFO when RESET went low can arrive after
/// a flush meant to discard them. Waiting first, then flushing, catches them.
const T_RESET_HOLD: Duration = Duration::from_millis(5);
const T_TOOL0_HOLD: Duration = Duration::from_millis(7);
const T_SETTLE: Duration = Duration::from_millis(35);

/// How long one reply may take. Replies are at most 257 bytes at 115200 baud, about 25 ms.
const REPLY_TIMEOUT: Duration = Duration::from_millis(1000);

/// F0085H bit 0 arms a single step (notes section 23.1). It is sticky across an execute, so a
/// free run must clear it explicitly.
const STEP_ENABLE: u32 = 0xF_0085;

/// The on-chip debugger driven over a UART, with the protocol codec in the host.
pub struct UartOcd<L> {
    link: L,
    state: protocol::State,
    security_id: [u8; SECURITY_ID_LEN],
}

impl<L: fmt::Debug> fmt::Debug for UartOcd<L> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UartOcd")
            .field("link", &self.link)
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

impl<L: Rl78Uart> UartOcd<L> {
    /// Wrap a link. `security_id` unlocks every session; a part that was never given one has ten
    /// `00H` bytes.
    pub fn new(link: L, security_id: [u8; SECURITY_ID_LEN]) -> Self {
        Self {
            link,
            state: protocol::State::new(),
            security_id,
        }
    }

    /// The link, for the probe that owns it.
    pub fn link_mut(&mut self) -> &mut L {
        &mut self.link
    }

    fn read_exact(&mut self, buf: &mut [u8], op: &'static str) -> Result<(), Rl78Error> {
        let deadline = Instant::now() + REPLY_TIMEOUT;
        let mut got = 0;
        while got < buf.len() {
            let left = deadline.saturating_duration_since(Instant::now());
            let n = self.link.read(&mut buf[got..], left)?;
            if n == 0 && left.is_zero() {
                return Err(Rl78Error::Timeout {
                    op,
                    got,
                    expected: buf.len(),
                });
            }
            got += n;
        }
        tracing::trace!("rl78 {op}: RX {:02x?}", buf);
        Ok(())
    }

    /// One transaction: encode, send, read `want` reply bytes (the codec's minimum when `None`),
    /// and let the codec check the reply and advance the session state.
    fn xfer(
        &mut self,
        op: Op,
        args: &Args,
        want: Option<usize>,
    ) -> Result<(Vec<u8>, Option<Sync>), Rl78Error> {
        let req = self.state.encode(op, args)?;
        let shape = self.state.response_shape(op, args)?;
        let want = want.unwrap_or(shape.min);
        tracing::trace!("rl78 {}: TX {:02x?}", op.name(), req);
        self.link.write(&req)?;
        let mut resp = vec![0; want];
        self.read_exact(&mut resp, op.name())?;
        let reply = self.state.apply_response(op, args, &resp)?;
        let sync = reply.sync;
        let payload = reply.payload.to_vec();
        Ok((payload, sync))
    }

    fn boot_mode_reset(&mut self) -> Result<(), Rl78Error> {
        // RESET first, then TOOL0 low. The other order fails on a part that is sitting in the
        // monitor: TOOL0 going low is a break, the monitor answers it, and the reset cuts the
        // answer off mid-byte, so its remains arrive after the flush (as 00H bytes with a parity
        // error) and are taken for the next reply. TOOL0 must still be low when RESET is
        // released, and stay low across the latch window.
        self.link.set_reset(true)?;
        self.link.set_tool0_low(true)?;
        std::thread::sleep(T_RESET_HOLD);
        self.link.set_reset(false)?;
        std::thread::sleep(T_TOOL0_HOLD);
        self.link.set_tool0_low(false)?;
        std::thread::sleep(T_SETTLE);
        self.link.flush_input()?;
        self.state = protocol::State::new();
        Ok(())
    }

    fn chunks(address: u32, len: usize) -> impl Iterator<Item = (u32, std::ops::Range<usize>)> {
        (0..len)
            .step_by(256)
            .map(move |off| (address + off as u32, off..len.min(off + 256)))
    }

    fn check_f_segment(address: u32, len: usize) -> Result<(), Rl78Error> {
        if address < protocol::ADDR16_BASE || address as usize + len > 0x10_0000 {
            return Err(Rl78Error::Other(format!(
                "{address:05X}H+{len} is outside F0000H-FFFFFH, which is all the monitor reaches"
            )));
        }
        Ok(())
    }
}

impl<L: Rl78Uart> Rl78OcdInterface for UartOcd<L> {
    fn attach(&mut self) -> Result<Sync, Rl78Error> {
        self.boot_mode_reset()?;
        // CAH is itself the mode byte, not a command after one. Sent after a 00H mode entry it
        // is an unknown flash-loader command (04H), and every later reply is off by one.
        let (_, sync) = self
            .xfer(Op::PbEnterOcd, &Args::default(), None)
            .map_err(|e| match e {
                Rl78Error::Timeout { .. } | Rl78Error::Codec(_) => Rl78Error::NoMonitor,
                e => e,
            })?;
        self.unlock()?;
        Ok(sync.expect("the codec decodes a sync for pb_enter_ocd"))
    }

    fn unlock(&mut self) -> Result<(), Rl78Error> {
        self.xfer(Op::UnlockChallenge, &Args::default(), None)?;
        let id = self.security_id;
        let args = Args {
            data: &id,
            ..Args::default()
        };
        match self.xfer(Op::UnlockSecurityId, &args, None) {
            Err(Rl78Error::Codec(CodecError::Rejected)) => Err(Rl78Error::SecurityIdRejected),
            r => r.map(|_| ()),
        }
    }

    fn read_mem(&mut self, address: u32, data: &mut [u8]) -> Result<(), Rl78Error> {
        Self::check_f_segment(address, data.len())?;
        for (addr, range) in Self::chunks(address, data.len()) {
            let args = Args {
                addr,
                len: range.len() as u16,
                ..Args::default()
            };
            self.xfer(Op::SetAddrLen, &args, None)?;
            let (payload, _) = self.xfer(Op::Read, &Args::default(), None)?;
            data[range].copy_from_slice(&payload);
        }
        Ok(())
    }

    fn write_mem(&mut self, address: u32, data: &[u8]) -> Result<(), Rl78Error> {
        Self::check_f_segment(address, data.len())?;
        for (addr, range) in Self::chunks(address, data.len()) {
            let args = Args {
                addr,
                len: range.len() as u16,
                ..Args::default()
            };
            self.xfer(Op::SetAddrLen, &args, None)?;
            let args = Args {
                data: &data[range],
                ..Args::default()
            };
            self.xfer(Op::Write, &args, None)?;
        }
        Ok(())
    }

    fn call_stub(&mut self) -> Result<(), Rl78Error> {
        self.xfer(Op::CallKernel, &Args::default(), None)?;
        Ok(())
    }

    fn execute(&mut self, regs: Sync, single_step: bool) -> Result<Option<Sync>, Rl78Error> {
        self.write_mem(STEP_ENABLE, &[u8::from(single_step)])?;
        let args = Args {
            regs,
            ..Args::default()
        };
        // One byte (the echo) means running; six means it trapped and re-entered at once.
        let want = if single_step { 6 } else { 1 };
        let (_, sync) = self.xfer(Op::Execute, &args, Some(want))?;
        if single_step && sync.is_none() {
            return Err(Rl78Error::Other(
                "stepped, but the target did not trap".into(),
            ));
        }
        Ok(sync)
    }

    fn halt(&mut self) -> Result<Sync, Rl78Error> {
        // The sync may already be waiting if the target stopped by itself just now; the caller
        // should have polled first. Anything here now is answered by the halt below.
        let (_, sync) = self
            .xfer(Op::Halt, &Args::default(), None)
            .map_err(|e| match e {
                Rl78Error::Timeout { got: 0, .. } => Rl78Error::HaltUnanswered,
                e => e,
            })?;
        Ok(sync.expect("the codec decodes a sync for halt"))
    }

    fn reset(&mut self) -> Result<(), Rl78Error> {
        self.link.set_reset(true)?;
        std::thread::sleep(T_RESET_HOLD);
        self.link.set_reset(false)?;
        std::thread::sleep(T_SETTLE);
        self.link.flush_input()?;
        // If the program arms the monitor, the link is now the OCD protocol with the target
        // running, which looks exactly like a locked session after a resume.
        self.state = protocol::State {
            phase: Phase::Ocd,
            ..protocol::State::new()
        };
        Ok(())
    }

    fn poll_stopped(&mut self) -> Result<Option<Sync>, Rl78Error> {
        if self.state.phase != Phase::Ocd || !self.state.locked {
            // Unlocked means halted: the target cannot be running in an open session.
            return Ok(None);
        }
        // Read only. Sending anything would halt the very target being observed.
        let mut buf = [0u8; SYNC_LEN];
        let n = self.link.read(&mut buf, Duration::ZERO)?;
        if n == 0 {
            return Ok(None);
        }
        // The rest of the sync may still be in flight, and without it B, C, H and L are lost.
        self.read_exact(&mut buf[n..], "unsolicited sync")?;
        if buf[SYNC_LEN - 1] != 0x00 {
            return Err(CodecError::Protocol("unsolicited sync").into());
        }
        tracing::debug!("rl78: target re-entered the monitor by itself: {buf:02x?}");
        Ok(Some(Sync::from_bytes(&buf)))
    }
}
