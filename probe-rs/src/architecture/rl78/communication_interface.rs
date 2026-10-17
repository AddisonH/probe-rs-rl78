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

use probe_rs_target::Rl78Monitor;

use super::g23;
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

    /// The security ID was rejected. Set the part's ID with PROBE_RS_RL78_SECURITY_ID (a blank
    /// part's is FFFFFFFFFFFFFFFFFFFF).
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

    /// {0} while the target runs: only RAM and the SFRs, through pseudo-RRM, and only for a
    /// program that enables it with a block pointer at 00002H.
    NotWhileRunning(&'static str),

    /// The running target did not answer pseudo-RRM/DMM's {0}: is the monitor armed, and does
    /// 00002H point at the program's 4-byte block?
    RrmUnanswered(&'static str),

    /// Flash {op} at {address:05X}H failed: FSASTL error flags {status:02X}H (SEQER 10H, WRER
    /// 02H, ERER 01H).
    Flash {
        /// What the sequencer was doing.
        op: &'static str,
        /// The first address of the command.
        address: u32,
        /// FSASTL, masked to its error flags.
        status: u8,
    },

    /// The flash protocol's {op} answered {status:02X}H (15H NACK, 1AH erase error, 1BH blank
    /// or verify error).
    FlashProtocol {
        /// The command.
        op: &'static str,
        /// The status byte.
        status: u8,
    },
    /// The flash protocol wrote the image, but the part's CRC of it is {got:04X}H, not
    /// {expected:04X}H.
    FlashCrc {
        /// The part's CRC.
        got: u16,
        /// The image's.
        expected: u16,
    },
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
    /// Speak to `monitor` from the next attach on.
    fn set_monitor(&mut self, monitor: Rl78Monitor) -> Result<(), Rl78Error> {
        match monitor {
            Rl78Monitor::G15 => Ok(()),
            _ => Err(Rl78Error::Unsupported(
                "this part's debug monitor on this probe",
            )),
        }
    }

    /// The monitor this interface speaks to.
    fn monitor(&self) -> Rl78Monitor {
        Rl78Monitor::G15
    }

    /// Reset the target into the debug monitor and unlock it. The target is then halted, and the
    /// returned sync holds its B, C, H and L at entry.
    fn attach(&mut self) -> Result<Sync, Rl78Error>;

    /// Halt a program that runs with the monitor armed, as the debug stub leaves it after a
    /// normal boot, and unlock: an attach that leaves the program where it was. `None`
    /// when nothing answers: no stub, no program running, or a part already in the monitor.
    fn attach_running(&mut self) -> Result<Option<Sync>, Rl78Error> {
        Ok(None)
    }

    /// Unlock a session the monitor has locked again. Every monitor entry locks: after a halt,
    /// a step, or the target stopping by itself.
    fn unlock(&mut self) -> Result<(), Rl78Error>;

    /// The security ID this interface unlocks with. Flash programming writes it into an image
    /// that leaves the part's ID erased, so the next attach still unlocks.
    fn security_id(&self) -> [u8; SECURITY_ID_LEN];

    /// Read memory in `F0000H`–`FFFFFH`. The target must be halted.
    fn read_mem(&mut self, address: u32, data: &mut [u8]) -> Result<(), Rl78Error>;

    /// Write memory in `F0000H`–`FFFFFH`. The target must be halted.
    fn write_mem(&mut self, address: u32, data: &[u8]) -> Result<(), Rl78Error>;

    /// Execute `CALL !!0FFED0H` inside the monitor and return when the routine there returns,
    /// waiting up to `timeout` for it to do so.
    fn call_stub(&mut self, timeout: Duration) -> Result<(), Rl78Error>;

    /// Load B, C, H and L and return from the debug interrupt. With `single_step`, the target
    /// executes one instruction and re-enters the monitor, and the new sync is returned;
    /// otherwise it runs freely and `None` is returned. Either way the session is locked again.
    fn execute(&mut self, regs: Sync, single_step: bool) -> Result<Option<Sync>, Rl78Error>;

    /// Halt a running target. Returns the sync, and leaves the session locked.
    fn halt(&mut self) -> Result<Sync, Rl78Error>;

    /// Reset the target into its own program: RESET with TOOL0 high, a normal boot. Whether the
    /// debugger can halt it afterwards depends on the program arming the monitor, which is what
    /// the debug stub at 000CEH does.
    fn reset(&mut self) -> Result<(), Rl78Error>;

    /// Check, without disturbing a running target, whether it re-entered the monitor by itself.
    /// A breakpoint does that, but so does a watchdog reset: the syncs are byte-identical, and
    /// only the PC tells them apart.
    fn poll_stopped(&mut self) -> Result<Option<Sync>, Rl78Error>;

    /// Read RAM or SFRs while the program runs, through the ROM's pseudo-RRM: one
    /// command byte and one reply byte at a time, five per byte read, the program interrupted
    /// for a few microseconds each. Only `F0000H`-`F07FFH` and `FDF00H`-`FFFFFH`, and only for
    /// a program that put a block pointer at `00002H`.
    fn rrm_read(&mut self, address: u32, data: &mut [u8]) -> Result<Rrm, Rl78Error> {
        let _ = (address, data);
        Err(Rl78Error::Unsupported("pseudo-RRM on this probe"))
    }

    /// Write RAM or SFRs while the program runs, through pseudo-DMM: seven bytes per byte, eight
    /// per aligned word. The same limits as [`rrm_read`](Self::rrm_read).
    fn rrm_write(&mut self, address: u32, data: &[u8]) -> Result<Rrm, Rl78Error> {
        let _ = (address, data);
        Err(Rl78Error::Unsupported("pseudo-DMM on this probe"))
    }

    /// Erase all of code flash and write `image` from `00000H` over the flash protocol (Protocol
    /// B's write after erase), then check its CRC. This reaches a part the debugger cannot: one
    /// that is blank, has an unknown security ID, or has lost its debug stub. The part is left
    /// in flash programming mode; [`attach`](Self::attach) after.
    fn erase_all_and_program(&mut self, image: &[u8]) -> Result<(), Rl78Error> {
        let _ = image;
        Err(Rl78Error::Unsupported("the flash protocol on this probe"))
    }
}

/// What a pseudo-RRM/DMM access found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rrm {
    /// Done, the program running throughout.
    Done,
    /// The target stopped first (a breakpoint): it answered with its re-entry sync, returned
    /// for the core to take. The access is incomplete.
    Stopped(Sync),
}

/// What may follow a pseudo-RRM reply when the target has stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Trailing {
    /// The reply is predictable: a stopped target's sync would not match it.
    Known,
    /// A data reply: look at what has already arrived behind it.
    Buffered,
    /// A data reply that ends an access: wait a USB frame for anything behind it.
    Wait,
}

/// The first sync in what a stopped target sent. After the stop the stream is whole 5-byte syncs
/// (the stop's, then one per command a locked monitor received), unless the read before took the
/// first byte for data: then it is four bytes short, and `last_data` was that byte.
fn first_sync(stream: &[u8], last_data: Option<u8>) -> Option<Sync> {
    let sync: Vec<u8> = match (stream.len() % SYNC_LEN, last_data) {
        (0, _) if !stream.is_empty() => stream[..SYNC_LEN].to_vec(),
        (4, Some(first)) => std::iter::once(first)
            .chain(stream[..4].iter().copied())
            .collect(),
        _ => return None,
    };
    (sync[SYNC_LEN - 1] == 0x00).then(|| Sync::from_bytes(&sync))
}

/// A byte pipe to the target's TOOL0 line, plus control of RESET.
///
/// The UART starts at 115200 baud, 8 data bits, odd parity, 2 stop bits, the G15 monitor's
/// framing; [`set_line`](Self::set_line) changes it for the others. Implementations must not
/// discard bytes they have accepted for transmission (losing the mode byte that way leaves the
/// part in the flash loader), and should hold the port with a lock the operating system releases if the
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

    /// Set the rate and parity (odd or none); there are always 8 data bits and 2 stop bits.
    fn set_line(&mut self, baud: u32, odd_parity: bool) -> Result<(), Rl78Error> {
        let _ = (baud, odd_parity);
        Err(Rl78Error::Unsupported(
            "changing the line settings on this probe",
        ))
    }

    /// How many received bytes are waiting, without asking the transport for more: free, where
    /// [`read`](Self::read) with no timeout costs a USB transfer.
    fn buffered(&self) -> usize {
        0
    }
}

/// Reset timing, measured on the RL78/G15 FPB. The settle is not padding: the FT232R ships
/// received bytes on its own schedule, so bytes in its FIFO when RESET went low can arrive after
/// a flush meant to discard them. Waiting first, then flushing, catches them.
const T_RESET_HOLD: Duration = Duration::from_millis(5);
const T_TOOL0_HOLD: Duration = Duration::from_millis(7);
const T_SETTLE: Duration = Duration::from_millis(35);

/// How long one reply may take. Replies are at most 257 bytes at 115200 baud, about 25 ms.
const REPLY_TIMEOUT: Duration = Duration::from_millis(1000);
/// A pseudo-RRM/DMM reply: one byte from an interrupt handler, plus USB.
const T_RRM: Duration = Duration::from_millis(30);
/// Quiet on the line after a stop, before the last sync is taken to be complete.
const T_RRM_DRAIN: Duration = Duration::from_millis(20);
/// How long a running program with the monitor armed takes to answer a halt, with room for USB.
const T_ATTACH_RUNNING: Duration = Duration::from_millis(100);

/// F0085H bit 0 arms a single step. It is sticky across an execute, so a free run must clear it
/// explicitly.
const STEP_ENABLE: u32 = 0xF_0085;

/// The on-chip debugger driven over a UART, with the protocol codec in the host.
pub struct UartOcd<L> {
    link: L,
    monitor: Rl78Monitor,
    state: protocol::State,
    security_id: [u8; SECURITY_ID_LEN],
    /// The last pseudo-RRM data reply: if the target had stopped, it was the sync's first byte.
    rrm_last_data: Option<u8>,
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
            monitor: Rl78Monitor::G15,
            state: protocol::State::new(),
            security_id,
            rrm_last_data: None,
        }
    }

    /// The link, for the probe that owns it.
    pub fn link_mut(&mut self) -> &mut L {
        &mut self.link
    }

    fn read_exact(
        &mut self,
        buf: &mut [u8],
        op: &'static str,
        timeout: Duration,
    ) -> Result<(), Rl78Error> {
        let deadline = Instant::now() + timeout;
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
        self.xfer_within(op, args, want, REPLY_TIMEOUT)
    }

    /// [`xfer`](Self::xfer), waiting up to `timeout` for the reply.
    fn xfer_within(
        &mut self,
        op: Op,
        args: &Args,
        want: Option<usize>,
        timeout: Duration,
    ) -> Result<(Vec<u8>, Option<Sync>), Rl78Error> {
        let req = self.state.encode(op, args)?;
        let shape = self.state.response_shape(op, args)?;
        let want = want.unwrap_or(shape.min);
        tracing::trace!("rl78 {}: TX {:02x?}", op.name(), req);
        self.link.write(&req)?;
        let mut resp = vec![0; want];
        self.read_exact(&mut resp, op.name(), timeout)?;
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

    /// One pseudo-RRM/DMM command. `expect` is the reply it must have, where that is known:
    /// anything else came from a target that has stopped, and is the start of its sync. A data
    /// reply (`expect` `None`) is checked for bytes behind it instead.
    fn rrm_command(
        &mut self,
        op: Op,
        nibble: u8,
        expect: impl FnOnce(u8) -> bool,
        trailing: Trailing,
    ) -> Result<Result<u8, Sync>, Rl78Error> {
        let args = Args {
            nibble,
            ..Args::default()
        };
        let req = self.state.encode(op, &args)?;
        self.link.write(&req)?;
        let mut reply = [0u8; 1];
        if let Err(e) = self.read_exact(&mut reply, op.name(), T_RRM) {
            return Err(match e {
                Rl78Error::Timeout { got: 0, .. } => Rl78Error::RrmUnanswered(op.name()),
                e => e,
            });
        }
        let behind = match trailing {
            Trailing::Known => false,
            Trailing::Buffered => self.link.buffered() > 0,
            Trailing::Wait => {
                let mut more = [0u8; SYNC_LEN];
                let n = self.link.read(&mut more, Duration::ZERO)?;
                self.rrm_last_data = Some(reply[0]);
                if n > 0 {
                    let mut got = vec![reply[0]];
                    got.extend_from_slice(&more[..n]);
                    return Ok(Err(self.rrm_stopped(got)?));
                }
                false
            }
        };
        if behind || !expect(reply[0]) {
            return Ok(Err(self.rrm_stopped(vec![reply[0]])?));
        }
        // Only the command right after a data reply can find that reply was a sync's first byte.
        self.rrm_last_data = (trailing != Trailing::Known).then_some(reply[0]);
        self.state.apply_response(op, &args, &reply)?;
        Ok(Ok(reply[0]))
    }

    /// The target answered a pseudo-RRM command with something else: it stopped, and `got` is
    /// the start of its re-entry sync. Our commands after that went to a locked monitor, which
    /// answers each with the sync again; the first is the one with the program's B, C, H and L.
    fn rrm_stopped(&mut self, mut got: Vec<u8>) -> Result<Sync, Rl78Error> {
        // Everything the target sends now is whole syncs: let it finish.
        let mut drain = [0u8; 64];
        loop {
            let n = self.link.read(&mut drain, T_RRM_DRAIN)?;
            if n == 0 {
                break;
            }
            got.extend_from_slice(&drain[..n]);
        }
        let last_data = self.rrm_last_data.take();
        self.state.locked = true;
        self.state.rrm_c = 0;
        tracing::debug!("rl78: the target stopped during pseudo-RRM: {got:02x?}");
        first_sync(&got, last_data)
            .ok_or_else(|| CodecError::Protocol("sync after pseudo-RRM").into())
    }

    /// Bring the ROM's counter back to zero after a command went unanswered: `D0H` reads (and
    /// answers) if the count is four, and otherwise fails its gate, which zeroes it silently.
    fn rrm_resync(&mut self) -> Result<(), Rl78Error> {
        self.link.write(&[0xD0])?;
        let mut drain = [0u8; 64];
        while self.link.read(&mut drain, T_RRM_DRAIN)? > 0 {}
        self.state.rrm_c = 0;
        Ok(())
    }

    /// Shift a 16-bit address into the ROM's accumulator, most significant nibble first. Each
    /// reply is the accumulator's low byte: of the first, only its low nibble is ours.
    fn rrm_address(&mut self, address: u16) -> Result<Option<Sync>, Rl78Error> {
        for k in (0..4).rev() {
            let nibble = (address >> (4 * k)) as u8 & 0x0F;
            let low = (address >> (4 * k)) as u8;
            let expect = move |r: u8| if k == 3 { r & 0x0F == nibble } else { r == low };
            if let Err(sync) =
                self.rrm_command(Op::RrmAddrNibble, nibble, expect, Trailing::Known)?
            {
                return Ok(Some(sync));
            }
        }
        Ok(None)
    }

    /// Shift data nibbles in, most significant first. Each reply is the nibble over the count.
    fn rrm_data(&mut self, nibbles: &[u8]) -> Result<Option<Sync>, Rl78Error> {
        for &nibble in nibbles {
            let c = self.state.rrm_c + 1;
            let expect = move |r: u8| r == nibble << 4 | c;
            if let Err(sync) =
                self.rrm_command(Op::RrmDataNibble, nibble, expect, Trailing::Known)?
            {
                return Ok(Some(sync));
            }
        }
        Ok(None)
    }

    /// One pseudo-RRM/DMM access, tried again once after a failure. The ROM's counter lives in
    /// the program's RAM, and a block nobody zeroed, or an earlier access cut short, leaves it
    /// wrong: the first terminator then fails its gate and goes unanswered, which zeroes it.
    fn rrm_retry<T>(
        &mut self,
        mut access: impl FnMut(&mut Self) -> Result<Result<T, Sync>, Rl78Error>,
    ) -> Result<Result<T, Sync>, Rl78Error> {
        match access(self) {
            Err(e) => {
                tracing::debug!("rl78: pseudo-RRM failed ({e}); trying again");
                self.rrm_resync()?;
                access(self)
            }
            done => done,
        }
    }

    fn rrm_read_byte(&mut self, address: u16, last: bool) -> Result<Result<u8, Sync>, Rl78Error> {
        if let Some(sync) = self.rrm_address(address)? {
            return Ok(Err(sync));
        }
        // A sync behind the reply means the target had stopped and the "data" is its first
        // byte. Looking for it costs a USB frame; it is only worth that on an access's last
        // byte, since a stop before any other shows in the next command's reply.
        let trailing = if last {
            Trailing::Wait
        } else {
            Trailing::Buffered
        };
        self.rrm_command(Op::RrmReadByte, 0, |_| true, trailing)
    }

    /// One byte, or an aligned pair as a word: n1 n2 are the high byte and n3 n4 the low, and
    /// n4 rides in the `9xH` that commits.
    fn rrm_write_once(&mut self, address: u16, data: &[u8]) -> Result<Result<(), Sync>, Rl78Error> {
        if let Some(sync) = self.rrm_address(address)? {
            return Ok(Err(sync));
        }
        let (nibbles, commit, nibble, ack) = match *data {
            [low, high] => (
                vec![high >> 4, high & 0x0F, low >> 4],
                Op::RrmWriteWord,
                low & 0x0F,
                0xDA,
            ),
            [value] => (vec![value >> 4, value & 0x0F], Op::RrmWriteByte, 0, 0xD9),
            _ => unreachable!("one byte or a word"),
        };
        if let Some(sync) = self.rrm_data(&nibbles)? {
            return Ok(Err(sync));
        }
        Ok(self
            .rrm_command(commit, nibble, |r| r == ack, Trailing::Known)?
            .map(|_| ()))
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

/// The G23 monitor's link rate, chosen in its entry frame.
const G23_BAUD: u32 = 1_000_000;
/// How long the boot ROM takes to answer the G23 monitor's entry frame.
const T_G23_ENTRY: Duration = Duration::from_millis(100);

impl<L: Rl78Uart> UartOcd<L> {
    fn g23_xfer(&mut self, req: &[u8], n: usize, op: &'static str) -> Result<Vec<u8>, Rl78Error> {
        self.g23_xfer_within(req, n, op, REPLY_TIMEOUT)
    }

    fn g23_xfer_within(
        &mut self,
        req: &[u8],
        n: usize,
        op: &'static str,
        timeout: Duration,
    ) -> Result<Vec<u8>, Rl78Error> {
        tracing::trace!("rl78 {op}: TX {req:02x?}");
        self.link.write(req)?;
        let mut resp = vec![0; n];
        self.read_exact(&mut resp, op, timeout)?;
        Ok(resp)
    }

    fn g23_expect(&mut self, req: &[u8], want: &[u8], op: &'static str) -> Result<(), Rl78Error> {
        if self.g23_xfer(req, want.len(), op)? != want {
            return Err(CodecError::Protocol(op).into());
        }
        Ok(())
    }

    fn g23_attach(&mut self) -> Result<(), Rl78Error> {
        let (baud, code) = *g23::RATES
            .iter()
            .find(|(baud, _)| *baud == G23_BAUD)
            .expect("a rate the frame can choose");
        self.link.set_line(115_200, false)?;
        self.boot_mode_reset()?;
        self.link.write(&g23::entry(code))?;
        // The monitor answers 00H at the new rate before the host can switch to it, so the
        // byte is taken whatever it reads as, and 90H is the check.
        self.link.read(&mut [0], T_G23_ENTRY)?;
        self.link.set_line(baud, false)?;
        self.link.flush_input()?;
        self.state = protocol::State {
            phase: Phase::Ocd,
            ..protocol::State::new()
        };
        self.g23_unlock().map_err(|e| match e {
            Rl78Error::Timeout { .. } | Rl78Error::Codec(CodecError::Protocol(_)) => {
                Rl78Error::NoMonitor
            }
            e => e,
        })
    }

    fn g23_unlock(&mut self) -> Result<(), Rl78Error> {
        self.g23_expect(&[g23::VERSION], &g23::VERSION_REPLY, "version")?;
        match self.g23_xfer(&[g23::UNLOCK], 1, "unlock")?[0] {
            g23::UNLOCK_ALREADY => {}
            g23::UNLOCK_CHALLENGE => {
                let id = g23::unlock_id(&self.security_id);
                match self.g23_xfer(&id, 1, "security ID")?[0] {
                    g23::UNLOCK_ACCEPTED => {}
                    g23::UNLOCK_HALTED => {
                        tracing::error!(
                            "rl78: wrong security ID with option byte 000C3H bit 0 clear: the part \
                             has halted and erases its flash"
                        );
                        return Err(Rl78Error::SecurityIdRejected);
                    }
                    _ => return Err(Rl78Error::SecurityIdRejected),
                }
            }
            _ => return Err(CodecError::Protocol("unlock").into()),
        }
        self.state.locked = false;
        Ok(())
    }

    fn g23_read(&mut self, address: u32, data: &mut [u8]) -> Result<(), Rl78Error> {
        Self::check_f_segment(address, data.len())?;
        for (addr, range) in Self::chunks(address, data.len()) {
            let [lo, hi, ..] = addr.to_le_bytes();
            let n = range.len();
            let got = self.g23_xfer(&[g23::READ, lo, hi, n as u8], n, "read")?;
            data[range].copy_from_slice(&got);
        }
        Ok(())
    }

    fn g23_write(&mut self, address: u32, data: &[u8]) -> Result<(), Rl78Error> {
        Self::check_f_segment(address, data.len())?;
        for (addr, range) in Self::chunks(address, data.len()) {
            let [lo, hi, ..] = addr.to_le_bytes();
            let mut req = vec![g23::WRITE, lo, hi, range.len() as u8];
            req.extend_from_slice(&data[range]);
            self.g23_expect(&req, &[g23::WRITE], "write")?;
        }
        Ok(())
    }

    fn g23_call(&mut self, timeout: Duration) -> Result<(), Rl78Error> {
        // The echo goes out before the call, so a 90H sent behind it, which the monitor reads
        // when the routine returns, is what says it has.
        self.g23_expect(&[g23::CALL], &[g23::CALL], "call")?;
        let done = self.g23_xfer_within(&[g23::VERSION], 2, "call", timeout)?;
        if done != g23::VERSION_REPLY {
            return Err(CodecError::Protocol("call").into());
        }
        Ok(())
    }

    fn g23_execute(&mut self, single_step: bool) -> Result<Option<Sync>, Rl78Error> {
        self.g23_write(g23::STEP_ENABLE, &[u8::from(single_step)])?;
        self.g23_expect(&[g23::RUN], &[g23::RUN], "run")?;
        self.state.locked = true;
        if !single_step {
            return Ok(None);
        }
        let mut entered = [0];
        self.read_exact(&mut entered, "step", REPLY_TIMEOUT)?;
        if entered != [0x00] {
            return Err(CodecError::Protocol("step").into());
        }
        Ok(Some(Sync::default()))
    }

    fn g23_halt(&mut self) -> Result<Sync, Rl78Error> {
        match self.g23_xfer(&[0x00], 1, "halt") {
            Ok(r) if r == [0x00] => Ok(Sync::default()),
            Ok(_) => Err(CodecError::Protocol("halt").into()),
            Err(Rl78Error::Timeout { got: 0, .. }) => Err(Rl78Error::HaltUnanswered),
            Err(e) => Err(e),
        }
    }

    fn g23_poll_stopped(&mut self) -> Result<Option<Sync>, Rl78Error> {
        let mut buf = [0];
        if self.link.read(&mut buf, Duration::ZERO)? == 0 {
            return Ok(None);
        }
        if buf != [0x00] {
            return Err(CodecError::Protocol("unsolicited entry").into());
        }
        tracing::debug!("rl78: target re-entered the monitor by itself");
        Ok(Some(Sync::default()))
    }
}

impl<L: Rl78Uart> Rl78OcdInterface for UartOcd<L> {
    fn set_monitor(&mut self, monitor: Rl78Monitor) -> Result<(), Rl78Error> {
        self.monitor = monitor;
        Ok(())
    }

    fn monitor(&self) -> Rl78Monitor {
        self.monitor
    }

    fn attach(&mut self) -> Result<Sync, Rl78Error> {
        if self.monitor == Rl78Monitor::G23 {
            return self.g23_attach().map(|()| Sync::default());
        }
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

    fn attach_running(&mut self) -> Result<Option<Sync>, Rl78Error> {
        if self.monitor == Rl78Monitor::G23 {
            return Ok(None);
        }
        // An armed monitor answers a 00H within a few milliseconds. Speak to it as to a
        // target the monitor has let run; if nothing answers, the attach under reset starts the
        // codec afresh.
        self.link.flush_input()?;
        self.state = protocol::State {
            phase: protocol::Phase::Ocd,
            ..protocol::State::default()
        };
        match self.xfer_within(Op::Halt, &Args::default(), None, T_ATTACH_RUNNING) {
            Ok((_, sync)) => {
                self.unlock()?;
                Ok(Some(sync.expect("the codec decodes a sync for halt")))
            }
            Err(e) => {
                tracing::debug!("rl78: no program running with the monitor armed: {e}");
                Ok(None)
            }
        }
    }

    fn security_id(&self) -> [u8; SECURITY_ID_LEN] {
        self.security_id
    }

    fn rrm_read(&mut self, address: u32, data: &mut [u8]) -> Result<Rrm, Rl78Error> {
        if self.monitor == Rl78Monitor::G23 {
            return Err(Rl78Error::Unsupported("pseudo-RRM on this monitor"));
        }
        let len = data.len();
        for (i, byte) in data.iter_mut().enumerate() {
            let a = (address as usize + i) as u16;
            match self.rrm_retry(|ocd| ocd.rrm_read_byte(a, i + 1 == len))? {
                Ok(value) => *byte = value,
                Err(sync) => return Ok(Rrm::Stopped(sync)),
            }
        }
        Ok(Rrm::Done)
    }

    fn rrm_write(&mut self, address: u32, data: &[u8]) -> Result<Rrm, Rl78Error> {
        if self.monitor == Rl78Monitor::G23 {
            return Err(Rl78Error::Unsupported("pseudo-DMM on this monitor"));
        }
        let mut at = 0;
        while at < data.len() {
            let a = (address as usize + at) as u16;
            // An aligned pair goes as one word, which the ROM stores in one go.
            let n = if a.is_multiple_of(2) && at + 1 < data.len() {
                2
            } else {
                1
            };
            let bytes = &data[at..at + n];
            if let Err(sync) = self.rrm_retry(|ocd| ocd.rrm_write_once(a, bytes))? {
                return Ok(Rrm::Stopped(sync));
            }
            at += n;
        }
        Ok(Rrm::Done)
    }

    fn unlock(&mut self) -> Result<(), Rl78Error> {
        if self.monitor == Rl78Monitor::G23 {
            return self.g23_unlock();
        }
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
        if self.monitor == Rl78Monitor::G23 {
            return self.g23_read(address, data);
        }
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
        if self.monitor == Rl78Monitor::G23 {
            return self.g23_write(address, data);
        }
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

    fn call_stub(&mut self, timeout: Duration) -> Result<(), Rl78Error> {
        if self.monitor == Rl78Monitor::G23 {
            return self.g23_call(timeout);
        }
        self.xfer_within(Op::CallKernel, &Args::default(), None, timeout)?;
        Ok(())
    }

    fn execute(&mut self, regs: Sync, single_step: bool) -> Result<Option<Sync>, Rl78Error> {
        if self.monitor == Rl78Monitor::G23 {
            return self.g23_execute(single_step);
        }
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
        if self.monitor == Rl78Monitor::G23 {
            return self.g23_halt();
        }
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
        if self.monitor == Rl78Monitor::G23 {
            return self.g23_poll_stopped();
        }
        // Read only. Sending anything would halt the very target being observed.
        let mut buf = [0u8; SYNC_LEN];
        let n = self.link.read(&mut buf, Duration::ZERO)?;
        if n == 0 {
            return Ok(None);
        }
        // The rest of the sync may still be in flight, and without it B, C, H and L are lost.
        self.read_exact(&mut buf[n..], "unsolicited sync", REPLY_TIMEOUT)?;
        if buf[SYNC_LEN - 1] != 0x00 {
            return Err(CodecError::Protocol("unsolicited sync").into());
        }
        tracing::debug!("rl78: target re-entered the monitor by itself: {buf:02x?}");
        Ok(Some(Sync::from_bytes(&buf)))
    }

    fn erase_all_and_program(&mut self, image: &[u8]) -> Result<(), Rl78Error> {
        if self.monitor == Rl78Monitor::G23 {
            return Err(Rl78Error::Unsupported("the flash protocol on this monitor"));
        }
        let started = Instant::now();
        self.boot_mode_reset()?;
        // 36H instead of 06H is the first ACK of a part with data flash.
        let r = self.pb_xfer(Op::PbModeEntry, &Args::default(), 1)?;
        pb_status("mode entry", r[0], &[0x06, 0x36])?;

        // ACK, and the flash size in 256-byte units less one.
        let r = self.pb_xfer(Op::PbWriteAfterErase, &Args::default(), 2)?;
        pb_status("write after erase", r[0], &[0x06])?;
        let size = (usize::from(r[1]) + 1) * 256;
        if image.len() != size {
            return Err(Rl78Error::Other(format!(
                "the flash protocol writes all {size} bytes of code flash; the image has {}",
                image.len()
            )));
        }
        // The host's ACK starts the erase; its ACK ends it.
        let ack = self.state.encode(Op::PbAck, &Args::default())?;
        self.link.write(&ack)?;
        let status = self.pb_erase_done()?;
        pb_status("erase", status, &[0x06])?;
        self.state
            .apply_response(Op::PbAck, &Args::default(), &[status])?;

        // Four bytes at a time, each answered once programmed; the last answer also carries the
        // verify's.
        let groups = image.len() / 4;
        for (i, group) in image.chunks(4).enumerate() {
            let last = i + 1 == groups;
            let args = Args {
                data: group,
                ..Args::default()
            };
            let r = self.pb_xfer(Op::PbDataGroup, &args, if last { 2 } else { 1 })?;
            for &status in &r {
                pb_status("write", status, &[0x06])?;
            }
        }

        let r = self.pb_xfer(Op::PbCodeflashCrc, &Args::default(), 2)?;
        pb_status("CRC check", r[0], &[0x06])?;
        let r = self.pb_xfer(Op::PbAck, &Args::default(), 3)?;
        pb_status("CRC check", r[0], &[0x06])?;
        // Little-endian: checked against a write on the G15 FPB.
        let got = u16::from_le_bytes([r[1], r[2]]);
        let expected = protocol::flash_crc(image);
        if got != expected {
            return Err(Rl78Error::FlashCrc { got, expected });
        }
        tracing::info!(
            "rl78: wrote {size} bytes over the flash protocol in {:.2?}",
            started.elapsed()
        );
        Ok(())
    }
}

/// The longest a write after erase may take to erase the code flash: 208 ms plus 6 ms per KB,
/// 256 ms for 8 KB, with room for a part four times the size.
const PB_ERASE_TIMEOUT: Duration = Duration::from_secs(1);

fn pb_status(op: &'static str, status: u8, ok: &[u8]) -> Result<(), Rl78Error> {
    if ok.contains(&status) {
        Ok(())
    } else {
        Err(Rl78Error::FlashProtocol { op, status })
    }
}

impl<L: Rl78Uart> UartOcd<L> {
    /// A flash-protocol exchange: the status bytes are the caller's to check.
    fn pb_xfer(&mut self, op: Op, args: &Args, want: usize) -> Result<Vec<u8>, Rl78Error> {
        let req = self.state.encode(op, args)?;
        self.link.write(&req)?;
        let mut resp = vec![0; want];
        self.read_exact(&mut resp, op.name(), REPLY_TIMEOUT)?;
        self.state.apply_response(op, args, &resp)?;
        Ok(resp)
    }

    /// Wait out the erase. `FFH` bytes can arrive before the ACK; they are skipped.
    fn pb_erase_done(&mut self) -> Result<u8, Rl78Error> {
        let deadline = Instant::now() + PB_ERASE_TIMEOUT;
        loop {
            let mut b = [0];
            let left = deadline.saturating_duration_since(Instant::now());
            if self.link.read(&mut b, left)? == 0 {
                if left.is_zero() {
                    return Err(Rl78Error::Timeout {
                        op: "erase",
                        got: 0,
                        expected: 1,
                    });
                }
            } else if b[0] != 0xFF {
                return Ok(b[0]);
            }
        }
    }
}

#[cfg(test)]
mod rrm_tests {
    use super::{Sync, first_sync};

    const SYNC: [u8; 5] = [0x12, 0x34, 0x56, 0x78, 0x00];

    #[test]
    fn a_stop_seen_at_a_syncs_first_byte() {
        let stream: Vec<u8> = SYNC.iter().chain(&[0, 0, 0, 0, 0]).copied().collect();
        assert_eq!(
            first_sync(&stream, Some(0xAA)),
            Some(Sync::from_bytes(&SYNC))
        );
    }

    #[test]
    fn a_stop_whose_first_byte_was_taken_for_data() {
        // The read before got 12H; what follows is the rest of that sync and one more.
        let stream: Vec<u8> = SYNC[1..].iter().chain(&SYNC).copied().collect();
        assert_eq!(
            first_sync(&stream, Some(0x12)),
            Some(Sync::from_bytes(&SYNC))
        );
        assert_eq!(
            first_sync(&stream, None),
            None,
            "no data before: not a sync stream"
        );
    }

    #[test]
    fn not_a_sync() {
        assert_eq!(first_sync(&[1, 2, 3, 4, 5], None), None, "no prompt byte");
        assert_eq!(first_sync(&[1, 2, 3], Some(0)), None);
        assert_eq!(first_sync(&[], None), None);
    }
}
