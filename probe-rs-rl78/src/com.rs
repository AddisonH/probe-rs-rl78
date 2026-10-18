//! The COM-port debugger: an FT232R wired to the target's TOOL0 and RESET, as on Renesas's
//! Fast Prototyping Boards.
//!
//! On the board, TOOL0 is driven from TXD through a 2 kΩ resistor, so a UART break holds it low.
//! RESET is gated by a tristate buffer: RTS is its output enable and DTR its input. RTS asserted
//! lets the pull-up hold RESET high, which is the safe idle state; only with RTS released does
//! DTR drive it.
//!
//! The FT232R is driven over USB directly rather than through a tty, for reasons that are not
//! stylistic. Its latency timer must be 1 ms, or every reply waits out the 16 ms default and the
//! link runs about 16 times slower; through a tty that timer is a root-owned sysfs file. 8-O-2
//! framing, the break and the reset lines are likewise one vendor request each. And claiming the
//! USB interface is a port lock the operating system releases when the process dies.

use std::{
    collections::VecDeque,
    fmt,
    time::{Duration, Instant},
};

use nusb::{
    Endpoint, Interface, MaybeFuture,
    transfer::{Buffer, Bulk, ControlOut, ControlType, In, Out, Recipient},
};
use probe_rs::{
    architecture::rl78::communication_interface::{
        Rl78Error, Rl78OcdInterface, Rl78Uart, SecurityId, UartOcd,
    },
    probe::{
        DebugProbe, DebugProbeError, DebugProbeInfo, DebugProbeSelector, ProbeCreationError,
        ProbeFactory, WireProtocol,
        list::{ProbeListItem, usb_probe_accessibility},
    },
};

const VID_FTDI: u16 = 0x0403;
const PID_FT232R: u16 = 0x6001;

const EP_IN: u8 = 0x81;
const EP_OUT: u8 = 0x02;
/// Every FTDI bulk-IN packet starts with two modem-status bytes.
const STATUS_BYTES: usize = 2;
const PACKET: usize = 64;

// FTDI vendor requests.
const SIO_RESET: u8 = 0;
const SIO_SET_MODEM_CTRL: u8 = 1;
const SIO_SET_FLOW_CTRL: u8 = 2;
const SIO_SET_BAUD_RATE: u8 = 3;
const SIO_SET_DATA: u8 = 4;
const SIO_SET_LATENCY_TIMER: u8 = 9;

/// SIO_SET_DATA: 8 data bits and 2 stop bits; parity is bits 8 to 10.
const LINE_8X2: u16 = 8 | (2 << 11);
const LINE_ODD: u16 = 1 << 8;
/// Bit 14 of SIO_SET_DATA holds TXD in a break.
const LINE_BREAK: u16 = 1 << 14;
/// The FT232R's baud clock; a divisor of 26 gives 115385 baud, 0.16 % off 115200.
const BAUD_CLOCK: u32 = 3_000_000;

const USB_TIMEOUT: Duration = Duration::from_millis(1000);

/// How long one IN transfer may sit before reporting "nothing yet". The latency timer is 1 ms,
/// so an idle FT232R answers within about that with status bytes only.
const POLL: Duration = Duration::from_millis(5);

/// Environment variable holding the security ID, as hex digits: 20 for the G15 and G23, 32 for
/// the F24.
pub const SECURITY_ID_ENV: &str = "PROBE_RS_RL78_SECURITY_ID";

fn usb_err(e: impl fmt::Display) -> Rl78Error {
    Rl78Error::Probe(DebugProbeError::Other(format!("FT232R: {e}")))
}

/// The FT232R as a byte pipe to TOOL0.
pub struct Ft232r {
    intf: Interface,
    ep_in: Endpoint<Bulk, In>,
    ep_out: Endpoint<Bulk, Out>,
    /// Bytes delivered by the bridge but not yet asked for. Kept, never dropped: a reply can
    /// share a USB packet with the start of whatever the target sends next.
    rx: VecDeque<u8>,
    /// SIO_SET_DATA's value without the break bit.
    line: u16,
}

impl fmt::Debug for Ft232r {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ft232r")
            .field("rx", &self.rx)
            .finish_non_exhaustive()
    }
}

impl Ft232r {
    fn open(info: &nusb::DeviceInfo) -> Result<Self, ProbeCreationError> {
        let device = info
            .open()
            .wait()
            .map_err(|e| ProbeCreationError::Usb(e.into()))?;
        let intf = device
            .detach_and_claim_interface(0)
            .wait()
            .map_err(|e| ProbeCreationError::Usb(e.into()))?;
        let ep_in = intf
            .endpoint::<Bulk, In>(EP_IN)
            .map_err(|e| ProbeCreationError::Usb(e.into()))?;
        let ep_out = intf
            .endpoint::<Bulk, Out>(EP_OUT)
            .map_err(|e| ProbeCreationError::Usb(e.into()))?;
        let mut link = Self {
            intf,
            ep_in,
            ep_out,
            rx: VecDeque::new(),
            line: LINE_8X2 | LINE_ODD,
        };
        link.configure()
            .map_err(|e| ProbeCreationError::Usb(std::io::Error::other(e.to_string())))?;
        Ok(link)
    }

    fn configure(&mut self) -> Result<(), Rl78Error> {
        self.ctrl(SIO_RESET, 0)?;
        self.set_line(115_200, true)?;
        self.ctrl(SIO_SET_FLOW_CTRL, 0)?;
        // Without this the link runs about 16 times slower; see the module comment.
        self.ctrl(SIO_SET_LATENCY_TIMER, 1)?;
        self.set_reset(false)
    }

    fn ctrl(&self, request: u8, value: u16) -> Result<(), Rl78Error> {
        let c = ControlOut {
            control_type: ControlType::Vendor,
            recipient: Recipient::Device,
            request,
            value,
            index: 0,
            data: &[],
        };
        self.intf
            .control_out(c, USB_TIMEOUT)
            .wait()
            .map_err(usb_err)
    }

    /// RTS is the reset buffer's output enable, DTR its input. The high byte enables each bit.
    fn modem(&self, rts: bool, dtr: bool) -> Result<(), Rl78Error> {
        self.ctrl(
            SIO_SET_MODEM_CTRL,
            0x0300 | u16::from(rts) << 1 | u16::from(dtr),
        )
    }

    /// Wait up to `timeout` for one IN packet and keep its payload. Returns whether any arrived.
    ///
    /// An unfinished transfer is left queued, not cancelled: cancelling races its completion and
    /// can lose a packet that was already on its way.
    fn pump(&mut self, timeout: Duration) -> Result<bool, Rl78Error> {
        while self.ep_in.pending() < 2 {
            self.ep_in.submit(Buffer::new(PACKET));
        }
        let Some(c) = self.ep_in.wait_next_complete(timeout) else {
            return Ok(false);
        };
        c.status.map_err(usb_err)?;
        let data = c.buffer[..c.actual_len].get(STATUS_BYTES..).unwrap_or(&[]);
        if !data.is_empty() {
            tracing::trace!(
                "FT232R IN: status {:02x?} data {data:02x?}",
                &c.buffer[..STATUS_BYTES.min(c.actual_len)]
            );
        }
        self.rx.extend(data);
        Ok(!data.is_empty())
    }
}

impl Rl78Uart for Ft232r {
    fn write(&mut self, data: &[u8]) -> Result<(), Rl78Error> {
        let mut b = Buffer::new(data.len());
        b.extend_from_slice(data);
        self.ep_out.submit(b);
        let c = self
            .ep_out
            .wait_next_complete(USB_TIMEOUT)
            .ok_or_else(|| usb_err("bulk write timed out"))?;
        c.status.map_err(usb_err)
    }

    fn read(&mut self, buf: &mut [u8], timeout: Duration) -> Result<usize, Rl78Error> {
        let deadline = Instant::now() + timeout;
        while self.rx.is_empty() {
            let left = deadline.saturating_duration_since(Instant::now());
            // Always look at least once, so a zero timeout still sees what has arrived.
            if !self.pump(left.max(POLL))? && left.is_zero() {
                return Ok(0);
            }
        }
        let n = buf.len().min(self.rx.len());
        for (d, s) in buf.iter_mut().zip(self.rx.drain(..n)) {
            *d = s;
        }
        Ok(n)
    }

    fn set_reset(&mut self, asserted: bool) -> Result<(), Rl78Error> {
        if asserted {
            self.modem(false, true)
        } else {
            // Tristate the buffer; the pull-up takes RESET high.
            self.modem(true, false)
        }
    }

    fn set_tool0_low(&mut self, low: bool) -> Result<(), Rl78Error> {
        self.ctrl(SIO_SET_DATA, self.line | if low { LINE_BREAK } else { 0 })
    }

    fn buffered(&self) -> usize {
        self.rx.len()
    }

    fn flush_input(&mut self) -> Result<(), Rl78Error> {
        let mut dropped = std::mem::take(&mut self.rx).len();
        // A quiet bridge answers with status-only packets; stop at the first.
        for _ in 0..8 {
            if !self.pump(POLL)? {
                break;
            }
            dropped += self.rx.len();
            self.rx.clear();
        }
        if dropped > 0 {
            tracing::debug!("rl78: flushed {dropped} stale byte(s)");
        }
        Ok(())
    }

    fn set_line(&mut self, baud: u32, odd_parity: bool) -> Result<(), Rl78Error> {
        let divisor = (BAUD_CLOCK + baud / 2) / baud;
        // Divisors 0 and 1 are special-cased to 3 and 2 Mbaud by the chip.
        if !(2..=0x3FFF).contains(&divisor) || (BAUD_CLOCK / divisor).abs_diff(baud) > baud / 50 {
            return Err(Rl78Error::Other(format!(
                "the FT232R cannot run at {baud} baud"
            )));
        }
        self.ctrl(SIO_SET_BAUD_RATE, divisor as u16)?;
        self.line = LINE_8X2 | if odd_parity { LINE_ODD } else { 0 };
        self.ctrl(SIO_SET_DATA, self.line)
    }
}

/// The COM-port debugger: the OCD protocol over a byte pipe to TOOL0. The link is the FT232R
/// for a real board; tests put a simulated target there instead.
#[derive(Debug)]
pub struct ComProbe<L = Ft232r> {
    ocd: UartOcd<L>,
}

impl<L: Rl78Uart> ComProbe<L> {
    /// A probe over `link`, unlocking with `security_id`.
    pub fn new(link: L, security_id: impl Into<SecurityId>) -> Self {
        Self {
            ocd: UartOcd::new(link, security_id),
        }
    }
}

impl<L: Rl78Uart + 'static> DebugProbe for ComProbe<L> {
    fn get_name(&self) -> &str {
        "RL78 COM port (FT232R)"
    }

    fn speed_khz(&self) -> u32 {
        115
    }

    fn set_speed(&mut self, _speed_khz: u32) -> Result<u32, DebugProbeError> {
        // The boot ROM fixes the rate at 115200 baud.
        Ok(115)
    }

    fn attach(&mut self) -> Result<(), DebugProbeError> {
        // The link is ready from open. Attaching to the target is the RL78 core's job, because it
        // resets the part and returns the register state the monitor reports on entry.
        Ok(())
    }

    fn detach(&mut self) -> Result<(), probe_rs::Error> {
        // Leave RESET released so the part keeps running (or stays in the monitor) on its own.
        self.ocd
            .link_mut()
            .set_reset(false)
            .map_err(probe_rs::Error::from)
    }

    fn target_reset(&mut self) -> Result<(), DebugProbeError> {
        self.target_reset_assert()?;
        std::thread::sleep(Duration::from_millis(5));
        self.target_reset_deassert()
    }

    fn target_reset_assert(&mut self) -> Result<(), DebugProbeError> {
        self.ocd
            .link_mut()
            .set_reset(true)
            .map_err(|e| DebugProbeError::Other(e.to_string()))
    }

    fn target_reset_deassert(&mut self) -> Result<(), DebugProbeError> {
        self.ocd
            .link_mut()
            .set_reset(false)
            .map_err(|e| DebugProbeError::Other(e.to_string()))
    }

    fn select_protocol(&mut self, protocol: WireProtocol) -> Result<(), DebugProbeError> {
        // Neither SWD nor JTAG: the RL78 debugger speaks a UART protocol on TOOL0.
        Err(DebugProbeError::UnsupportedProtocol(protocol))
    }

    fn active_protocol(&self) -> Option<WireProtocol> {
        None
    }

    fn try_get_rl78_interface(&mut self) -> Result<&mut dyn Rl78OcdInterface, DebugProbeError> {
        Ok(&mut self.ocd)
    }

    fn has_rl78_interface(&self) -> bool {
        true
    }

    fn into_probe(self: Box<Self>) -> Box<dyn DebugProbe> {
        self
    }
}

/// Lists and opens COM-port debuggers.
#[derive(Debug)]
pub struct ComProbeFactory;

impl fmt::Display for ComProbeFactory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RL78 COM")
    }
}

/// Any FT232R qualifies: an FPB's bridge carries the stock FTDI identity, so a generic FTDI cable
/// is listed too. Opening one that is not wired to an RL78 fails at attach.
fn is_ft232r(d: &nusb::DeviceInfo) -> bool {
    d.vendor_id() == VID_FTDI && d.product_id() == PID_FT232R
}

pub(crate) fn security_id() -> Result<SecurityId, ProbeCreationError> {
    match std::env::var(SECURITY_ID_ENV) {
        Err(_) => Ok(SecurityId::BLANK),
        Ok(hex) => SecurityId::parse(&hex).ok_or(ProbeCreationError::Other(
            "PROBE_RS_RL78_SECURITY_ID must be hex digits",
        )),
    }
}

impl ProbeFactory for ComProbeFactory {
    fn open(&self, selector: &DebugProbeSelector) -> Result<Box<dyn DebugProbe>, DebugProbeError> {
        let device = nusb::list_devices()
            .wait()
            .map_err(|e| ProbeCreationError::Usb(e.into()))?
            .filter(is_ft232r)
            .find(|d| selector.matches(d))
            .ok_or(ProbeCreationError::NotFound)?;
        let link = Ft232r::open(&device)?;
        Ok(Box::new(ComProbe::new(link, security_id()?)))
    }

    fn list_probes(&self) -> Vec<ProbeListItem> {
        match nusb::list_devices().wait() {
            Ok(devices) => devices
                .filter(is_ft232r)
                .map(|d| ProbeListItem {
                    accessibility: usb_probe_accessibility(&d),
                    info: DebugProbeInfo::new(
                        "RL78 COM (FT232R)",
                        d.vendor_id(),
                        d.product_id(),
                        d.serial_number().map(Into::into),
                        &ComProbeFactory,
                        None,
                        false,
                    ),
                })
                .collect(),
            Err(e) => {
                tracing::warn!("error listing FT232R devices: {e}");
                vec![]
            }
        }
    }
}
