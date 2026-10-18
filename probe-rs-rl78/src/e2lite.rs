//! The Renesas E2 Lite as an RL78 debug probe.
//!
//! The probe takes requests on bulk OUT and answers each on bulk IN. A request starts with a
//! channel, which the reply repeats: `28H` for the probe's own management, `00H FFH` for its
//! debugger, `00H CCH` for its mode, and `00H 01H` to relay bytes to the target's monitor over
//! TOOL0. A reply to a `00H` channel starts with a status, `00H` for success. The probe enters
//! and unlocks the monitor itself, given the security ID, and does so again after every halt.
//! It needs no firmware from the host.

use std::{fmt, time::Duration};

use nusb::{
    Endpoint, Interface, MaybeFuture,
    transfer::{Buffer, Bulk, In, Out},
};
use probe_rs::{
    architecture::rl78::{
        communication_interface::{Rl78Error, Rl78OcdInterface, SecurityId},
        protocol::CodecError,
        relay::{RelayOcd, Rl78Relay},
    },
    probe::{
        DebugProbe, DebugProbeError, DebugProbeInfo, DebugProbeSelector, ProbeCreationError,
        ProbeFactory, WireProtocol,
        list::{ProbeListItem, usb_probe_accessibility},
    },
};

use crate::com::security_id;

const VID: u16 = 0x045B;
const PID: u16 = 0x82A0;
const EP_IN: u8 = 0x81;
const EP_OUT: u8 = 0x02;
/// The largest reply asked for: a 256-byte relay and its header fit with room to spare.
const REPLY_MAX: usize = 4096;
const USB_TIMEOUT: Duration = Duration::from_secs(5);

const POWER_ON: &[u8] = &[0x28, 0x0C, 0x01, 0x01];
const POWER_OFF: &[u8] = &[0x28, 0x0C, 0x00, 0x00];
/// The probe's debugger; `00H FFH` requests go unanswered until it is started and given a mode.
const START: &[u8] = &[0x28, 0x1D, 0x01];
const STOP: &[u8] = &[0x28, 0x1D, 0x00];
const MODE_DEBUG: &[u8] = &[0x00, 0xCC, 0x00, 0x01, 0x04];
const MODE_IDLE: &[u8] = &[0x00, 0xCC, 0x00, 0x01, 0x00];
const VERSION: &[u8] = &[0x00, 0xFF, 0x00, 0x01];
const SET_ID: &[u8] = &[0x00, 0xFF, 0x00, 0x2C];
const CONNECT: &[u8] = &[0x00, 0xFF, 0x00, 0x0B, 0x23];
const STATE: &[u8] = &[0x00, 0xFF, 0x00, 0x07];
const HALT: &[u8] = &[0x00, 0xFF, 0x00, 0x09];
const WATCH_RUN: &[u8] = &[0x00, 0xFF, 0x00, 0x0A, 0x02, 0xFF];
/// What the vendor's debugger sends to end a session, before going idle.
const DISCONNECT: [&[u8]; 3] = [
    &[0x00, 0xFF, 0x00, 0x0A, 0x01, 0xFF],
    &[0x00, 0xFF, 0x00, 0x0B, 0x01],
    &[0x00, 0xFF, 0x00, 0x0A, 0x00, 0xFF],
];
const RELAY: [u8; 2] = [0x00, 0x01];
/// [`STATE`]'s reply byte 4.
const HALTED: u8 = 2;
/// The probe firmware this driver was written against.
const TESTED_FIRMWARE: &str = "V7.06";

fn usb_err(e: impl fmt::Display) -> Rl78Error {
    Rl78Error::Probe(DebugProbeError::Other(format!("E2 Lite: {e}")))
}

/// The E2 Lite's USB link.
pub struct E2Lite {
    _intf: Interface,
    ep_in: Endpoint<Bulk, In>,
    ep_out: Endpoint<Bulk, Out>,
}

impl fmt::Debug for E2Lite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("E2Lite").finish_non_exhaustive()
    }
}

impl E2Lite {
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
        Ok(Self {
            _intf: intf,
            ep_in,
            ep_out,
        })
    }

    /// One request and its reply.
    ///
    /// A reply that did not come in time is left queued, not cancelled, and is discarded when
    /// it arrives: the probe answers once it is done waiting on the target.
    fn xfer(&mut self, req: &[u8], timeout: Duration) -> Result<Vec<u8>, Rl78Error> {
        while self.ep_in.pending() > 0 {
            let Some(late) = self.ep_in.wait_next_complete(Duration::ZERO) else {
                break;
            };
            tracing::debug!(
                "E2 Lite: discarding a late reply {:02x?}",
                &late.buffer[..late.actual_len]
            );
        }
        let mut b = Buffer::new(req.len());
        b.extend_from_slice(req);
        self.ep_out.submit(b);
        self.ep_out
            .wait_next_complete(USB_TIMEOUT)
            .ok_or_else(|| usb_err("bulk write timed out"))?
            .status
            .map_err(usb_err)?;
        if self.ep_in.pending() == 0 {
            self.ep_in.submit(Buffer::new(REPLY_MAX));
        }
        let Some(c) = self.ep_in.wait_next_complete(timeout) else {
            return Err(Rl78Error::Timeout {
                op: "E2 Lite request",
                got: 0,
                expected: 1,
            });
        };
        c.status.map_err(usb_err)?;
        let reply = c.buffer[..c.actual_len].to_vec();
        tracing::trace!("E2 Lite: {req:02x?} -> {reply:02x?}");
        Ok(reply)
    }

    /// A request answered by its status: `28H` replies repeat the request's first two bytes,
    /// the others start with `00H`.
    fn command(&mut self, req: &[u8]) -> Result<Vec<u8>, Rl78Error> {
        let reply = self.xfer(req, USB_TIMEOUT)?;
        let ok = if req[0] == 0x28 {
            reply.starts_with(&req[..2])
        } else {
            reply.first() == Some(&0)
        };
        if !ok {
            return Err(usb_err(format!("request {req:02x?} failed: {reply:02x?}")));
        }
        Ok(reply)
    }

    /// Leave whatever an earlier session left the probe in. Its debugger requests go unanswered
    /// unless it was connected, so the first that times out ends them.
    fn disconnect(&mut self) -> Result<(), Rl78Error> {
        for req in DISCONNECT.into_iter().chain([MODE_IDLE]) {
            match self.xfer(req, Duration::from_secs(1)) {
                Ok(_) => {}
                Err(Rl78Error::Timeout { .. }) => break,
                Err(e) => return Err(e),
            }
        }
        self.command(POWER_OFF)?;
        self.command(STOP)?;
        Ok(())
    }
}

impl Rl78Relay for E2Lite {
    fn connect(&mut self, security_id: &[u8]) -> Result<(), Rl78Error> {
        self.disconnect()?;
        self.command(POWER_ON)?;
        self.command(START)?;
        self.command(MODE_DEBUG)?;
        let version = self.command(VERSION)?;
        let version = String::from_utf8_lossy(&version[4..]);
        let version = version.trim_end_matches('\0').trim();
        if !version.starts_with(TESTED_FIRMWARE) {
            tracing::warn!(
                "E2 Lite firmware {version}: probe-rs was tested with {TESTED_FIRMWARE} only"
            );
        }
        self.command(&[SET_ID, security_id].concat())?;
        match self.xfer(CONNECT, USB_TIMEOUT)?.first() {
            Some(0) => Ok(()),
            // 03H when the monitor refused the ID.
            Some(3) => Err(Rl78Error::SecurityIdRejected),
            _ => Err(Rl78Error::NoMonitor),
        }
    }

    fn relay(&mut self, req: &[u8], n: usize, timeout: Duration) -> Result<Vec<u8>, Rl78Error> {
        let count = u16::try_from(n).expect("a monitor reply fits the count");
        let msg = [&RELAY[..], &count.to_be_bytes(), req].concat();
        let reply = self.xfer(&msg, timeout + Duration::from_secs(1))?;
        if !reply.starts_with(&RELAY) || reply.len() != n + RELAY.len() {
            return Err(CodecError::Protocol("relay").into());
        }
        Ok(reply[RELAY.len()..].to_vec())
    }

    fn running(&mut self) -> Result<(), Rl78Error> {
        self.command(WATCH_RUN).map(|_| ())
    }

    fn halt(&mut self) -> Result<(), Rl78Error> {
        self.command(HALT).map(|_| ())
    }

    fn halted(&mut self) -> Result<bool, Rl78Error> {
        Ok(self.command(STATE)?.get(4) == Some(&HALTED))
    }
}

/// The E2 Lite debugger.
#[derive(Debug)]
pub struct E2LiteProbe {
    ocd: RelayOcd<E2Lite>,
}

impl DebugProbe for E2LiteProbe {
    fn get_name(&self) -> &str {
        "Renesas E2 Lite"
    }

    fn speed_khz(&self) -> u32 {
        115
    }

    fn set_speed(&mut self, _speed_khz: u32) -> Result<u32, DebugProbeError> {
        Ok(115)
    }

    fn attach(&mut self) -> Result<(), DebugProbeError> {
        // Connecting powers the target and enters its monitor: the RL78 core's attach.
        Ok(())
    }

    fn detach(&mut self) -> Result<(), probe_rs::Error> {
        // The probe stays connected, so the program keeps running or stays halted.
        Ok(())
    }

    fn target_reset(&mut self) -> Result<(), DebugProbeError> {
        Err(DebugProbeError::NotImplemented {
            function_name: "target_reset",
        })
    }

    fn target_reset_assert(&mut self) -> Result<(), DebugProbeError> {
        Err(DebugProbeError::NotImplemented {
            function_name: "target_reset_assert",
        })
    }

    fn target_reset_deassert(&mut self) -> Result<(), DebugProbeError> {
        Err(DebugProbeError::NotImplemented {
            function_name: "target_reset_deassert",
        })
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

/// Lists and opens E2 Lites.
#[derive(Debug)]
pub struct E2LiteProbeFactory;

impl fmt::Display for E2LiteProbeFactory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("E2 Lite")
    }
}

fn is_e2lite(d: &nusb::DeviceInfo) -> bool {
    d.vendor_id() == VID && d.product_id() == PID
}

impl ProbeFactory for E2LiteProbeFactory {
    fn open(&self, selector: &DebugProbeSelector) -> Result<Box<dyn DebugProbe>, DebugProbeError> {
        let device = nusb::list_devices()
            .wait()
            .map_err(|e| ProbeCreationError::Usb(e.into()))?
            .filter(is_e2lite)
            .find(|d| selector.matches(d))
            .ok_or(ProbeCreationError::NotFound)?;
        let link = E2Lite::open(&device)?;
        let id: SecurityId = security_id()?;
        Ok(Box::new(E2LiteProbe {
            ocd: RelayOcd::new(link, id),
        }))
    }

    fn list_probes(&self) -> Vec<ProbeListItem> {
        match nusb::list_devices().wait() {
            Ok(devices) => devices
                .filter(is_e2lite)
                .map(|d| ProbeListItem {
                    accessibility: usb_probe_accessibility(&d),
                    info: DebugProbeInfo::new(
                        "Renesas E2 Lite",
                        d.vendor_id(),
                        d.product_id(),
                        d.serial_number().map(Into::into),
                        &E2LiteProbeFactory,
                        None,
                        false,
                    ),
                })
                .collect(),
            Err(e) => {
                tracing::warn!("error listing E2 Lite devices: {e}");
                vec![]
            }
        }
    }
}
