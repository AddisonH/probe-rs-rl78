//! The on-chip debugger through a probe that relays bytes to the monitor, and enters, unlocks
//! and halts it by itself: the E2 Lite.

use std::{
    fmt,
    time::{Duration, Instant},
};

use probe_rs_target::Rl78Monitor;

use super::communication_interface::{
    REPLY_TIMEOUT, Rl78Error, Rl78OcdInterface, SecurityId, check_f_segment,
};
use super::f24;
use super::g23::{self, MonitorLink};
use super::protocol::Sync;

/// What the debugger needs of such a probe.
pub trait Rl78Relay: Send + fmt::Debug {
    /// Power the target, enter its monitor and unlock it with `security_id`. The target is
    /// then halted.
    fn connect(&mut self, security_id: &[u8]) -> Result<(), Rl78Error>;

    /// Send `req` to the monitor and return the `n` bytes of its reply.
    fn relay(&mut self, req: &[u8], n: usize, timeout: Duration) -> Result<Vec<u8>, Rl78Error>;

    /// After the monitor's run command: have the probe watch for its next entry.
    fn running(&mut self) -> Result<(), Rl78Error>;

    /// Stop the program. The probe unlocks the monitor again, as it does on every entry.
    fn halt(&mut self) -> Result<(), Rl78Error>;

    /// Whether the target is in the monitor.
    fn halted(&mut self) -> Result<bool, Rl78Error>;
}

/// The on-chip debugger over an [`Rl78Relay`].
#[derive(Debug)]
pub struct RelayOcd<L> {
    link: L,
    monitor: Rl78Monitor,
    security_id: SecurityId,
}

impl<L: Rl78Relay> RelayOcd<L> {
    /// Wrap a link. `security_id` unlocks every session.
    pub fn new(link: L, security_id: impl Into<SecurityId>) -> Self {
        Self {
            link,
            monitor: Rl78Monitor::F24,
            security_id: security_id.into(),
        }
    }

    /// The link, for the probe that owns it.
    pub fn link_mut(&mut self) -> &mut L {
        &mut self.link
    }

    fn wait_halted(&mut self, op: &'static str) -> Result<(), Rl78Error> {
        let deadline = Instant::now() + REPLY_TIMEOUT;
        while !self.link.halted()? {
            if Instant::now() > deadline {
                return Err(Rl78Error::Timeout {
                    op,
                    got: 0,
                    expected: 1,
                });
            }
        }
        Ok(())
    }
}

impl<L: Rl78Relay> MonitorLink for RelayOcd<L> {
    fn transact(
        &mut self,
        req: &[u8],
        n: usize,
        op: &'static str,
        timeout: Duration,
    ) -> Result<Vec<u8>, Rl78Error> {
        tracing::trace!("rl78 {op}: relay {req:02x?}");
        self.link.relay(req, n, timeout)
    }
}

impl<L: Rl78Relay> Rl78OcdInterface for RelayOcd<L> {
    fn set_monitor(&mut self, monitor: Rl78Monitor) -> Result<(), Rl78Error> {
        if monitor != Rl78Monitor::F24 {
            return Err(Rl78Error::Unsupported(
                "this part's debug monitor on this probe",
            ));
        }
        self.monitor = monitor;
        Ok(())
    }

    fn monitor(&self) -> Rl78Monitor {
        self.monitor
    }

    fn attach(&mut self) -> Result<Sync, Rl78Error> {
        let id = self.security_id()?;
        self.link.connect(&id)?;
        g23::expect(self, &[g23::VERSION], &f24::VERSION_REPLY, "version").map_err(
            |e| match e {
                Rl78Error::Timeout { .. } | Rl78Error::Codec(_) => Rl78Error::NoMonitor,
                e => e,
            },
        )?;
        Ok(Sync::default())
    }

    fn unlock(&mut self) -> Result<(), Rl78Error> {
        Ok(())
    }

    fn security_id(&self) -> Result<Vec<u8>, Rl78Error> {
        self.security_id.for_monitor(self.monitor)
    }

    fn read_mem(&mut self, address: u32, data: &mut [u8]) -> Result<(), Rl78Error> {
        check_f_segment(address, data.len())?;
        g23::read(self, address, data)
    }

    fn write_mem(&mut self, address: u32, data: &[u8]) -> Result<(), Rl78Error> {
        check_f_segment(address, data.len())?;
        g23::write(self, address, data)
    }

    fn call_stub(&mut self, timeout: Duration) -> Result<(), Rl78Error> {
        g23::call(self, &f24::VERSION_REPLY, timeout)
    }

    fn read_far(&mut self, address: u32, data: &mut [u8]) -> Result<(), Rl78Error> {
        f24::read_far(self, address, data)
    }

    fn execute(&mut self, _regs: Sync, single_step: bool) -> Result<Option<Sync>, Rl78Error> {
        g23::write(self, g23::STEP_ENABLE, &[u8::from(single_step)])?;
        g23::run(self)?;
        if single_step {
            self.wait_halted("step")?;
            return Ok(Some(Sync::default()));
        }
        self.link.running()?;
        Ok(None)
    }

    fn halt(&mut self) -> Result<Sync, Rl78Error> {
        self.link.halt()?;
        self.wait_halted("halt")?;
        Ok(Sync::default())
    }

    fn reset(&mut self) -> Result<(), Rl78Error> {
        Err(Rl78Error::Unsupported(
            "a reset into the program on this probe",
        ))
    }

    fn poll_stopped(&mut self) -> Result<Option<Sync>, Rl78Error> {
        Ok(self.link.halted()?.then(Sync::default))
    }
}
