//! Renesas RL78 as a probe-rs vendor: chip detection.

use std::fmt;

use probe_rs::{
    Error,
    architecture::rl78::{
        communication_interface::Rl78Error,
        sequences::{F24Rl78Sequence, G23Rl78Sequence},
    },
    config::{DebugSequence, Registry},
    probe::Probe,
    vendor::Vendor,
};
use probe_rs_target::{Chip, CoreAccessOptions, Rl78Monitor};

/// Renesas RL78.
#[derive(Debug)]
pub struct RenesasRl78;

impl fmt::Display for RenesasRl78 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Renesas RL78")
    }
}

impl Vendor for RenesasRl78 {
    fn try_create_debug_sequence(&self, chip: &Chip) -> Option<DebugSequence> {
        // The default RL78 sequence, the G15's, is chosen by architecture.
        chip.cores
            .iter()
            .find_map(|core| match &core.core_access_options {
                CoreAccessOptions::Rl78(o) => match o.monitor {
                    Rl78Monitor::G15 => None,
                    Rl78Monitor::G23 => Some(DebugSequence::Rl78(G23Rl78Sequence::create())),
                    Rl78Monitor::F24 => Some(DebugSequence::Rl78(F24Rl78Sequence::create())),
                },
                _ => None,
            })
    }

    /// Detection is limited. RL78 debug monitors have no identity register: no IDCODE, no ROM
    /// table. So this finds which monitor answers (an attach resets the part into it) and names
    /// the chip only when the registry has one with that monitor.
    fn try_detect_chip_from_probe(
        &self,
        registry: &Registry,
        probe: &mut Probe,
    ) -> Result<Option<String>, Error> {
        if !probe.has_rl78_interface() {
            return Ok(None);
        }
        let interface = probe.try_get_rl78_interface()?;
        let mut found = None;
        for monitor in [Rl78Monitor::G15, Rl78Monitor::G23, Rl78Monitor::F24] {
            // Each probe speaks to some monitors only.
            if interface.set_monitor(monitor).is_err() {
                continue;
            }
            match interface.attach() {
                Ok(_) => {
                    found = Some(monitor);
                    break;
                }
                Err(Rl78Error::NoMonitor) => continue,
                Err(e) => return Err(e.into()),
            }
        }
        let Some(monitor) = found else {
            return Ok(None);
        };

        let candidates: Vec<&str> = registry
            .families()
            .iter()
            .flat_map(|family| family.variants.iter())
            .filter(|chip| {
                chip.cores.iter().any(|c| {
                    matches!(&c.core_access_options,
                        CoreAccessOptions::Rl78(o) if o.monitor == monitor)
                })
            })
            .map(|chip| chip.name.as_str())
            .collect();
        match candidates[..] {
            [only] => Ok(Some(only.to_owned())),
            _ => {
                tracing::warn!(
                    "An RL78 {monitor:?} debug monitor answered, but it has no identity register \
                     to tell {} candidates apart. Name the chip with --chip.",
                    candidates.len()
                );
                Ok(None)
            }
        }
    }
}
