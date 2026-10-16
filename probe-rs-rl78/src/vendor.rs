//! Renesas RL78 as a probe-rs vendor: chip detection.

use std::fmt;

use probe_rs::{
    Error,
    config::{DebugSequence, Registry},
    probe::Probe,
    vendor::Vendor,
};
use probe_rs_target::{Chip, CoreType};

/// Renesas RL78.
#[derive(Debug)]
pub struct RenesasRl78;

impl fmt::Display for RenesasRl78 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Renesas RL78")
    }
}

impl Vendor for RenesasRl78 {
    fn try_create_debug_sequence(&self, _chip: &Chip) -> Option<DebugSequence> {
        // The default RL78 sequence is chosen by architecture.
        None
    }

    /// Detection is limited. The RL78/G15's debugger has no identity register: no IDCODE, no
    /// ROM table, and Protocol B has no signature command. So this proves an RL78 debug monitor
    /// answers (it attaches, which resets the part into it), and names the chip only when the
    /// registry leaves no choice.
    fn try_detect_chip_from_probe(
        &self,
        registry: &Registry,
        probe: &mut Probe,
    ) -> Result<Option<String>, Error> {
        if !probe.has_rl78_interface() {
            return Ok(None);
        }
        probe.try_get_rl78_interface()?.attach()?;

        let candidates: Vec<&str> = registry
            .families()
            .iter()
            .flat_map(|family| family.variants.iter())
            .filter(|chip| chip.cores.iter().any(|c| c.core_type == CoreType::Rl78))
            .map(|chip| chip.name.as_str())
            .collect();
        match candidates[..] {
            [only] => Ok(Some(only.to_owned())),
            _ => {
                tracing::warn!(
                    "An RL78 debug monitor answered, but the RL78/G15 class has no identity \
                     register to tell {} candidates apart. Name the chip with --chip.",
                    candidates.len()
                );
                Ok(None)
            }
        }
    }
}
