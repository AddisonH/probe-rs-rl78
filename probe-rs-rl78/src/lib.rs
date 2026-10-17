//! Renesas RL78 support for probe-rs.
//!
//! The RL78 architecture itself (the on-chip-debug protocol, the core driver) is part of probe-rs,
//! because plugins cannot add architectures. This crate carries the rest: the COM-port probe found
//! on Renesas Fast Prototyping Boards, and RL78 target descriptions.

use probe_rs::plugin;
use probe_rs_target::ChipFamily;

pub mod com;
pub mod vendor;

/// Register the RL78 probes and targets with probe-rs.
pub fn register_plugin() {
    let targets = targets();
    plugin::register_plugin(plugin::Plugin {
        vendors: &[&vendor::RenesasRl78],
        image_formats: &[],
        targets: &targets,
        probe_drivers: &[&com::ComProbeFactory],
    });
}

const TARGETS: &[&str] = &[
    include_str!("../targets/RL78_G15.yaml"),
    include_str!("../targets/RL78_G23.yaml"),
];

fn targets() -> Vec<ChipFamily> {
    TARGETS
        .iter()
        .map(|yaml| {
            yaml_serde::from_str(yaml).expect("Built-in RL78 target is invalid. This is a bug.")
        })
        .collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn targets_parse() {
        let families = super::targets();
        assert_eq!(families[0].variants[0].name, "R5F12068");
    }
}
