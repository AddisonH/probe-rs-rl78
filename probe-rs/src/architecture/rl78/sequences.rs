//! Per-family behaviour for RL78 targets.

use std::{fmt::Debug, ops::Range, sync::Arc};

use super::Rl78Flash;
use crate::flashing::{DebugFlashSequence, FlashVerify};

/// Debug sequences for RL78 targets.
pub trait Rl78DebugSequence: Send + Sync + Debug {
    /// Return the host-side flash sequence implementation, if any.
    fn debug_flash_sequence(&self) -> Option<Arc<dyn DebugFlashSequence>> {
        None
    }

    /// Return the fast flash verification implementation if one exists.
    fn flash_verify_sequence(&self) -> Option<Arc<dyn FlashVerify>> {
        None
    }

    /// The code flash the mirror shows at `F0000H` plus its address, which the monitor reads
    /// directly; the rest of code flash takes a routine and borrowed RAM.
    fn code_flash_mirror(&self) -> Range<u32> {
        0..0
    }
}

/// The default sequence, which is the RL78/G15 class.
#[derive(Debug)]
pub struct DefaultRl78Sequence;

impl DefaultRl78Sequence {
    /// Create the default sequence.
    pub fn create() -> Arc<dyn Rl78DebugSequence> {
        Arc::new(Self)
    }
}

impl Rl78DebugSequence for DefaultRl78Sequence {
    fn debug_flash_sequence(&self) -> Option<Arc<dyn DebugFlashSequence>> {
        Some(Arc::new(Rl78Flash::from_env()))
    }

    /// The G15's mirror starts where the 2nd SFRs end, `F0800H`, and runs to the end
    /// of its largest flash.
    fn code_flash_mirror(&self) -> Range<u32> {
        0x0800..0x2000
    }
}

/// The RL78/G23 class.
#[derive(Debug)]
pub struct G23Rl78Sequence;

impl G23Rl78Sequence {
    /// Create the sequence.
    pub fn create() -> Arc<dyn Rl78DebugSequence> {
        Arc::new(Self)
    }
}

impl Rl78DebugSequence for G23Rl78Sequence {
    fn debug_flash_sequence(&self) -> Option<Arc<dyn DebugFlashSequence>> {
        Some(Arc::new(Rl78Flash::g23()))
    }
}

/// The RL78/F24. Flash programming is not supported yet.
#[derive(Debug)]
pub struct F24Rl78Sequence;

impl F24Rl78Sequence {
    /// Create the sequence.
    pub fn create() -> Arc<dyn Rl78DebugSequence> {
        Arc::new(Self)
    }
}

impl Rl78DebugSequence for F24Rl78Sequence {}
