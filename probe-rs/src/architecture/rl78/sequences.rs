//! Per-family behaviour for RL78 targets.

use std::{fmt::Debug, sync::Arc};

use super::Rl78Flash;
use crate::flashing::{DebugFlashSequence, FlashVerify};

/// Debug sequences for RL78 targets.
///
/// The RL78/G15 class programs flash by self-programming ([`Rl78Flash`]). Other OCD classes
/// (macro kinds 2 and 4, the R7F10x parts) are expected to differ in the call gate, the step
/// mechanism and the RAM they borrow, and those differences will live here.
pub trait Rl78DebugSequence: Send + Sync + Debug {
    /// Return the host-side flash sequence implementation, if any.
    fn debug_flash_sequence(&self) -> Option<Arc<dyn DebugFlashSequence>> {
        None
    }

    /// Return the fast flash verification implementation if one exists.
    fn flash_verify_sequence(&self) -> Option<Arc<dyn FlashVerify>> {
        None
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
        Some(Arc::new(Rl78Flash))
    }
}
