//! Which console the title runs on. Titles pick settings (resolution,
//! memory budgets) by it, so the user chooses; Series X unless told.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};

const GIB: usize = 1 << 30;
const MIB: usize = 1 << 20;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Console {
    #[default]
    SeriesX,
    SeriesS,
}

impl Console {
    /// Title memory in bytes: (GPU-optimal, standard). Series X in the
    /// advanced configuration; Series S has one range, counted as standard
    /// (7,776 MiB by default, overridable via `VICTORY_CONSOLE_MEMORY_MB`).
    pub fn title_memory(self) -> (usize, usize) {
        match self {
            Console::SeriesX => (10 * GIB, 7 * GIB / 2),
            Console::SeriesS => {
                static OVERRIDE: OnceLock<Option<usize>> = OnceLock::new();
                let custom = *OVERRIDE.get_or_init(|| {
                    std::env::var("VICTORY_CONSOLE_MEMORY_MB")
                        .ok()
                        .and_then(|v| v.trim().parse::<usize>().ok())
                        .filter(|&mb| mb >= 4096)
                        .and_then(|mb| mb.checked_mul(MIB))
                });
                (0, custom.unwrap_or(7_776 * MIB))
            }
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Console::SeriesX => "Xbox Series X",
            Console::SeriesS => "Xbox Series S",
        }
    }
}

static SERIES_S: AtomicBool = AtomicBool::new(false);

/// Set before the title starts.
pub fn set(console: Console) {
    SERIES_S.store(console == Console::SeriesS, Ordering::Relaxed);
}

pub fn current() -> Console {
    if SERIES_S.load(Ordering::Relaxed) {
        Console::SeriesS
    } else {
        Console::SeriesX
    }
}
