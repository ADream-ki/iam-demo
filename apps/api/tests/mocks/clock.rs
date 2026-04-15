//! Mock clock implementation

use chrono::{DateTime, Utc};
use std::sync::{Arc, Mutex};

use iam_api::domain::ports::Clock;

/// Mock clock that can be controlled for testing
#[derive(Debug, Default)]
pub struct MockClock {
    now: Arc<Mutex<Option<DateTime<Utc>>>>,
}

impl MockClock {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_now(&self, now: DateTime<Utc>) {
        let mut current = self.now.lock().unwrap();
        *current = Some(now);
    }
}

impl Clock for MockClock {
    fn now(&self) -> DateTime<Utc> {
        let current = self.now.lock().unwrap();
        current.unwrap_or_else(Utc::now)
    }
}

/// Real clock for production use
pub struct RealClock;

impl Clock for RealClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}
