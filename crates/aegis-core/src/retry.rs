use std::time::Duration;

/// Bounded exponential backoff.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    pub base: Duration,
    pub max_delay: Duration,
    pub max_attempts: u32,
}

impl RetryPolicy {
    pub fn new(max_attempts: u32) -> Self {
        Self {
            base: Duration::from_secs(1),
            max_delay: Duration::from_secs(60),
            max_attempts,
        }
    }

    /// Delay before attempt `n` (1-based), or `None` once attempts are exhausted.
    // ponytail: no jitter; one client per machine so thundering-herd does not apply.
    pub fn delay(&self, attempt: u32) -> Option<Duration> {
        if attempt == 0 || attempt > self.max_attempts {
            return None;
        }
        let factor = 2u32.saturating_pow(attempt - 1);
        Some(self.base.saturating_mul(factor).min(self.max_delay))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grows_and_caps() {
        let p = RetryPolicy::new(10);
        let secs: Vec<u64> = (1..=10).map(|n| p.delay(n).unwrap().as_secs()).collect();
        assert_eq!(secs, [1, 2, 4, 8, 16, 32, 60, 60, 60, 60]);
        assert_eq!(p.delay(11), None);
        assert_eq!(p.delay(0), None);
        assert_eq!(
            RetryPolicy::new(40).delay(40),
            Some(Duration::from_secs(60))
        );
    }
}
