//! Circuit Breaker pattern for upstream services.
//!
//! States:
//! - **Closed**: normal operation, requests flow through. Failures increment the counter.
//! - **Open**: all requests short-circuit with an error. After `recovery_timeout` → HalfOpen.
//! - **HalfOpen**: limited probe requests allowed. Success → Closed, Failure → Open.
//!
//! Thread-safe via `Mutex<CircuitState>` per upstream.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

// ─── Configuration ──────────────────────────────────────────────────

/// Configuration for a circuit breaker instance.
#[derive(Debug, Clone)]
pub struct CircuitBreakerConfig {
    /// Number of consecutive failures before opening the circuit.
    pub failure_threshold: u32,
    /// Time to stay in Open state before transitioning to HalfOpen.
    pub recovery_timeout: Duration,
    /// Maximum probe requests allowed in HalfOpen state.
    pub half_open_max_requests: u32,
    /// Consecutive successes in HalfOpen required to close the circuit.
    pub success_threshold: u32,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            recovery_timeout: Duration::from_secs(30),
            half_open_max_requests: 3,
            success_threshold: 2,
        }
    }
}

// ─── State machine ──────────────────────────────────────────────────

/// The three states of a circuit breaker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum State {
    Closed,
    Open,
    HalfOpen,
}

/// Internal mutable state for one upstream circuit.
#[derive(Debug)]
struct CircuitState {
    state: State,
    consecutive_failures: u32,
    consecutive_successes: u32,
    half_open_in_flight: u32,
    /// When the circuit was opened (used for recovery_timeout).
    opened_at: Option<Instant>,
    /// Counters
    total_requests: u64,
    total_failures: u64,
    total_short_circuits: u64,
}

impl CircuitState {
    fn new() -> Self {
        Self {
            state: State::Closed,
            consecutive_failures: 0,
            consecutive_successes: 0,
            half_open_in_flight: 0,
            opened_at: None,
            total_requests: 0,
            total_failures: 0,
            total_short_circuits: 0,
        }
    }
}

// ─── Circuit Breaker ─────────────────────────────────────────────────

/// Error returned when the circuit is open.
#[derive(Debug, Clone)]
pub struct CircuitOpenError {
    pub upstream: String,
    pub state: State,
    pub retry_after: Option<Duration>,
}

impl std::fmt::Display for CircuitOpenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "circuit breaker {:?} for upstream '{}'",
            self.state, self.upstream
        )
    }
}

impl std::error::Error for CircuitOpenError {}

/// Thread-safe circuit breaker manager for multiple upstreams.
pub struct CircuitBreaker {
    config: CircuitBreakerConfig,
    circuits: Mutex<HashMap<String, CircuitState>>,
}

impl CircuitBreaker {
    /// Create a new circuit breaker with the given config.
    pub fn new(config: CircuitBreakerConfig) -> Self {
        Self {
            config,
            circuits: Mutex::new(HashMap::new()),
        }
    }

    /// Check if a request to `upstream` is allowed.
    ///
    /// Returns `Ok(())` if the request may proceed, or `Err(CircuitOpenError)` if blocked.
    pub fn check(&self, upstream: &str) -> Result<(), CircuitOpenError> {
        let mut map = self.circuits.lock().unwrap();
        let state = map
            .entry(upstream.to_string())
            .or_insert_with(CircuitState::new);

        // Possibly transition Open → HalfOpen
        if state.state == State::Open {
            if let Some(opened_at) = state.opened_at {
                if opened_at.elapsed() >= self.config.recovery_timeout {
                    tracing::info!(
                        upstream = upstream,
                        "circuit breaker: Open → HalfOpen (recovery timeout elapsed)"
                    );
                    state.state = State::HalfOpen;
                    state.half_open_in_flight = 0;
                    state.consecutive_successes = 0;
                }
            }
        }

        match state.state {
            State::Closed => {
                state.total_requests += 1;
                Ok(())
            }
            State::Open => {
                state.total_short_circuits += 1;
                let retry_after = state
                    .opened_at
                    .map(|t| self.config.recovery_timeout.saturating_sub(t.elapsed()));
                Err(CircuitOpenError {
                    upstream: upstream.to_string(),
                    state: State::Open,
                    retry_after,
                })
            }
            State::HalfOpen => {
                if state.half_open_in_flight >= self.config.half_open_max_requests {
                    state.total_short_circuits += 1;
                    Err(CircuitOpenError {
                        upstream: upstream.to_string(),
                        state: State::HalfOpen,
                        retry_after: None,
                    })
                } else {
                    state.half_open_in_flight += 1;
                    state.total_requests += 1;
                    Ok(())
                }
            }
        }
    }

    /// Record a successful request to `upstream`.
    pub fn record_success(&self, upstream: &str) {
        let mut map = self.circuits.lock().unwrap();
        if let Some(state) = map.get_mut(upstream) {
            state.consecutive_failures = 0;
            state.consecutive_successes += 1;

            match state.state {
                State::HalfOpen => {
                    if state.consecutive_successes >= self.config.success_threshold {
                        tracing::info!(
                            upstream = upstream,
                            successes = state.consecutive_successes,
                            "circuit breaker: HalfOpen → Closed"
                        );
                        state.state = State::Closed;
                        state.half_open_in_flight = 0;
                        state.opened_at = None;
                    }
                }
                State::Closed => {
                    // Already good
                }
                State::Open => {
                    // Shouldn't happen — success while open? Ignore.
                }
            }
        }
    }

    /// Record a failed request to `upstream`.
    pub fn record_failure(&self, upstream: &str) {
        let mut map = self.circuits.lock().unwrap();
        let state = map
            .entry(upstream.to_string())
            .or_insert_with(CircuitState::new);

        state.consecutive_failures += 1;
        state.consecutive_successes = 0;
        state.total_failures += 1;

        match state.state {
            State::Closed => {
                if state.consecutive_failures >= self.config.failure_threshold {
                    tracing::warn!(
                        upstream = upstream,
                        failures = state.consecutive_failures,
                        "circuit breaker: Closed → Open"
                    );
                    state.state = State::Open;
                    state.opened_at = Some(Instant::now());
                }
            }
            State::HalfOpen => {
                tracing::warn!(
                    upstream = upstream,
                    "circuit breaker: HalfOpen → Open (probe failed)"
                );
                state.state = State::Open;
                state.opened_at = Some(Instant::now());
                state.half_open_in_flight = 0;
            }
            State::Open => {
                // Already open
            }
        }
    }

    /// Get the current state of an upstream's circuit.
    pub fn state(&self, upstream: &str) -> State {
        let map = self.circuits.lock().unwrap();
        map.get(upstream)
            .map(|s| s.state.clone())
            .unwrap_or(State::Closed)
    }

    /// Get statistics for an upstream.
    pub fn stats(&self, upstream: &str) -> CircuitStats {
        let map = self.circuits.lock().unwrap();
        map.get(upstream)
            .map(|s| CircuitStats {
                state: s.state.clone(),
                total_requests: s.total_requests,
                total_failures: s.total_failures,
                total_short_circuits: s.total_short_circuits,
                consecutive_failures: s.consecutive_failures,
            })
            .unwrap_or_default()
    }

    /// Reset a specific upstream circuit to Closed.
    pub fn reset(&self, upstream: &str) {
        let mut map = self.circuits.lock().unwrap();
        if let Some(state) = map.get_mut(upstream) {
            *state = CircuitState::new();
            tracing::info!(upstream = upstream, "circuit breaker reset to Closed");
        }
    }
}

/// Read-only stats snapshot.
#[derive(Debug, Clone, Default)]
pub struct CircuitStats {
    pub state: State,
    pub total_requests: u64,
    pub total_failures: u64,
    pub total_short_circuits: u64,
    pub consecutive_failures: u32,
}

impl Default for State {
    fn default() -> Self {
        State::Closed
    }
}

// ─── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> CircuitBreakerConfig {
        CircuitBreakerConfig {
            failure_threshold: 3,
            recovery_timeout: Duration::from_millis(100),
            half_open_max_requests: 2,
            success_threshold: 2,
        }
    }

    #[test]
    fn starts_closed() {
        let cb = CircuitBreaker::new(test_config());
        assert_eq!(cb.state("upstream1"), State::Closed);
        assert!(cb.check("upstream1").is_ok());
    }

    #[test]
    fn opens_after_threshold() {
        let cb = CircuitBreaker::new(test_config());
        let up = "backend";

        // 2 failures — still closed
        cb.check(up).unwrap();
        cb.record_failure(up);
        cb.check(up).unwrap();
        cb.record_failure(up);
        assert_eq!(cb.state(up), State::Closed);

        // 3rd failure — opens
        cb.check(up).unwrap();
        cb.record_failure(up);
        assert_eq!(cb.state(up), State::Open);

        // Next check should fail
        assert!(cb.check(up).is_err());
    }

    #[test]
    fn success_resets_failure_count() {
        let cb = CircuitBreaker::new(test_config());
        let up = "backend";

        cb.check(up).unwrap();
        cb.record_failure(up);
        cb.check(up).unwrap();
        cb.record_failure(up);

        // Success resets consecutive failures
        cb.check(up).unwrap();
        cb.record_success(up);
        assert_eq!(cb.state(up), State::Closed);

        // Need 3 more failures to open
        cb.check(up).unwrap();
        cb.record_failure(up);
        cb.check(up).unwrap();
        cb.record_failure(up);
        assert_eq!(cb.state(up), State::Closed); // Still only 2
    }

    #[test]
    fn transitions_to_half_open_after_recovery() {
        let cb = CircuitBreaker::new(test_config());
        let up = "backend";

        // Trip the breaker
        for _ in 0..3 {
            cb.check(up).unwrap();
            cb.record_failure(up);
        }
        assert_eq!(cb.state(up), State::Open);

        // Wait for recovery timeout
        std::thread::sleep(Duration::from_millis(150));

        // Next check transitions to HalfOpen and allows a probe
        assert!(cb.check(up).is_ok());
        assert_eq!(cb.state(up), State::HalfOpen);
    }

    #[test]
    fn half_open_limits_probes() {
        let cb = CircuitBreaker::new(test_config());
        let up = "backend";

        // Open the circuit
        for _ in 0..3 {
            cb.check(up).unwrap();
            cb.record_failure(up);
        }

        std::thread::sleep(Duration::from_millis(150));

        // HalfOpen allows 2 probes
        assert!(cb.check(up).is_ok()); // Probe 1
        assert!(cb.check(up).is_ok()); // Probe 2
        assert!(cb.check(up).is_err()); // Probe 3 — rejected
    }

    #[test]
    fn half_open_closes_on_success() {
        let cb = CircuitBreaker::new(test_config());
        let up = "backend";

        // Open
        for _ in 0..3 {
            cb.check(up).unwrap();
            cb.record_failure(up);
        }

        std::thread::sleep(Duration::from_millis(150));

        // HalfOpen
        cb.check(up).unwrap();
        cb.record_success(up);
        assert_eq!(cb.state(up), State::HalfOpen); // Need 2 successes

        cb.check(up).unwrap();
        cb.record_success(up);
        assert_eq!(cb.state(up), State::Closed); // Now closed
    }

    #[test]
    fn half_open_reopens_on_failure() {
        let cb = CircuitBreaker::new(test_config());
        let up = "backend";

        // Open
        for _ in 0..3 {
            cb.check(up).unwrap();
            cb.record_failure(up);
        }

        std::thread::sleep(Duration::from_millis(150));

        // HalfOpen
        cb.check(up).unwrap();
        cb.record_failure(up);
        assert_eq!(cb.state(up), State::Open); // Back to open
    }

    #[test]
    fn independent_upstreams() {
        let cb = CircuitBreaker::new(test_config());

        // Break upstream-A
        for _ in 0..3 {
            cb.check("A").unwrap();
            cb.record_failure("A");
        }
        assert_eq!(cb.state("A"), State::Open);

        // Upstream-B is still fine
        assert_eq!(cb.state("B"), State::Closed);
        assert!(cb.check("B").is_ok());
    }

    #[test]
    fn stats_tracking() {
        let cb = CircuitBreaker::new(test_config());
        let up = "backend";

        cb.check(up).unwrap();
        cb.record_success(up);
        cb.check(up).unwrap();
        cb.record_failure(up);

        let stats = cb.stats(up);
        assert_eq!(stats.total_requests, 2);
        assert_eq!(stats.total_failures, 1);
        assert_eq!(stats.consecutive_failures, 1);
    }

    #[test]
    fn reset_circuit() {
        let cb = CircuitBreaker::new(test_config());
        let up = "backend";

        // Open it
        for _ in 0..3 {
            cb.check(up).unwrap();
            cb.record_failure(up);
        }
        assert_eq!(cb.state(up), State::Open);

        // Reset
        cb.reset(up);
        assert_eq!(cb.state(up), State::Closed);
        assert!(cb.check(up).is_ok());
    }

    #[test]
    fn circuit_open_error_display() {
        let err = CircuitOpenError {
            upstream: "backend".into(),
            state: State::Open,
            retry_after: Some(Duration::from_secs(10)),
        };
        assert!(err.to_string().contains("Open"));
        assert!(err.to_string().contains("backend"));
    }
}
