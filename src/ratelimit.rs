//! Rate limiting for AI Gateway requests.
//!
//! Provides sliding window rate limiting by client IP, with support for:
//! - Requests per minute
//! - Tokens per minute (estimated)

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

/// Rate limiter configuration
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Maximum requests per minute per client (0 = unlimited)
    pub requests_per_minute: u32,
    /// Maximum estimated tokens per minute per client (0 = unlimited)
    pub tokens_per_minute: u32,
    /// Window duration for rate limiting
    pub window_duration: Duration,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            requests_per_minute: 0,
            tokens_per_minute: 0,
            window_duration: Duration::from_secs(60),
        }
    }
}

impl RateLimitConfig {
    /// Check if rate limiting is enabled
    pub fn is_enabled(&self) -> bool {
        self.requests_per_minute > 0 || self.tokens_per_minute > 0
    }
}

/// Result of a rate limit check
#[derive(Debug, Clone)]
pub struct RateLimitResult {
    /// Whether the request is allowed
    pub allowed: bool,
    /// Current request count in window
    pub request_count: u32,
    /// Request limit
    pub request_limit: u32,
    /// Current token count in window
    pub token_count: u32,
    /// Token limit
    pub token_limit: u32,
    /// Seconds until window resets
    pub reset_seconds: u64,
    /// Which limit was exceeded (if any)
    pub exceeded_limit: Option<ExceededLimit>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExceededLimit {
    Requests,
    Tokens,
}

impl RateLimitResult {
    pub fn allowed(
        request_count: u32,
        request_limit: u32,
        token_count: u32,
        token_limit: u32,
        reset_seconds: u64,
    ) -> Self {
        Self {
            allowed: true,
            request_count,
            request_limit,
            token_count,
            token_limit,
            reset_seconds,
            exceeded_limit: None,
        }
    }

    pub fn denied(
        request_count: u32,
        request_limit: u32,
        token_count: u32,
        token_limit: u32,
        reset_seconds: u64,
        exceeded: ExceededLimit,
    ) -> Self {
        Self {
            allowed: false,
            request_count,
            request_limit,
            token_count,
            token_limit,
            reset_seconds,
            exceeded_limit: Some(exceeded),
        }
    }
}

/// Entry tracking usage within a time window
#[derive(Debug, Clone)]
struct WindowEntry {
    /// When this window started
    window_start: Instant,
    /// Request count in current window
    request_count: u32,
    /// Token count in current window
    token_count: u32,
}

impl WindowEntry {
    fn new() -> Self {
        Self {
            window_start: Instant::now(),
            request_count: 0,
            token_count: 0,
        }
    }

    /// Check if the window has expired
    fn is_expired(&self, window_duration: Duration) -> bool {
        self.window_start.elapsed() >= window_duration
    }

    /// Reset the window
    fn reset(&mut self) {
        self.window_start = Instant::now();
        self.request_count = 0;
        self.token_count = 0;
    }

    /// Get seconds until window resets
    fn seconds_until_reset(&self, window_duration: Duration) -> u64 {
        let elapsed = self.window_start.elapsed();
        if elapsed >= window_duration {
            0
        } else {
            (window_duration - elapsed).as_secs()
        }
    }
}

/// In-memory rate limiter using sliding windows
pub struct RateLimiter {
    config: RateLimitConfig,
    /// Per-client rate limit state, keyed by client identifier (usually IP)
    state: Arc<Mutex<HashMap<String, WindowEntry>>>,
}

impl RateLimiter {
    /// Create a new rate limiter with the given configuration
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            state: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Check if a request is allowed and record it
    ///
    /// Returns the rate limit result with current counts and limits.
    /// If allowed, the request and tokens are counted.
    pub async fn check_and_record(
        &self,
        client_id: &str,
        estimated_tokens: u32,
    ) -> RateLimitResult {
        if !self.config.is_enabled() {
            return RateLimitResult::allowed(0, 0, 0, 0, 0);
        }

        let mut state = self.state.lock().await;
        let entry = state
            .entry(client_id.to_string())
            .or_insert_with(WindowEntry::new);

        // Reset window if expired
        if entry.is_expired(self.config.window_duration) {
            entry.reset();
        }

        let reset_seconds = entry.seconds_until_reset(self.config.window_duration);

        // Check request limit
        if self.config.requests_per_minute > 0
            && entry.request_count >= self.config.requests_per_minute
        {
            return RateLimitResult::denied(
                entry.request_count,
                self.config.requests_per_minute,
                entry.token_count,
                self.config.tokens_per_minute,
                reset_seconds,
                ExceededLimit::Requests,
            );
        }

        // Check token limit
        if self.config.tokens_per_minute > 0
            && entry.token_count + estimated_tokens > self.config.tokens_per_minute
        {
            return RateLimitResult::denied(
                entry.request_count,
                self.config.requests_per_minute,
                entry.token_count,
                self.config.tokens_per_minute,
                reset_seconds,
                ExceededLimit::Tokens,
            );
        }

        // Record the request
        entry.request_count += 1;
        entry.token_count += estimated_tokens;

        RateLimitResult::allowed(
            entry.request_count,
            self.config.requests_per_minute,
            entry.token_count,
            self.config.tokens_per_minute,
            reset_seconds,
        )
    }

    /// Clean up expired entries to prevent memory growth
    pub async fn cleanup_expired(&self) {
        let mut state = self.state.lock().await;
        state.retain(|_, entry| !entry.is_expired(self.config.window_duration));
    }

    /// Get current state for a client (for testing/debugging)
    #[cfg(test)]
    pub async fn get_state(&self, client_id: &str) -> Option<(u32, u32)> {
        let state = self.state.lock().await;
        state
            .get(client_id)
            .map(|e| (e.request_count, e.token_count))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_rate_limiter_disabled() {
        let limiter = RateLimiter::new(RateLimitConfig::default());
        let result = limiter.check_and_record("client1", 100).await;
        assert!(result.allowed);
    }

    #[tokio::test]
    async fn test_request_limit() {
        let config = RateLimitConfig {
            requests_per_minute: 3,
            tokens_per_minute: 0,
            window_duration: Duration::from_secs(60),
        };
        let limiter = RateLimiter::new(config);

        // First 3 requests should be allowed
        for i in 1..=3 {
            let result = limiter.check_and_record("client1", 0).await;
            assert!(result.allowed, "Request {} should be allowed", i);
            assert_eq!(result.request_count, i);
        }

        // 4th request should be denied
        let result = limiter.check_and_record("client1", 0).await;
        assert!(!result.allowed);
        assert_eq!(result.exceeded_limit, Some(ExceededLimit::Requests));
    }

    #[tokio::test]
    async fn test_token_limit() {
        let config = RateLimitConfig {
            requests_per_minute: 0,
            tokens_per_minute: 1000,
            window_duration: Duration::from_secs(60),
        };
        let limiter = RateLimiter::new(config);

        // Request with 500 tokens - allowed
        let result = limiter.check_and_record("client1", 500).await;
        assert!(result.allowed);
        assert_eq!(result.token_count, 500);

        // Request with 400 tokens - allowed (900 total)
        let result = limiter.check_and_record("client1", 400).await;
        assert!(result.allowed);
        assert_eq!(result.token_count, 900);

        // Request with 200 tokens - denied (would be 1100)
        let result = limiter.check_and_record("client1", 200).await;
        assert!(!result.allowed);
        assert_eq!(result.exceeded_limit, Some(ExceededLimit::Tokens));
    }

    #[tokio::test]
    async fn test_separate_clients() {
        let config = RateLimitConfig {
            requests_per_minute: 2,
            tokens_per_minute: 0,
            window_duration: Duration::from_secs(60),
        };
        let limiter = RateLimiter::new(config);

        // Client 1: 2 requests
        limiter.check_and_record("client1", 0).await;
        limiter.check_and_record("client1", 0).await;

        // Client 1 should be rate limited
        let result = limiter.check_and_record("client1", 0).await;
        assert!(!result.allowed);

        // Client 2 should still be allowed
        let result = limiter.check_and_record("client2", 0).await;
        assert!(result.allowed);
    }

    #[tokio::test]
    async fn test_window_reset() {
        let config = RateLimitConfig {
            requests_per_minute: 2,
            tokens_per_minute: 0,
            window_duration: Duration::from_millis(100), // Very short window for testing
        };
        let limiter = RateLimiter::new(config);

        // Use up the limit
        limiter.check_and_record("client1", 0).await;
        limiter.check_and_record("client1", 0).await;

        // Should be rate limited
        let result = limiter.check_and_record("client1", 0).await;
        assert!(!result.allowed);

        // Wait for window to expire
        tokio::time::sleep(Duration::from_millis(150)).await;

        // Should be allowed again
        let result = limiter.check_and_record("client1", 0).await;
        assert!(result.allowed);
        assert_eq!(result.request_count, 1);
    }

    #[tokio::test]
    async fn test_combined_limits() {
        let config = RateLimitConfig {
            requests_per_minute: 10,
            tokens_per_minute: 500,
            window_duration: Duration::from_secs(60),
        };
        let limiter = RateLimiter::new(config);

        // 3 requests with 100 tokens each - all allowed
        for _ in 0..3 {
            let result = limiter.check_and_record("client1", 100).await;
            assert!(result.allowed);
        }

        // Next request would exceed token limit
        let result = limiter.check_and_record("client1", 300).await;
        assert!(!result.allowed);
        assert_eq!(result.exceeded_limit, Some(ExceededLimit::Tokens));
    }

    #[tokio::test]
    async fn test_cleanup_expired() {
        let config = RateLimitConfig {
            requests_per_minute: 10,
            tokens_per_minute: 0,
            window_duration: Duration::from_millis(50),
        };
        let limiter = RateLimiter::new(config);

        // Create some entries
        limiter.check_and_record("client1", 0).await;
        limiter.check_and_record("client2", 0).await;

        // Verify they exist
        assert!(limiter.get_state("client1").await.is_some());
        assert!(limiter.get_state("client2").await.is_some());

        // Wait for expiration
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Cleanup
        limiter.cleanup_expired().await;

        // Entries should be gone
        assert!(limiter.get_state("client1").await.is_none());
        assert!(limiter.get_state("client2").await.is_none());
    }
}
