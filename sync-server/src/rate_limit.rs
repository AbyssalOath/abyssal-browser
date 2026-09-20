//! A minimal rate-limiter/lockout layer for `sync-server`. Two
//! independent mechanisms, both in-memory:
//!
//!   - **Per-IP request rate limiting**: caps how many requests a
//!     single remote address can make per rolling window, regardless
//!     of whether they're authorized — this is what stops someone from
//!     hammering the endpoint at all (account enumeration, brute-force
//!     auth-secret guessing, plain DoS-adjacent noise).
//!   - **Per-account lockout**: after enough failed-auth attempts
//!     against one `account_id`, that account_id itself is locked out
//!     for a cooldown period even from a *different* IP — this is what
//!     stops someone from working around the per-IP limit by
//!     distributing guesses across many source addresses.
//!
//! Both are simple fixed-window counters, not a proper token bucket or
//! sliding-window log — good enough to turn "unlimited attempts" into
//! "bounded attempts," not a defense against a distributed attacker
//! with many IPs *and* patience. Also: entries are never evicted except
//! by their own window/lockout expiring in place, so a sustained flood
//! of distinct account_ids grows this map unboundedly over a long
//! enough time — bounded in practice by the per-IP limit (an attacker
//! can only mint account_ids as fast as their own request budget
//! allows), but a real deployment would want an LRU cap or periodic
//! sweep on top of that.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Requests allowed from one IP address within `IP_WINDOW`.
const MAX_REQUESTS_PER_IP_WINDOW: u32 = 30;
const IP_WINDOW: Duration = Duration::from_secs(60);

/// Failed-auth attempts allowed against one account_id before it's
/// locked out, and how long that lockout lasts. Deliberately generous
/// (not a 3-strikes policy) since a legitimate second device that
/// hasn't synced yet, or a user who mistyped their recovery code once,
/// shouldn't get locked out — this is aimed at sustained guessing, not
/// the occasional honest mistake.
const MAX_AUTH_FAILURES: u32 = 10;
const LOCKOUT_DURATION: Duration = Duration::from_secs(15 * 60);

struct IpBucket {
    count: u32,
    window_start: Instant,
}

struct AccountLockout {
    failures: u32,
    locked_until: Option<Instant>,
}

/// Blocked, with how long the caller should wait before trying again.
#[derive(Debug)]
pub struct RateLimited {
    pub retry_after: Duration,
}

#[derive(Default)]
pub struct RateLimiter {
    ip_buckets: HashMap<IpAddr, IpBucket>,
    account_lockouts: HashMap<String, AccountLockout>,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Call once per incoming request, before doing any real work.
    /// `Err` means the request should be rejected (429) without
    /// touching the account store at all.
    pub fn check_ip(&mut self, ip: IpAddr) -> Result<(), RateLimited> {
        let now = Instant::now();
        let bucket = self.ip_buckets.entry(ip).or_insert_with(|| IpBucket {
            count: 0,
            window_start: now,
        });
        if now.duration_since(bucket.window_start) >= IP_WINDOW {
            bucket.count = 0;
            bucket.window_start = now;
        }
        bucket.count += 1;
        if bucket.count > MAX_REQUESTS_PER_IP_WINDOW {
            let retry_after = IP_WINDOW.saturating_sub(now.duration_since(bucket.window_start));
            return Err(RateLimited { retry_after });
        }
        Ok(())
    }

    /// Call after `check_ip` succeeds but before touching the account
    /// store — a locked-out account_id should never even reach
    /// `FileSyncServer::push`/`pull`, successful or not, since reaching
    /// it at all is exactly what a lockout is meant to prevent.
    pub fn check_account_lockout(&mut self, account_id: &str) -> Result<(), RateLimited> {
        let now = Instant::now();
        if let Some(lockout) = self.account_lockouts.get(account_id) {
            if let Some(until) = lockout.locked_until {
                if now < until {
                    return Err(RateLimited {
                        retry_after: until - now,
                    });
                }
            }
        }
        Ok(())
    }

    /// Record a failed authentication against `account_id` (wrong auth
    /// secret on push/pull) — escalates to a lockout once
    /// `MAX_AUTH_FAILURES` is reached.
    pub fn record_auth_failure(&mut self, account_id: &str) {
        let now = Instant::now();
        let entry = self
            .account_lockouts
            .entry(account_id.to_string())
            .or_insert_with(|| AccountLockout {
                failures: 0,
                locked_until: None,
            });
        entry.failures += 1;
        if entry.failures >= MAX_AUTH_FAILURES {
            entry.locked_until = Some(now + LOCKOUT_DURATION);
        }
    }

    /// A successful, authorized push/pull clears any accumulated
    /// failure count for that account_id — failures only compound
    /// within a streak of wrong attempts, not across its whole history.
    pub fn record_auth_success(&mut self, account_id: &str) {
        self.account_lockouts.remove(account_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_requests_under_the_ip_limit() {
        let mut limiter = RateLimiter::new();
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        for _ in 0..MAX_REQUESTS_PER_IP_WINDOW {
            assert!(limiter.check_ip(ip).is_ok());
        }
    }

    #[test]
    fn blocks_requests_once_the_ip_limit_is_exceeded() {
        let mut limiter = RateLimiter::new();
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        for _ in 0..MAX_REQUESTS_PER_IP_WINDOW {
            limiter.check_ip(ip).unwrap();
        }
        assert!(limiter.check_ip(ip).is_err());
    }

    #[test]
    fn different_ips_have_independent_limits() {
        let mut limiter = RateLimiter::new();
        let a: IpAddr = "127.0.0.1".parse().unwrap();
        let b: IpAddr = "127.0.0.2".parse().unwrap();
        for _ in 0..MAX_REQUESTS_PER_IP_WINDOW {
            limiter.check_ip(a).unwrap();
        }
        assert!(limiter.check_ip(a).is_err());
        assert!(limiter.check_ip(b).is_ok());
    }

    #[test]
    fn locks_an_account_out_after_enough_auth_failures() {
        let mut limiter = RateLimiter::new();
        for _ in 0..MAX_AUTH_FAILURES {
            assert!(limiter.check_account_lockout("acct_1").is_ok());
            limiter.record_auth_failure("acct_1");
        }
        assert!(limiter.check_account_lockout("acct_1").is_err());
    }

    #[test]
    fn a_successful_auth_clears_accumulated_failures() {
        let mut limiter = RateLimiter::new();
        for _ in 0..MAX_AUTH_FAILURES - 1 {
            limiter.record_auth_failure("acct_1");
        }
        limiter.record_auth_success("acct_1");
        limiter.record_auth_failure("acct_1");
        // Only one failure since the reset — nowhere near locked out.
        assert!(limiter.check_account_lockout("acct_1").is_ok());
    }

    #[test]
    fn unrelated_accounts_are_never_locked_out_by_each_other() {
        let mut limiter = RateLimiter::new();
        for _ in 0..MAX_AUTH_FAILURES {
            limiter.record_auth_failure("acct_attacked");
        }
        assert!(limiter.check_account_lockout("acct_attacked").is_err());
        assert!(limiter.check_account_lockout("acct_innocent").is_ok());
    }
}
