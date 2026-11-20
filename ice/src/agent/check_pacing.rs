use std::cmp::Reverse;
use std::net::IpAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use tokio::time::{Duration, Instant};

use crate::candidate::{CandidatePair, CandidateType};
use crate::util::globally_reachable_ipv4;

// RFC 8445 recommends a 50ms Ta. The existing selector normally wakes every
// 200ms, so it can spend at most four elapsed slots per wake. Adding a
// trickled candidate does not refill the budget. Authenticated peer-triggered
// checks, nomination and maintenance of an established pair stay independent.
const SLOT: Duration = Duration::from_millis(50);
const BURST: usize = 4;

pub(super) struct CheckPacing {
    credit: usize,
    last: Instant,
}

impl Default for CheckPacing {
    fn default() -> Self {
        Self {
            credit: BURST,
            last: Instant::now(),
        }
    }
}

impl CheckPacing {
    pub(super) fn ensure_one(&mut self) {
        self.credit = self.credit.max(1);
    }

    fn take(&mut self, now: Instant, count: usize) -> usize {
        let elapsed = now.saturating_duration_since(self.last);
        let slots = elapsed.as_millis() / SLOT.as_millis();
        if slots != 0 {
            self.credit = (self.credit + slots.min(BURST as u128) as usize).min(BURST);
            self.last = now - Duration::from_nanos((elapsed.as_nanos() % SLOT.as_nanos()) as u64);
        }
        let n = self.credit.min(count);
        self.credit -= n;
        n
    }

    pub(super) fn choose(&mut self, pairs: &mut Vec<Arc<CandidatePair>>, now: Instant) {
        let n = self.take(now, pairs.len());
        if n != 0 && n < pairs.len() {
            // Untried pairs go before retries, including newly learned endpoints.
            pairs.sort_by_cached_key(|p| {
                (
                    p.binding_request_count.load(Ordering::Relaxed),
                    path_order(p),
                    Reverse(p.priority()),
                )
            });
        }
        pairs.truncate(n);
    }
}

fn path_order(p: &CandidatePair) -> u8 {
    let local = p.local.addr().ip();
    let remote = p.remote.addr().ip();
    if p.local.candidate_type() == CandidateType::Host
        && p.remote.candidate_type() == CandidateType::Host
    {
        match (local, remote) {
            (IpAddr::V4(a), IpAddr::V4(b))
                if a.is_private() && a.octets()[..3] == b.octets()[..3] =>
            {
                return 0
            }
            (IpAddr::V6(a), IpAddr::V6(b)) if a.octets()[..8] == b.octets()[..8] => return 0,
            _ => {}
        }
    }
    match remote {
        IpAddr::V4(v) if globally_reachable_ipv4(v) => 1,
        IpAddr::V6(v) if v.octets()[0] & 0xe0 == 0x20 => 1,
        _ => 2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::candidate::{
        candidate_base::CandidateBaseConfig, candidate_host::CandidateHostConfig, Candidate,
    };

    fn host(address: &str, port: u16) -> Arc<dyn Candidate + Send + Sync> {
        Arc::new(
            CandidateHostConfig {
                base_config: CandidateBaseConfig {
                    network: "udp4".into(),
                    component: 1,
                    address: address.into(),
                    port,
                    ..Default::default()
                },
                ..Default::default()
            }
            .new_candidate_host()
            .unwrap(),
        )
    }

    #[test]
    fn large_checklist_tries_lan_and_public_first_and_reaches_every_tuple() {
        let local = host("10.1.0.23", 42000);
        let source: Vec<_> = (0..70)
            .map(|i| {
                let ip = match i {
                    68 => "8.8.4.4",
                    69 => "10.1.0.10",
                    _ => "192.168.10.10",
                };
                Arc::new(CandidatePair::new(local.clone(), host(ip, 46000 + i), true))
            })
            .collect();
        let mut pace = CheckPacing::default();
        let start = pace.last;
        let mut sent = 0;
        for tick in 0..=20 {
            let mut pairs = source.clone();
            pace.choose(&mut pairs, start + Duration::from_millis(200 * tick));
            if tick == 0 {
                assert_eq!(pairs[0].remote.port(), 46069);
                assert_eq!(pairs[1].remote.port(), 46068);
            }
            assert!(pairs.len() <= BURST);
            sent += pairs.len();
            for p in pairs {
                p.binding_request_count.fetch_add(1, Ordering::Relaxed);
            }
        }
        assert_eq!(sent, 84);
        assert!(source
            .iter()
            .all(|p| p.binding_request_count.load(Ordering::Relaxed) >= 1));
    }

    #[test]
    fn bursts_and_trickle_share_slots_and_relay_go_can_wake_one() {
        let mut pace = CheckPacing::default();
        let start = pace.last;
        assert_eq!(pace.take(start, 400), 4);
        for _ in 0..100 {
            assert_eq!(pace.take(start, 400), 0);
        }
        assert_eq!(pace.take(start + Duration::from_millis(49), 400), 0);
        assert_eq!(pace.take(start + Duration::from_millis(199), 400), 3);
        assert_eq!(pace.take(start + Duration::from_millis(200), 400), 1);
        pace.ensure_one();
        pace.ensure_one();
        assert_eq!(pace.take(start + Duration::from_millis(200), 400), 1);
        assert_eq!(pace.take(start + Duration::from_secs(100), 400), 4);
    }
}
