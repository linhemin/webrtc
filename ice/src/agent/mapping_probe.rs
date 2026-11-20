//! Opt-in comparison of public mappings on sockets already installed in the ICE checklist.
//! The existing candidate receive loop owns recv_from throughout the measurement.
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};

use futures_util::future::join_all;
use stun::addr::MappedAddress;
use stun::agent::TransactionId;
use stun::attributes::*;
use stun::fingerprint::FINGERPRINT;
use stun::message::{Getter, Message, BINDING_REQUEST, BINDING_SUCCESS};
use stun::xoraddr::XorMappedAddress;
use tokio::sync::{oneshot, OnceCell};
use tokio::task::JoinSet;
use tokio::time::{sleep, timeout, Duration, Instant};
use util::sync::Mutex;

use super::Agent;
use crate::candidate::{
    candidate_base::CandidateBaseConfig,
    candidate_server_reflexive::CandidateServerReflexiveConfig, Candidate, CandidatePairState,
    CandidateType,
};
use crate::network_type::NetworkType;
use crate::url::{ProtoType, SchemeType, Url};
use crate::util::globally_reachable_ipv4;

type Local = Arc<dyn Candidate + Send + Sync>;
const MAX_SOCKETS: usize = 6;
const MAX_SIGNALED_MAPPINGS: usize = 6;
const MAX_MAPPINGS_PER_SOCKET: usize = 2;
const MAX_OBSERVERS: usize = 4;
const REPLY_WAIT: Duration = Duration::from_millis(810);
const RETRY_AFTER: Duration = Duration::from_millis(350);

/// Each measured socket counts exactly once in stable, port_changed, address_changed or
/// inconclusive. Alternate outcomes are a subset. No peer, STUN, or mapping addresses escape.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MappingProbeStats {
    pub sockets: u32,
    pub stable: u32,
    pub port_changed: u32,
    pub address_changed: u32,
    pub inconclusive: u32,
    pub alternate_tested: u32,
    pub alternate_changed: u32,
    /// Stable, constant nonzero step, irregular, insufficient/address changed.
    /// Only populated from sequential observations on a grouped retry.
    pub ordered_profiles: [u32; 4],
}

#[derive(Clone, Copy)]
struct Observation {
    mapped: SocketAddrV4,
    alternate: Option<SocketAddr>,
}

struct Pending {
    socket: Local,
    source: SocketAddr,
    reply: oneshot::Sender<Observation>,
}

#[derive(Default)]
pub(crate) struct Probes {
    gathered: Mutex<HashMap<String, (SocketAddr, Observation)>>,
    physical: Mutex<Vec<Weak<dyn Candidate + Send + Sync>>>,
    active: AtomicBool,
    pending: Mutex<HashMap<TransactionId, Pending>>,
    epoch: Mutex<Arc<OnceCell<Measurement>>>,
}

#[derive(Default)]
struct Measurement {
    stats: MappingProbeStats,
    ranks: HashMap<String, u8>,
    // Kept only in this ICE generation. The diagnostic payload contains counts only.
    alternates: Vec<(Weak<dyn Candidate + Send + Sync>, Vec<SocketAddrV4>)>,
}

impl Probes {
    pub(super) fn mark_physical(&self, c: &Local) {
        self.physical.lock().push(Arc::downgrade(c));
    }

    /// Only called on a matching transaction from the locally configured gather observer.
    pub(super) fn remember(&self, socket: &Local, remote: SocketAddr, msg: &Message) {
        let endpoint = match remote {
            SocketAddr::V4(a) if globally_reachable_ipv4(*a.ip()) => remote,
            #[cfg(any(target_os = "ios", test))]
            SocketAddr::V6(_) => {
                let Some(addr) = socket
                    .get_conn()
                    .and_then(|c| crate::nat64::observer_v4(c, remote))
                else {
                    return;
                };
                if !matches!(addr.ip(),IpAddr::V4(ip) if globally_reachable_ipv4(ip)) {
                    return;
                }
                addr
            }
            _ => return,
        };
        if let Some(obs) = observed(endpoint, msg) {
            self.gathered.lock().insert(socket.id(), (endpoint, obs));
        }
    }

    pub(crate) fn reset(&self) {
        *self.epoch.lock() = Default::default();
        self.physical.lock().clear();
        self.gathered.lock().clear();
        let mut pending = self.pending.lock();
        pending.clear();
        self.active.store(false, Ordering::Release);
    }

    pub(crate) fn deliver(&self, socket: &Local, source: SocketAddr, msg: &Message) -> bool {
        if msg.typ != BINDING_SUCCESS || !self.active.load(Ordering::Acquire) {
            return false;
        }
        let mut pending = self.pending.lock();
        let Some(probe) = pending.get(&msg.transaction_id) else {
            return false;
        };
        if probe.source != source || !Arc::ptr_eq(socket, &probe.socket) {
            return false;
        }
        let Some(obs) = observed(source, msg) else {
            return false;
        };
        if let Some(probe) = pending.remove(&msg.transaction_id) {
            let _ = probe.reply.send(obs);
        }
        self.active.store(!pending.is_empty(), Ordering::Release);
        true
    }

    async fn query(
        &self,
        socket: &Local,
        target: SocketAddr,
        expected: SocketAddr,
        change_port: bool,
    ) -> Option<Observation> {
        let conn = socket.get_conn()?;
        let id = TransactionId::new();
        let mut request = Message::new();
        request
            .build(&[Box::new(BINDING_REQUEST), Box::new(id)])
            .ok()?;
        request.add(ATTR_SOFTWARE, b"RustDesk observation");
        if change_port {
            request.add(ATTR_CHANGE_REQUEST, &2u32.to_be_bytes());
        }
        let (tx, mut rx) = oneshot::channel();
        {
            let mut pending = self.pending.lock();
            pending.insert(
                id,
                Pending {
                    socket: socket.clone(),
                    source: expected,
                    reply: tx,
                },
            );
            self.active.store(true, Ordering::Release);
        }
        // Cancellation, including an outer timeout, must remove this transaction immediately.
        let _registered = Registration { probes: self, id };
        timeout(REPLY_WAIT, async {
            if conn.send_to(&request.raw, target).await.ok()? != request.raw.len() {
                return None;
            }
            tokio::select! {
                received = &mut rx => received.ok(),
                _ = sleep(RETRY_AFTER) => {
                    // Retransmit this very same STUN transaction once from the same candidate.
                    if conn.send_to(&request.raw, target).await.ok()? != request.raw.len() {return None;}
                    rx.await.ok()
                }
            }
        })
        .await
        .ok()
        .flatten()
    }
}

struct Registration<'a> {
    probes: &'a Probes,
    id: TransactionId,
}
impl Drop for Registration<'_> {
    fn drop(&mut self) {
        let mut pending = self.probes.pending.lock();
        pending.remove(&self.id);
        self.probes
            .active
            .store(!pending.is_empty(), Ordering::Release);
    }
}

fn observed(source: SocketAddr, msg: &Message) -> Option<Observation> {
    if msg.raw.len() != 20 + msg.length as usize
        || (msg.contains(ATTR_FINGERPRINT) && FINGERPRINT.check(msg).is_err())
    {
        return None;
    }
    if msg.contains(ATTR_RESPONSE_ORIGIN) && plain_address(msg, ATTR_RESPONSE_ORIGIN)? != source {
        return None;
    }
    let raw = msg.get(ATTR_XORMAPPED_ADDRESS).ok()?;
    if raw.len() != 8 || raw[..2] != [0, 1] {
        return None;
    }
    let mut mapped = XorMappedAddress::default();
    mapped.get_from(msg).ok()?;
    let IpAddr::V4(ip) = mapped.ip else {
        return None;
    };
    if !globally_reachable_ipv4(ip) || mapped.port == 0 {
        return None;
    }
    // RFC 5780 OTHER-ADDRESS supplies A2:P2. CHANGE-PORT alone replies from A1:P2.
    // Never send to the advertised alternate IP.
    let alternate = plain_address(msg, ATTR_OTHER_ADDRESS)
        .filter(|other| {
            matches!(source.ip(),IpAddr::V4(v) if globally_reachable_ipv4(v))
                && matches!(other.ip(),IpAddr::V4(v) if globally_reachable_ipv4(v))
                && matches!((source.port(), other.port()), (443, 3478) | (3478, 443))
        })
        .map(|other| SocketAddr::new(source.ip(), other.port()));
    Some(Observation {
        mapped: SocketAddrV4::new(ip, mapped.port),
        alternate,
    })
}

fn plain_address(m: &Message, kind: AttrType) -> Option<SocketAddr> {
    let raw = m.get(kind).ok()?;
    if raw.len() != 8 || raw[..2] != [0, 1] {
        return None;
    }
    let mut value = MappedAddress::default();
    value.get_from_as(m, kind).ok()?;
    Some(SocketAddr::new(value.ip, value.port))
}

#[derive(Default)]
struct Sample {
    mappings: Vec<SocketAddrV4>,
    alternate_changed: Option<bool>,
    ordered_profile: Option<usize>,
}

impl Sample {
    fn record(&self, stats: &mut MappingProbeStats) {
        stats.sockets += 1;
        if let Some(kind) = self.ordered_profile { stats.ordered_profiles[kind] += 1; }
        match self.mappings.first() {
            Some(a) if self.mappings.len() >= 2 => {
                if self.mappings.iter().any(|m| m.ip() != a.ip()) {
                    stats.address_changed += 1;
                } else if self.mappings.iter().any(|m| m.port() != a.port()) {
                    stats.port_changed += 1;
                } else {
                    stats.stable += 1;
                }
            }
            _ => stats.inconclusive += 1,
        }
        if let Some(changed) = self.alternate_changed {
            stats.alternate_tested += 1;
            stats.alternate_changed += u32::from(changed);
        }
    }
}

// A constant step requires three equal changes at four distinct destinations
// from the same socket. Mixed public addresses and short series are inconclusive.
fn observed_profile(series: &[SocketAddrV4]) -> usize {
    let Some(first) = series.first() else { return 3 };
    if series.len() < 2 || series.iter().any(|ep| ep.ip() != first.ip()) { return 3; }
    if series.iter().all(|ep| ep.port() == first.port()) { return 0; }
    if series.len() < 4 { return 3; }
    let mut steps = series.windows(2).map(|w| w[1].port().wrapping_sub(w[0].port()));
    let step = steps.next().unwrap_or(0);
    if step != 0 && steps.all(|d| d == step) { 1 } else { 2 }
}

async fn sample(probes: &Probes, socket: &Local, endpoints: &[SocketAddr], ordered: bool) -> Sample {
    let mut result = Sample::default();
    let gathered = probes.gathered.lock().get(&socket.id()).copied();
    let replies = if ordered {
        let mut replies = Vec::with_capacity(endpoints.len());
        for &ep in endpoints {
            let reply = timeout(Duration::from_millis(450), probes.query(socket, ep, ep, false))
                .await.ok().flatten();
            replies.push(reply);
        }
        replies
    } else {
        join_all(endpoints.iter().map(|&ep| probes.query(socket, ep, ep, false))).await
    };
    // Deduplicate by destination. A repeated request to one observer cannot establish stability.
    // The matched gather response is the observation that originated this published candidate.
    let mut observations: Vec<_> = endpoints
        .iter()
        .copied()
        .zip(replies)
        .filter_map(|(ep, obs)| obs.map(|o| (ep, o)))
        .collect();
    // Classify only live queries to distinct destinations in send order.
    // The cached gather mapping does not establish its allocation order.
    let mut live: Vec<_> = observations.iter().map(|(ep, obs)| (*ep, obs.mapped)).collect();
    if let Some((ep, cached)) = gathered {
        if !observations.iter().any(|(target, _)| *target == ep) {
            observations.push((ep, cached));
        }
    }
    let mut alternate = None;
    let observed_targets: HashSet<_> = observations.iter().map(|(ep, _)| *ep).collect();
    for (ep, obs) in observations {
        result.mappings.push(obs.mapped);
        if alternate.is_none() {
            alternate = obs.alternate.map(|target| (ep, target, obs.mapped));
        }
    }
    // Only the configured server's validated, same-IP alternate is eligible.
    // A CHANGE-PORT timeout alone never implies a filtering or mapping outcome.
    if let Some((target, alt, baseline)) = alternate {
        // Preserve completed ordinary observations even when the alternate ignores us.
        let exchange = async {
            let _ = probes.query(socket, target, alt, true).await;
            probes.query(socket, alt, alt, false).await
        };
        if let Ok(Some(other)) = timeout(Duration::from_millis(1450), exchange).await {
            // This reply matched the direct query to alt. The CHANGE-PORT
            // request went to the primary and is never a second destination.
            if ordered && !live.iter().any(|(ep, _)| *ep == alt) {
                live.push((alt, other.mapped));
            }
            result.alternate_changed = Some(other.mapped != baseline);
            if !observed_targets.contains(&alt) {
                result.mappings.push(other.mapped);
            }
        }
    }
    if ordered {
        let series: Vec<_> = live.into_iter().map(|(_, mapped)| mapped).collect();
        result.ordered_profile = Some(observed_profile(&series));
    }
    result
}

impl Agent {
    pub fn udp_mapping_stats(&self) -> Option<MappingProbeStats> {
        self.internal
            .mapping_probes
            .epoch
            .lock()
            .get()
            .map(|m| m.stats)
    }

    /// Return additional *signaling* candidates derived from responses on a still-installed
    /// socket. Only ports on that socket's already signaled public IP are eligible. The owning
    /// candidate keeps its original reader and handles the peer checks and data.
    pub async fn observed_udp_candidates(&self) -> Vec<Local> {
        self.observed_udp_aliases().await.into_iter().map(|(_, alias)| alias).collect()
    }

    async fn observed_udp_aliases(&self) -> Vec<(String, Local)> {
        let epoch = self.internal.mapping_probes.epoch.lock().clone();
        let Some(measurement) = epoch.get() else {
            return Vec::new();
        };
        let locals = self.internal.local_candidates.lock().await;
        let Some(installed) = locals.get(&NetworkType::Udp4) else {
            return Vec::new();
        };
        let mut seen: HashSet<_> = installed.iter().map(|c| c.addr()).collect();
        let mut out: Vec<(String, Local)> = Vec::new();
        // Offer one port per socket before considering a second port on the same socket.
        for round in 0..MAX_MAPPINGS_PER_SOCKET {
            for (owner, ports) in &measurement.alternates {
                let (Some(owner), Some(&addr)) = (owner.upgrade(), ports.get(round)) else {
                    continue;
                };
                if !installed.iter().any(|c| Arc::ptr_eq(c, &owner))
                    || !seen.insert(SocketAddr::V4(addr))
                {
                    continue;
                }
                let Some(related) = owner.related_address() else {
                    continue;
                };
                let config = CandidateServerReflexiveConfig {
                    base_config: CandidateBaseConfig {
                        network: "udp".into(),
                        address: addr.ip().to_string(),
                        port: addr.port(),
                        component: owner.component(),
                        // Retain the base socket's component and reduce its local preference.
                        priority: owner.priority().saturating_sub(256),
                        ..Default::default()
                    },
                    rel_addr: related.address,
                    rel_port: related.port,
                };
                if let Ok(candidate) = config.new_candidate_server_reflexive() {
                    out.push((owner.id(), Arc::new(candidate)));
                    if out.len() == MAX_SIGNALED_MAPPINGS {
                        return out;
                    }
                }
            }
        }
        out
    }

    /// Uses configured STUN servers and exclusively existing, published IPv4 srflx sockets.
    /// A NAT64-backed srflx uses its retained translating Conn just like a peer check.
    /// Results for distinct destinations characterize those observers, never the peer itself.
    pub async fn measure_udp_mappings(self: &Arc<Self>) -> MappingProbeStats {
        let epoch = self.internal.mapping_probes.epoch.lock().clone();
        epoch
            .get_or_try_init(|| self.collect_mappings())
            .await
            .map(|m| m.stats)
            .unwrap_or_default()
    }

    async fn public_udp_sockets(&self) -> Vec<Local> {
        let deadline = Instant::now() + Duration::from_millis(650);
        let mut locals;
        loop {
            locals = self.internal.local_candidates.lock().await
                .get(&NetworkType::Udp4).into_iter().flatten()
                .filter(|candidate| candidate.candidate_type() == CandidateType::ServerReflexive
                        && matches!(candidate.addr().ip(), IpAddr::V4(ip) if globally_reachable_ipv4(ip))
                        && candidate.get_conn().is_some()).cloned().collect::<Vec<_>>();
            if Instant::now() >= deadline
                || (!locals.is_empty()
                    && self.gathering_state.load(Ordering::SeqCst)
                        == super::GatheringState::Complete as u8)
            {
                break;
            }
            sleep(Duration::from_millis(40)).await;
        }
        {
            let physical = self.internal.mapping_probes.physical.lock();
            locals.sort_by_key(|candidate| {
                if physical
                    .iter()
                    .any(|p| p.ptr_eq(&Arc::downgrade(candidate)))
                {
                    return 0;
                }
                let addr = candidate.get_conn().and_then(|s| s.local_addr().ok());
                match addr {
                    Some(SocketAddr::V6(_)) => 1, // retained NAT64 adapter
                    Some(a) if !a.ip().is_unspecified() => 2,
                    _ => 3,
                }
            });
        }
        locals
    }

    pub async fn grouped_public_candidates(self: &Arc<Self>) -> Vec<(String, SocketAddrV4, u8)> {
        self.measure_udp_mappings().await;
        let epoch = self.internal.mapping_probes.epoch.lock().clone();
        let sockets = self.public_udp_sockets().await;
        let aliases = self.observed_udp_aliases().await;
        let physical = self.internal.mapping_probes.physical.lock();
        let mut ranked = Vec::new();
        for socket in sockets {
            if self.interface_stun_provider.is_some()
                && !physical.iter().any(|p| p.ptr_eq(&Arc::downgrade(&socket))) {
                continue;
            }
            let SocketAddr::V4(endpoint) = socket.addr() else { continue };
            let id = socket.id();
            let rank = epoch.get().and_then(|m| m.ranks.get(&id)).copied().unwrap_or(1);
            ranked.push((id, endpoint, rank));
        }
        ranked.sort_by_key(|(_, _, rank)| *rank);
        let mut seen = HashSet::new();
        let mut selected = Vec::new();
        for (id, base, rank) in ranked {
            // Retain the first gathered mapping. Alternate observations can be
            // destination-specific even when every check to a different observer succeeded.
            let alias = aliases.iter().find(|(owner, _)| *owner == id)
                .and_then(|(_, c)| match c.addr() {
                    SocketAddr::V4(addr) => Some(addr),
                    _ => None,
                });
            let endpoint = if !selected.is_empty() && rank == 2 {
                alias.unwrap_or(base)
            } else {
                base
            };
            if seen.insert(endpoint) {
                selected.push((id, endpoint, rank));
            }
            if selected.len() == 3 {
                break;
            }
        }
        selected
    }

    pub async fn timed_local_candidate(&self) -> Option<Local> {
        let sockets = self.public_udp_sockets().await;
        if self.interface_stun_provider.is_some() {
            let physical = self.internal.mapping_probes.physical.lock();
            return sockets.into_iter().find(|c| physical.iter().any(|p| p.ptr_eq(&Arc::downgrade(c))));
        }
        sockets.into_iter().next()
    }

    /// The caller withholds remote trickle until this one-shot check. Use the normal
    /// signed Binding request, transaction table and existing candidate receive loop.
    pub async fn timed_first_check(&self, local_id: &str, remote_line: &str) -> bool {
        if self.get_selected_candidate_pair().is_some() || remote_line.len() > 2048 {
            return false;
        }
        let Ok(remote) = crate::candidate::candidate_base::unmarshal_candidate(remote_line) else {
            return false;
        };
        if remote.network_type() != NetworkType::Udp4 || remote.component() != 1
            || remote.candidate_type() != CandidateType::ServerReflexive
            || !matches!(remote.addr(), SocketAddr::V4(a) if a.port() != 0 && globally_reachable_ipv4(*a.ip())) {
            return false;
        }
        let local = self.internal.local_candidates.lock().await.get(&NetworkType::Udp4)
            .and_then(|v| v.iter().find(|c| c.id() == local_id && c.candidate_type() == CandidateType::ServerReflexive)).cloned();
        let Some(local) = local else { return false };
        {
            let credentials = self.internal.ufrag_pwd.lock().await;
            if credentials.remote_ufrag.is_empty() || credentials.remote_pwd.is_empty() {
                return false;
            }
        }
        let pair = crate::candidate::CandidatePair::new(local, Arc::new(remote),
            self.internal.is_controlling.load(Ordering::SeqCst));
        self.internal.ping_candidate(&pair).await;
        let written = pair.check_io.lock().requests_sent != 0;
        written
    }

    async fn collect_mappings(self: &Arc<Self>) -> Result<Measurement, ()> {
        let locals = self.public_udp_sockets().await;
        // Do not cache a missing candidate during trickle gathering. A later call can retry.
        if locals.is_empty() { return Err(()); }
        let mut work = JoinSet::new();
        for candidate in locals.into_iter().take(MAX_SOCKETS) {
            let agent = self.clone();
            work.spawn(async move {
                let endpoints = agent.observers(&candidate).await;
                let sample = sample(&agent.internal.mapping_probes, &candidate, &endpoints, agent.grouped_physical_stun).await;
                (candidate, sample)
            });
        }
        let total = work.len() as u32;
        let mut measurement = Measurement::default();
        // Dropping the JoinSet aborts stalled resolution/sends without retaining the sockets.
        let limit = if self.grouped_physical_stun { Duration::from_secs(5) } else { Duration::from_secs(3) };
        let _ = timeout(limit, async {
            while let Some(result) = work.join_next().await {
                if let Ok((candidate, sample)) = result {
                    sample.record(&mut measurement.stats);
                    let base = candidate.addr();
                    let rank = if sample.mappings.len() < 2 {
                        1 // insufficient observations
                    } else if sample.mappings.iter().all(|m| SocketAddr::V4(*m) == base) {
                        0 // multiple destinations saw the advertised endpoint
                    } else {
                        2 // at least one observation disagrees with the advertised endpoint
                    };
                    measurement.ranks.insert(candidate.id(), rank);
                    let mut alternates = Vec::new();
                    // The final observation, when present, is the alternate-port test.
                    for addr in sample.mappings.into_iter().rev() {
                        if IpAddr::V4(*addr.ip()) == base.ip()
                            && addr.port() != base.port()
                            && !alternates.contains(&addr)
                        {
                            alternates.push(addr);
                            if alternates.len() == MAX_MAPPINGS_PER_SOCKET {
                                break;
                            }
                        }
                    }
                    if !alternates.is_empty() {
                        measurement
                            .alternates
                            .push((Arc::downgrade(&candidate), alternates));
                    }
                }
            }
        })
        .await;
        if self.grouped_physical_stun {
            measurement.stats.ordered_profiles[3] += total - measurement.stats.sockets;
        }
        measurement.stats.inconclusive += total - measurement.stats.sockets;
        measurement.stats.sockets = total;
        Ok(measurement)
    }

    async fn observers(&self, socket: &Local) -> Vec<SocketAddr> {
        let Some(conn) = socket.get_conn() else {
            return vec![];
        };
        let bind = conn.local_addr().ok();
        let physical = bind.and_then(|a| match a.ip() {
            IpAddr::V4(v) => self
                .interface_stun_provider
                .as_ref()
                .filter(|p| p.supports_source(v))
                .map(|p| (p, v)),
            _ => None,
        });
        let mut urls: Vec<&Url> = self
            .urls
            .iter()
            .filter(|u| u.scheme == SchemeType::Stun && u.proto == ProtoType::Udp)
            .take(8)
            .collect();
        urls.sort_by_key(|u| u.port != 443);
        let resolving = urls.into_iter().map(|url| async move {
            let resolve = async {
                if let Some((provider, source)) = physical {
                    return provider
                        .resolve_for_socket(source, &url.host, url.port)
                        .await
                        .filter(|ep| ep.port() == url.port)
                        .map(SocketAddr::V4);
                }
                let host = format!("{}:{}", url.host, url.port);
                if let Ok(addr) = self.net.resolve_addr(true, &host).await {
                    if matches!(addr.ip(), IpAddr::V4(ip) if globally_reachable_ipv4(ip)) {
                        return Some(addr);
                    }
                }
                #[cfg(any(target_os = "ios", test))]
                if bind.is_some_and(|s| s.is_ipv6()) {
                    let v6 = self.net.resolve_addr(false, &host).await.ok()?;
                    return crate::nat64::observer_v4(conn, v6);
                }
                None
            };
            let endpoint = timeout(Duration::from_millis(470), resolve)
                .await
                .ok()
                .flatten();
            endpoint.filter(|ep| {
                matches!(ep.ip(),IpAddr::V4(v) if globally_reachable_ipv4(v))
                    && ep.port() == url.port
            })
        });
        let mut out = Vec::new();
        for ep in join_all(resolving).await.into_iter().flatten() {
            if !out.contains(&ep) {
                out.push(ep);
            }
            if out.len() == MAX_OBSERVERS {
                break;
            }
        }
        out
    }

    /// Coalesces with ordinary candidate/gather triggers. Uses the selector, credentials,
    /// state and per-pair retry limits of the existing ICE agent.
    pub async fn request_connectivity_check(&self) -> bool {
        if self.internal.connection_state.load(Ordering::SeqCst)
            != crate::state::ConnectionState::Checking as u8
            || self.get_selected_candidate_pair().is_some()
        {
            return false;
        }
        {
            let creds = self.internal.ufrag_pwd.lock().await;
            if creds.remote_ufrag.is_empty() || creds.remote_pwd.is_empty() {
                return false;
            }
        }
        if !self
            .internal
            .agent_conn
            .checklist
            .lock()
            .await
            .iter()
            .any(|p| {
                p.local.network_type().is_udp()
                    && p.remote.network_type().is_udp()
                    && p.local.candidate_type() != CandidateType::Relay
                    && p.remote.candidate_type() != CandidateType::Relay
                    && matches!(
                        CandidatePairState::from(p.state.load(Ordering::SeqCst)),
                        CandidatePairState::Waiting | CandidatePairState::InProgress
                    )
            })
        {
            return false;
        }
        self.internal.wake_synchronized_check();
        true
    }
}

#[cfg(test)]
#[path = "mapping_probe_test.rs"]
mod tests;

#[cfg(test)]
mod ordered_profile_tests {
    use super::*;

    #[test]
    fn distinguishes_ordered_port_patterns_without_predicting_from_missing_samples() {
        let make = |ports: &[u16]| ports.iter().map(|&p| SocketAddrV4::new(
            "198.51.100.7".parse().unwrap(), p)).collect::<Vec<_>>();
        assert_eq!(observed_profile(&make(&[4000,4000])),0);
        assert_eq!(observed_profile(&make(&[100,103,106,109])),1);
        assert_eq!(observed_profile(&make(&[115,110,105,100])),1);
        assert_eq!(observed_profile(&make(&[100,113,104,101])),2);
        assert_eq!(observed_profile(&make(&[100,101,102])),3);
        let mut changed=make(&[101,101,101,101]);
        changed[2].set_ip("198.51.100.8".parse().unwrap());
        assert_eq!(observed_profile(&changed),3);
    }
}
