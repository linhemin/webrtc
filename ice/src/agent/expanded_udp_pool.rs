use super::*;
use std::net::SocketAddrV4;

use super::super::agent_config::ExpandedUdpPool;

const MAX_CAPACITY: usize = 500;
const WAVE: usize = 24;
const BUDGET: Duration = Duration::from_secs(20);
const QUERY_WINDOW: Duration = Duration::from_millis(1100);
const SOCKET_INTERVAL: Duration = Duration::from_millis(16);
#[cfg(any(target_os = "ios", test))]
const NATIVE_DISCOVERY_BUDGET: Duration = Duration::from_secs(3);
#[cfg(any(target_os = "ios", test))]
const MAX_TRANSLATED_SOURCES: usize = 8;

pub(super) async fn gather(
    params: &GatherCandidatesSrflxParams,
    sources: Vec<IpAddr>,
    pool: ExpandedUdpPool,
) {
    if !params.network_types.contains(&NetworkType::Udp4) {
        return;
    }
    let capacity = usize::from(pool.capacity).min(MAX_CAPACITY);
    if capacity == 0 {
        return;
    }
    let observers: Vec<_> = pool
        .observers
        .into_iter()
        .take(4)
        .filter(|addr| addr.port() != 0 && globally_reachable_ipv4(*addr.ip()))
        .collect();
    let end = Instant::now() + BUDGET;
    let mut routes = Vec::new();
    for observer in observers.iter().copied() {
        for source in sources
            .iter()
            .copied()
            .filter(|source| match *source {
                IpAddr::V4(ip) => {
                    !ip.is_unspecified()
                        && params
                            .interface_stun_provider
                            .as_ref()
                            .map_or(true, |p| p.supports_source(ip))
                }
                IpAddr::V6(_) => false,
            })
            .take(4)
        {
            routes.push((source, SocketAddr::V4(observer), observer));
        }
    }

    #[cfg(any(target_os = "ios", test))]
    let translated_available = params.interface_stun_provider.is_none()
        && params.network_types.contains(&NetworkType::Udp6)
        && sources.iter().any(IpAddr::is_ipv6);
    #[cfg(any(target_os = "ios", test))]
    let native_end = if translated_available { end.min(Instant::now() + NATIVE_DISCOVERY_BUDGET) } else { end };
    #[cfg(not(any(target_os = "ios", test)))]
    let native_end = end;
    #[allow(unused_mut)]
    let mut active = discover(params, &routes, native_end).await;
    #[cfg(any(target_os = "ios", test))]
    if active.is_none() && translated_available {
        routes.clear();
        for observer in observers.iter().copied() {
            let translated =
                tokio::time::timeout_at(end, params.dns64.stun_destinations(observer)).await;
            if let Ok(targets) = translated {
                for target in targets {
                    let mut eligible: Vec<_> = sources
                        .iter()
                        .copied()
                        .filter(|ip| ip.is_ipv6() && !ip.is_unspecified())
                        .collect();
                    if !params.net.is_virtual() {
                        let preferred = std::net::UdpSocket::bind((Ipv6Addr::UNSPECIFIED, 0))
                            .and_then(|socket| {
                                socket.connect(target)?;
                                socket.local_addr()
                            })
                            .ok().map(|local| local.ip());
                        eligible.sort_by_key(|source| (Some(*source) != preferred, *source));
                    }
                    for source in eligible.into_iter().take(MAX_TRANSLATED_SOURCES) {
                        routes.push((source, target, observer));
                    }
                }
            }
        }
        active = discover(params, &routes, end).await;
    }

    let Some(mut route) = active else { return };
    let mut allocated = 1;
    let mut missed = 0;
    while allocated < capacity && Instant::now() < end {
        let count = WAVE.min(capacity - allocated);
        let started = Instant::now();
        let replies = futures_util::future::join_all((0..count).map(|slot| async move {
            tokio::time::sleep_until(started + SOCKET_INTERVAL * slot as u32).await;
            gather_one(params, (route.0, route.1), route.2, end, ObservationMode::PoolWave).await
        }))
        .await;
        allocated += count;
        if replies
            .iter()
            .all(|reply| matches!(reply, Err(Error::ErrClosed)))
        {
            break;
        }
        if replies.iter().any(Result::is_ok) {
            missed = 0;
        } else {
            missed += 1;
            if missed == 2 {
                // Keep the current local interface when switching the observation service.
                if let Some(next) = routes
                    .iter()
                    .cycle()
                    .skip_while(|r| **r != route)
                    .skip(1)
                    .take(routes.len())
                    .find(|r| r.0 == route.0 && r.2 != route.2)
                {
                    route = *next;
                }
            }
            if missed >= 4 {
                break;
            }
        }
    }
}

async fn discover(
    params: &GatherCandidatesSrflxParams,
    routes: &[(IpAddr, SocketAddr, SocketAddrV4)],
    end: Instant,
) -> Option<(IpAddr, SocketAddr, SocketAddrV4)> {
    for &(source, target, observer) in routes {
        match gather_one(params, (source, target), observer, end, ObservationMode::PoolDiscovery).await {
            Ok(()) => {
                log::trace!("expanded UDP discovery: IPv6={} verified", source.is_ipv6());
                return Some((source, target, observer));
            }
            Err(Error::ErrClosed) => return None,
            Err(_) => log::trace!(
                "expanded UDP discovery: IPv6={} result={}",
                source.is_ipv6(), if Instant::now() >= end { "budget expired" } else { "unverified" }
            ),
        }
    }
    None
}

async fn gather_one(
    params: &GatherCandidatesSrflxParams,
    (source, target): (IpAddr, SocketAddr),
    observer: SocketAddrV4,
    end: Instant,
    mode: ObservationMode,
) -> Result<()> {
    let deadline = end.min(Instant::now() + QUERY_WINDOW);
    if Instant::now() >= deadline
        || params.agent_internal.done_tx.lock().await.is_none()
        || params
            .agent_internal
            .agent_conn
            .get_selected_pair()
            .is_some()
    {
        return Err(Error::ErrClosed);
    }
    let seed = matches!(mode, ObservationMode::PoolDiscovery);
    let counters = &params.agent_internal.socket_rx;
    if seed {
        counters.add(|c| if target.is_ipv4() { &c.seed_ipv4 } else { &c.seed_nat64 });
    }
    let host = observer.ip().to_string();
    let bind = async {
        let conn = if let Some(provider) = &params.interface_stun_provider {
        let IpAddr::V4(source) = source else {
            return Err(Error::ErrGetXorMappedAddrResponse);
        };
        let mapping = tokio::time::timeout_at(
            deadline,
            provider.bind_and_resolve(
                source,
                &host,
                observer.port(),
                params.port_min,
                params.port_max,
            ),
        )
        .await
        .ok()
        .flatten()
        .ok_or(Error::ErrGetXorMappedAddrResponse)?;
        let (conn, endpoint) = mapping;
        let verified = conn.local_addr().is_ok_and(|a| {
            a.ip() == IpAddr::V4(source)
                && a.port() > 0
                && (params.port_min == 0 || a.port() >= params.port_min)
                && (params.port_max == 0 || a.port() <= params.port_max)
        });
        if endpoint != observer || conn.remote_addr().is_some() || !verified {
            let _ = conn.close().await;
            return Err(Error::ErrGetXorMappedAddrResponse);
        }
            conn
        } else {
        before(
            Some(deadline),
            listen_udp_in_port_range(
                &params.net,
                params.port_max,
                params.port_min,
                SocketAddr::new(source, 0),
            ),
        )
        .await?
        };
        Result::<_>::Ok(conn)
    };
    let conn = bind.await.map_err(|err| {
        if seed {
            counters.add(|c| &c.seed_bind_failed);
        }
        err
    })?;
    Agent::install_observed_socket(params, conn, target, &host, Some(deadline), true, mode).await?;
    Ok(())
}
