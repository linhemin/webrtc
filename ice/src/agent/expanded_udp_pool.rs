use super::*;
use std::net::SocketAddrV4;

const CAPACITY: usize = 32;
const WAVE: usize = 4;
const BUDGET: Duration = Duration::from_secs(10);
const QUERY_WINDOW: Duration = Duration::from_millis(1100);

// The address is supplied by the application from its signature-verified observer
// list. The receiver must see the real socket before it can enter the cohort.
pub(super) async fn gather(
    params: &GatherCandidatesSrflxParams,
    sources: Vec<IpAddr>,
    observer: SocketAddrV4,
) {
    if observer.port() == 0
        || !globally_reachable_ipv4(*observer.ip())
        || !params.network_types.contains(&NetworkType::Udp4)
    {
        return;
    }
    let end = Instant::now() + BUDGET;
    let mut active = None;
    let native_sources = sources.iter().filter_map(|source| match *source {
        IpAddr::V4(ip)
            if !ip.is_unspecified()
                && params
                    .interface_stun_provider
                    .as_ref()
                    .map_or(true, |p| p.supports_source(ip)) =>
        {
            Some(ip)
        }
        _ => None,
    });
    for ip in native_sources.take(4).map(IpAddr::V4) {
        let route = (ip, SocketAddr::V4(observer));
        if gather_one(params, route, observer, end).await.is_ok() {
            active = Some(route);
            break;
        }
    }
    #[cfg(any(target_os = "ios", test))]
    if active.is_none()
        && params.interface_stun_provider.is_none()
        && params.network_types.contains(&NetworkType::Udp6)
    {
        let translated =
            tokio::time::timeout_at(end, params.dns64.stun_destinations(observer)).await;
        if let Ok(targets) = translated {
            'routes: for target in targets {
                for ip in sources
                    .iter()
                    .copied()
                    .filter(|ip| ip.is_ipv6() && !ip.is_unspecified())
                    .take(4)
                {
                    let route = (ip, target);
                    if gather_one(params, route, observer, end).await.is_ok() {
                        active = Some(route);
                        break 'routes;
                    }
                }
            }
        }
    }
    let Some(route) = active else { return };
    let mut allocated = 1;
    while allocated < CAPACITY && Instant::now() < end {
        let count = WAVE.min(CAPACITY - allocated);
        let replies = futures_util::future::join_all(
            (0..count).map(|_| gather_one(params, route, observer, end)),
        )
        .await;
        allocated += count;
        if replies.iter().all(Result::is_err) {
            break;
        }
    }
}

async fn gather_one(
    params: &GatherCandidatesSrflxParams,
    (source, target): (IpAddr, SocketAddr),
    observer: SocketAddrV4,
    end: Instant,
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
    let host = observer.ip().to_string();
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
    Agent::install_observed_socket(params, conn, target, &host, Some(deadline), true, true).await?;
    Ok(())
}
