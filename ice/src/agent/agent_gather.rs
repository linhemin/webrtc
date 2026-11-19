use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::Arc;

use util::vnet::net::*;
use util::Conn;
use waitgroup::WaitGroup;

use super::*;
use crate::candidate::candidate_base::CandidateBaseConfig;
use crate::candidate::candidate_host::CandidateHostConfig;
use crate::candidate::candidate_relay::CandidateRelayConfig;
use crate::candidate::candidate_server_reflexive::CandidateServerReflexiveConfig;
use crate::candidate::*;
use crate::error::*;
use crate::network_type::*;
use crate::udp_network::UDPNetwork;
use crate::url::{ProtoType, SchemeType, Url};
use crate::util::*;

const STUN_GATHER_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) struct GatherCandidatesInternalParams {
    pub(crate) udp_network: UDPNetwork,
    pub(crate) candidate_types: Vec<CandidateType>,
    pub(crate) urls: Vec<Url>,
    pub(crate) network_types: Vec<NetworkType>,
    pub(crate) mdns_mode: MulticastDnsMode,
    pub(crate) mdns_name: String,
    pub(crate) net: Arc<Net>,
    pub(crate) interface_filter: Arc<Option<InterfaceFilterFn>>,
    pub(crate) ip_filter: Arc<Option<IpFilterFn>>,
    pub(crate) gather_interface_srflx: bool,
    pub(crate) ext_ip_mapper: Arc<Option<ExternalIpMapper>>,
    pub(crate) agent_internal: Arc<AgentInternal>,
    pub(crate) gathering_state: Arc<AtomicU8>,
    pub(crate) chan_candidate_tx: ChanCandidateTx,
    pub(crate) include_loopback: bool,
}

struct GatherCandidatesLocalParams {
    udp_network: UDPNetwork,
    network_types: Vec<NetworkType>,
    mdns_mode: MulticastDnsMode,
    mdns_name: String,
    interface_filter: Arc<Option<InterfaceFilterFn>>,
    ip_filter: Arc<Option<IpFilterFn>>,
    ext_ip_mapper: Arc<Option<ExternalIpMapper>>,
    net: Arc<Net>,
    agent_internal: Arc<AgentInternal>,
    include_loopback: bool,
}

struct GatherCandidatesLocalUDPMuxParams {
    network_types: Vec<NetworkType>,
    interface_filter: Arc<Option<InterfaceFilterFn>>,
    ip_filter: Arc<Option<IpFilterFn>>,
    ext_ip_mapper: Arc<Option<ExternalIpMapper>>,
    net: Arc<Net>,
    agent_internal: Arc<AgentInternal>,
    udp_mux: Arc<dyn UDPMux + Send + Sync>,
    include_loopback: bool,
}

struct GatherCandidatesSrflxMappedParasm {
    network_types: Vec<NetworkType>,
    port_max: u16,
    port_min: u16,
    ext_ip_mapper: Arc<Option<ExternalIpMapper>>,
    net: Arc<Net>,
    agent_internal: Arc<AgentInternal>,
}

struct GatherCandidatesSrflxParams {
    urls: Vec<Url>,
    network_types: Vec<NetworkType>,
    port_max: u16,
    port_min: u16,
    net: Arc<Net>,
    agent_internal: Arc<AgentInternal>,
}

impl Agent {
    pub(crate) async fn gather_candidates_internal(params: GatherCandidatesInternalParams) {
        Self::set_gathering_state(
            &params.chan_candidate_tx,
            &params.gathering_state,
            GatheringState::Gathering,
        )
        .await;

        let wg = WaitGroup::new();

        for t in &params.candidate_types {
            match t {
                CandidateType::Host => {
                    let local_params = GatherCandidatesLocalParams {
                        udp_network: params.udp_network.clone(),
                        network_types: params.network_types.clone(),
                        mdns_mode: params.mdns_mode,
                        mdns_name: params.mdns_name.clone(),
                        interface_filter: Arc::clone(&params.interface_filter),
                        ip_filter: Arc::clone(&params.ip_filter),
                        ext_ip_mapper: Arc::clone(&params.ext_ip_mapper),
                        net: Arc::clone(&params.net),
                        agent_internal: Arc::clone(&params.agent_internal),
                        include_loopback: params.include_loopback,
                    };

                    let w = wg.worker();
                    tokio::spawn(async move {
                        let _d = w;

                        Self::gather_candidates_local(local_params).await;
                    });
                }
                CandidateType::ServerReflexive => {
                    let ephemeral_config = match &params.udp_network {
                        UDPNetwork::Ephemeral(e) => e,
                        // No server reflexive for muxxed connections
                        UDPNetwork::Muxed(_) => continue,
                    };

                    let srflx_params = Arc::new(GatherCandidatesSrflxParams {
                        urls: params.urls.clone(),
                        network_types: params.network_types.clone(),
                        port_max: ephemeral_config.port_max(),
                        port_min: ephemeral_config.port_min(),
                        net: Arc::clone(&params.net),
                        agent_internal: Arc::clone(&params.agent_internal),
                    });
                    let wildcard = Arc::clone(&srflx_params);
                    let w1 = wg.worker();
                    tokio::spawn(async move {
                        let _d = w1;
                        Self::gather_candidates_srflx(wildcard).await;
                    });

                    // The related address of a bound srflx candidate is its local IP.
                    // Only expose it if this session already permits advertising that host IP.
                    if params.gather_interface_srflx
                        && params.candidate_types.contains(&CandidateType::Host)
                        && params.mdns_mode != MulticastDnsMode::QueryAndGather
                        && params.ext_ip_mapper.is_none()
                    {
                        let interface_filter = Arc::clone(&params.interface_filter);
                        let ip_filter = Arc::clone(&params.ip_filter);
                        let include_loopback = params.include_loopback;
                        let worker = wg.worker();
                        tokio::spawn(async move {
                            let _worker = worker;
                            Self::gather_interface_srflx(
                                srflx_params,
                                interface_filter,
                                ip_filter,
                                include_loopback,
                            )
                            .await;
                        });
                    }
                    if let Some(ext_ip_mapper) = &*params.ext_ip_mapper {
                        if ext_ip_mapper.candidate_type == CandidateType::ServerReflexive {
                            let srflx_mapped_params = GatherCandidatesSrflxMappedParasm {
                                network_types: params.network_types.clone(),
                                port_max: ephemeral_config.port_max(),
                                port_min: ephemeral_config.port_min(),
                                ext_ip_mapper: Arc::clone(&params.ext_ip_mapper),
                                net: Arc::clone(&params.net),
                                agent_internal: Arc::clone(&params.agent_internal),
                            };
                            let w2 = wg.worker();
                            tokio::spawn(async move {
                                let _d = w2;

                                Self::gather_candidates_srflx_mapped(srflx_mapped_params).await;
                            });
                        }
                    }
                }
                CandidateType::Relay => {
                    let urls = params.urls.clone();
                    let net = Arc::clone(&params.net);
                    let agent_internal = Arc::clone(&params.agent_internal);
                    let w = wg.worker();
                    tokio::spawn(async move {
                        let _d = w;

                        Self::gather_candidates_relay(urls, net, agent_internal).await;
                    });
                }
                _ => {}
            }
        }

        // Block until all STUN and TURN URLs have been gathered (or timed out)
        wg.wait().await;

        Self::set_gathering_state(
            &params.chan_candidate_tx,
            &params.gathering_state,
            GatheringState::Complete,
        )
        .await;
    }

    async fn set_gathering_state(
        chan_candidate_tx: &ChanCandidateTx,
        gathering_state: &Arc<AtomicU8>,
        new_state: GatheringState,
    ) {
        if GatheringState::from(gathering_state.load(Ordering::SeqCst)) != new_state
            && new_state == GatheringState::Complete
        {
            let cand_tx = chan_candidate_tx.lock().await;
            if let Some(tx) = &*cand_tx {
                let _ = tx.send(None).await;
            }
        }

        gathering_state.store(new_state as u8, Ordering::SeqCst);
    }

    async fn gather_candidates_local(params: GatherCandidatesLocalParams) {
        let GatherCandidatesLocalParams {
            udp_network,
            network_types,
            mdns_mode,
            mdns_name,
            interface_filter,
            ip_filter,
            ext_ip_mapper,
            net,
            agent_internal,
            include_loopback,
        } = params;

        // If we wanna use UDP mux, do so
        // FIXME: We still need to support TCP in combination with this option
        if let UDPNetwork::Muxed(udp_mux) = udp_network {
            let result = Self::gather_candidates_local_udp_mux(GatherCandidatesLocalUDPMuxParams {
                network_types,
                interface_filter,
                ip_filter,
                ext_ip_mapper,
                net,
                agent_internal,
                udp_mux,
                include_loopback,
            })
            .await;

            if let Err(err) = result {
                log::error!("Failed to gather local candidates using UDP mux: {}", err);
            }

            return;
        }

        let ips = local_interfaces(
            &net,
            &interface_filter,
            &ip_filter,
            &network_types,
            include_loopback,
        )
        .await;
        for ip in ips {
            let mut mapped_ip = ip;

            if mdns_mode != MulticastDnsMode::QueryAndGather && ext_ip_mapper.is_some() {
                if let Some(ext_ip_mapper2) = ext_ip_mapper.as_ref() {
                    if ext_ip_mapper2.candidate_type == CandidateType::Host {
                        if let Ok(mi) = ext_ip_mapper2.find_external_ip(&ip.to_string()) {
                            mapped_ip = mi;
                        } else {
                            log::warn!(
                                "[{}]: 1:1 NAT mapping is enabled but no external IP is found for {}",
                                agent_internal.get_name(),
                                ip
                            );
                        }
                    }
                }
            }

            let address = if mdns_mode == MulticastDnsMode::QueryAndGather {
                mdns_name.clone()
            } else {
                mapped_ip.to_string()
            };

            //TODO: for network in networks
            let network = UDP.to_owned();
            if let UDPNetwork::Ephemeral(ephemeral_config) = &udp_network {
                /*TODO:switch network {
                case tcp:
                    // Handle ICE TCP passive mode

                    a.log.Debugf("GetConn by ufrag: %s\n", a.localUfrag)
                    conn, err = a.tcpMux.GetConnByUfrag(a.localUfrag)
                    if err != nil {
                        if !errors.Is(err, ErrTCPMuxNotInitialized) {
                            a.log.Warnf("error getting tcp conn by ufrag: %s %s %s\n", network, ip, a.localUfrag)
                        }
                        continue
                    }
                    port = conn.LocalAddr().(*net.TCPAddr).Port
                    tcpType = TCPTypePassive
                    // is there a way to verify that the listen address is even
                    // accessible from the current interface.
                case udp:*/

                let conn: Arc<dyn Conn + Send + Sync> = match listen_udp_in_port_range(
                    &net,
                    ephemeral_config.port_max(),
                    ephemeral_config.port_min(),
                    SocketAddr::new(ip, 0),
                )
                .await
                {
                    Ok(conn) => conn,
                    Err(err) => {
                        log::warn!(
                            "[{}]: could not listen {} {}: {}",
                            agent_internal.get_name(),
                            network,
                            ip,
                            err
                        );
                        continue;
                    }
                };

                let port = match conn.local_addr() {
                    Ok(addr) => addr.port(),
                    Err(err) => {
                        log::warn!(
                            "[{}]: could not get local addr: {}",
                            agent_internal.get_name(),
                            err
                        );
                        continue;
                    }
                };

                let host_config = CandidateHostConfig {
                    base_config: CandidateBaseConfig {
                        network: network.clone(),
                        address,
                        port,
                        component: COMPONENT_RTP,
                        conn: Some(conn),
                        ..CandidateBaseConfig::default()
                    },
                    ..CandidateHostConfig::default()
                };

                let candidate: Arc<dyn Candidate + Send + Sync> =
                    match host_config.new_candidate_host() {
                        Ok(candidate) => {
                            if mdns_mode == MulticastDnsMode::QueryAndGather {
                                if let Err(err) = candidate.set_ip(&ip) {
                                    log::warn!(
                                        "[{}]: Failed to create host candidate: {} {} {}: {:?}",
                                        agent_internal.get_name(),
                                        network,
                                        mapped_ip,
                                        port,
                                        err
                                    );
                                    continue;
                                }
                            }
                            Arc::new(candidate)
                        }
                        Err(err) => {
                            log::warn!(
                                "[{}]: Failed to create host candidate: {} {} {}: {}",
                                agent_internal.get_name(),
                                network,
                                mapped_ip,
                                port,
                                err
                            );
                            continue;
                        }
                    };

                {
                    if let Err(err) = agent_internal.add_candidate(&candidate).await {
                        if let Err(close_err) = candidate.close().await {
                            log::warn!(
                                "[{}]: Failed to close candidate: {}",
                                agent_internal.get_name(),
                                close_err
                            );
                        }
                        log::warn!(
                            "[{}]: Failed to append to localCandidates and run onCandidateHdlr: {}",
                            agent_internal.get_name(),
                            err
                        );
                    }
                }
            }
        }
    }

    async fn gather_candidates_local_udp_mux(
        params: GatherCandidatesLocalUDPMuxParams,
    ) -> Result<()> {
        let GatherCandidatesLocalUDPMuxParams {
            network_types,
            interface_filter,
            ip_filter,
            ext_ip_mapper,
            net,
            agent_internal,
            udp_mux,
            include_loopback,
        } = params;

        // Filter out non UDP network types
        let relevant_network_types: Vec<_> =
            network_types.into_iter().filter(|n| n.is_udp()).collect();

        let udp_mux = Arc::clone(&udp_mux);

        let local_ips = local_interfaces(
            &net,
            &interface_filter,
            &ip_filter,
            &relevant_network_types,
            include_loopback,
        )
        .await;

        let candidate_ips: Vec<std::net::IpAddr> = ext_ip_mapper
            .as_ref() // Arc
            .as_ref() // Option
            .and_then(|mapper| {
                if mapper.candidate_type != CandidateType::Host {
                    return None;
                }

                Some(
                    local_ips
                        .iter()
                        .filter_map(|ip| match mapper.find_external_ip(&ip.to_string()) {
                            Ok(ip) => Some(ip),
                            Err(err) => {
                                log::warn!(
                            "1:1 NAT mapping is enabled but not external IP is found for {}: {}",
                            ip,
                            err
                        );
                                None
                            }
                        })
                        .collect(),
                )
            })
            .unwrap_or_else(|| local_ips.iter().copied().collect());

        if candidate_ips.is_empty() {
            return Err(Error::ErrCandidateIpNotFound);
        }

        let ufrag = {
            let ufrag_pwd = agent_internal.ufrag_pwd.lock().await;

            ufrag_pwd.local_ufrag.clone()
        };

        let conn = udp_mux.get_conn(&ufrag).await?;
        let port = conn.local_addr()?.port();

        for candidate_ip in candidate_ips {
            let host_config = CandidateHostConfig {
                base_config: CandidateBaseConfig {
                    network: UDP.to_owned(),
                    address: candidate_ip.to_string(),
                    port,
                    conn: Some(conn.clone()),
                    component: COMPONENT_RTP,
                    ..Default::default()
                },
                tcp_type: TcpType::Unspecified,
            };

            let candidate: Arc<dyn Candidate + Send + Sync> =
                Arc::new(host_config.new_candidate_host()?);

            agent_internal.add_candidate(&candidate).await?;
        }

        Ok(())
    }

    async fn gather_candidates_srflx_mapped(params: GatherCandidatesSrflxMappedParasm) {
        let GatherCandidatesSrflxMappedParasm {
            network_types,
            port_max,
            port_min,
            ext_ip_mapper,
            net,
            agent_internal,
        } = params;

        let wg = WaitGroup::new();

        for network_type in network_types {
            if network_type.is_tcp() {
                continue;
            }

            let network = network_type.to_string();
            let net2 = Arc::clone(&net);
            let agent_internal2 = Arc::clone(&agent_internal);
            let ext_ip_mapper2 = Arc::clone(&ext_ip_mapper);

            let w = wg.worker();
            tokio::spawn(async move {
                let _d = w;

                let conn: Arc<dyn Conn + Send + Sync> = match listen_udp_in_port_range(
                    &net2,
                    port_max,
                    port_min,
                    if network_type.is_ipv4() {
                        SocketAddr::new(Ipv4Addr::new(0, 0, 0, 0).into(), 0)
                    } else {
                        SocketAddr::new(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0).into(), 0)
                    },
                )
                .await
                {
                    Ok(conn) => conn,
                    Err(err) => {
                        log::warn!(
                            "[{}]: Failed to listen {}: {}",
                            agent_internal2.get_name(),
                            network,
                            err
                        );
                        return Ok(());
                    }
                };

                let laddr = conn.local_addr()?;
                let mapped_ip = {
                    if let Some(ext_ip_mapper3) = &*ext_ip_mapper2 {
                        match ext_ip_mapper3.find_external_ip(&laddr.ip().to_string()) {
                            Ok(ip) => ip,
                            Err(err) => {
                                log::warn!(
                                    "[{}]: 1:1 NAT mapping is enabled but no external IP is found for {}: {}",
                                    agent_internal2.get_name(),
                                    laddr,
                                    err
                                );
                                return Ok(());
                            }
                        }
                    } else {
                        log::error!(
                            "[{}]: ext_ip_mapper is None in gather_candidates_srflx_mapped",
                            agent_internal2.get_name(),
                        );
                        return Ok(());
                    }
                };

                let srflx_config = CandidateServerReflexiveConfig {
                    base_config: CandidateBaseConfig {
                        network: network.clone(),
                        address: mapped_ip.to_string(),
                        port: laddr.port(),
                        component: COMPONENT_RTP,
                        conn: Some(conn),
                        ..CandidateBaseConfig::default()
                    },
                    rel_addr: laddr.ip().to_string(),
                    rel_port: laddr.port(),
                };

                let candidate: Arc<dyn Candidate + Send + Sync> =
                    match srflx_config.new_candidate_server_reflexive() {
                        Ok(candidate) => Arc::new(candidate),
                        Err(err) => {
                            log::warn!(
                                "[{}]: Failed to create server reflexive candidate: {} {} {}: {}",
                                agent_internal2.get_name(),
                                network,
                                mapped_ip,
                                laddr.port(),
                                err
                            );
                            return Ok(());
                        }
                    };

                {
                    if let Err(err) = agent_internal2.add_candidate(&candidate).await {
                        if let Err(close_err) = candidate.close().await {
                            log::warn!(
                                "[{}]: Failed to close candidate: {}",
                                agent_internal2.get_name(),
                                close_err
                            );
                        }
                        log::warn!(
                            "[{}]: Failed to append to localCandidates and run onCandidateHdlr: {}",
                            agent_internal2.get_name(),
                            err
                        );
                    }
                }

                Result::<()>::Ok(())
            });
        }

        wg.wait().await;
    }

    async fn gather_candidates_srflx(params: Arc<GatherCandidatesSrflxParams>) {
        let wg = WaitGroup::new();
        for network in params.network_types.iter().filter(|n| n.is_udp()) {
            let source = if network.is_ipv4() {
                IpAddr::V4(Ipv4Addr::UNSPECIFIED)
            } else {
                IpAddr::V6(Ipv6Addr::UNSPECIFIED)
            };
            for url in &params.urls {
                let worker = wg.worker();
                let params = Arc::clone(&params);
                let url = url.clone();
                tokio::spawn(async move {
                    let _worker = worker;
                    if let Err(err) = Self::gather_srflx_from(&params, source, &url, None).await {
                        log::warn!(
                            "[{}]: failed to gather server reflexive candidate: {}",
                            params.agent_internal.get_name(),
                            err
                        );
                    }
                });
            }
        }
        wg.wait().await;
    }

    async fn gather_interface_srflx(
        params: Arc<GatherCandidatesSrflxParams>,
        interface_filter: Arc<Option<InterfaceFilterFn>>,
        ip_filter: Arc<Option<IpFilterFn>>,
        include_loopback: bool,
    ) {
        const MAX_SOURCES_PER_FAMILY: usize = 4;
        const MAX_STUN_SERVERS: usize = 2;
        let mut urls: Vec<Url> = Vec::new();
        for url in &params.urls {
            if url.scheme == SchemeType::Stun
                && url.proto == ProtoType::Udp
                && !urls
                    .iter()
                    .any(|v| v.host.eq_ignore_ascii_case(&url.host) && v.port == url.port)
            {
                urls.push(url.clone());
                if urls.len() == MAX_STUN_SERVERS {
                    break;
                }
            }
        }
        if urls.is_empty() {
            return;
        }
        let udp_types: Vec<_> = params
            .network_types
            .iter()
            .copied()
            .filter(|n| n.is_udp())
            .collect();
        let deadline = Instant::now() + STUN_GATHER_TIMEOUT;
        let gather_sources = local_interfaces(
            &params.net,
            &interface_filter,
            &ip_filter,
            &udp_types,
            include_loopback,
        );
        let Ok(sources) = tokio::time::timeout_at(deadline, gather_sources).await else {
            return;
        };
        // HashSet iteration also lets later ICE attempts sample different local addresses
        // on hosts with more candidates than the per-family socket budget.
        let urls = Arc::new(urls);
        let wg = WaitGroup::new();
        for v4 in [true, false] {
            for &source in sources
                .iter()
                .filter(|s| !s.is_unspecified() && s.is_ipv4() == v4)
                .take(MAX_SOURCES_PER_FAMILY)
            {
                let worker = wg.worker();
                let params = Arc::clone(&params);
                let urls = Arc::clone(&urls);
                tokio::spawn(async move {
                    let _worker = worker;
                    for (index, url) in urls.iter().enumerate() {
                        let now = Instant::now();
                        if now >= deadline {
                            break;
                        }
                        let slice = (deadline - now) / (urls.len() - index) as u32;
                        if Self::gather_srflx_from(&params, source, url, Some(now + slice))
                            .await
                            .is_ok()
                        {
                            break;
                        }
                    }
                });
            }
        }
        wg.wait().await;
    }

    async fn gather_srflx_from(
        params: &GatherCandidatesSrflxParams,
        source: IpAddr,
        url: &Url,
        deadline: Option<Instant>,
    ) -> Result<()> {
        async fn before<T, E: Into<Error>>(
            deadline: Option<Instant>,
            operation: impl Future<Output = std::result::Result<T, E>>,
        ) -> Result<T> {
            let result = if let Some(end) = deadline {
                tokio::time::timeout_at(end, operation)
                    .await
                    .map_err(|_| Error::ErrGetXorMappedAddrResponse)?
            } else {
                operation.await
            };
            result.map_err(Into::into)
        }
        let host_port = match url.host.parse::<Ipv6Addr>() {
            Ok(ip) => SocketAddr::new(IpAddr::V6(ip), url.port).to_string(),
            Err(_) => format!("{}:{}", url.host, url.port),
        };
        let remote = before(
            deadline,
            params.net.resolve_addr(source.is_ipv4(), &host_port),
        )
        .await?;
        let conn = before(
            deadline,
            listen_udp_in_port_range(
                &params.net,
                params.port_max,
                params.port_min,
                SocketAddr::new(source, 0),
            ),
        )
        .await?;
        let built = async {
            let mapped = before(
                deadline,
                get_xormapped_addr(&conn, remote, STUN_GATHER_TIMEOUT),
            )
            .await?;
            let local = conn.local_addr()?;
            let config = CandidateServerReflexiveConfig {
                base_config: CandidateBaseConfig {
                    network: if source.is_ipv4() {
                        NetworkType::Udp4
                    } else {
                        NetworkType::Udp6
                    }
                    .to_string(),
                    address: mapped.ip.to_string(),
                    port: mapped.port,
                    component: COMPONENT_RTP,
                    conn: Some(Arc::clone(&conn)),
                    ..Default::default()
                },
                rel_addr: local.ip().to_string(),
                rel_port: local.port(),
            };
            config.new_candidate_server_reflexive()
        }
        .await;
        // VNet keeps its own socket-map reference; dropping a failed STUN socket alone
        // doesn't release the port there. A registered candidate instead owns this socket.
        let candidate: Arc<dyn Candidate + Send + Sync> = match built {
            Ok(candidate) => Arc::new(candidate),
            Err(err) => {
                let _ = conn.close().await;
                return Err(err);
            }
        };
        if let Err(err) = params.agent_internal.add_candidate(&candidate).await {
            let _ = candidate.close().await;
            return Err(err);
        }
        Ok(())
    }

    pub(crate) async fn gather_candidates_relay(
        urls: Vec<Url>,
        net: Arc<Net>,
        agent_internal: Arc<AgentInternal>,
    ) {
        let wg = WaitGroup::new();

        for url in urls {
            if url.scheme != SchemeType::Turn && url.scheme != SchemeType::Turns {
                continue;
            }
            if url.username.is_empty() {
                log::error!(
                    "[{}]:Failed to gather relay candidates: {:?}",
                    agent_internal.get_name(),
                    Error::ErrUsernameEmpty
                );
                return;
            }
            if url.password.is_empty() {
                log::error!(
                    "[{}]: Failed to gather relay candidates: {:?}",
                    agent_internal.get_name(),
                    Error::ErrPasswordEmpty
                );
                return;
            }

            let network = NetworkType::Udp4.to_string();
            let net2 = Arc::clone(&net);
            let agent_internal2 = Arc::clone(&agent_internal);

            let w = wg.worker();
            tokio::spawn(async move {
                let _d = w;

                let turn_server_addr = format!("{}:{}", url.host, url.port);

                let (loc_conn, rel_addr, rel_port) =
                    if url.proto == ProtoType::Udp && url.scheme == SchemeType::Turn {
                        let loc_conn = match net2.bind(SocketAddr::from_str("0.0.0.0:0")?).await {
                            Ok(c) => c,
                            Err(err) => {
                                log::warn!(
                                    "[{}]: Failed to listen due to error: {}",
                                    agent_internal2.get_name(),
                                    err
                                );
                                return Ok(());
                            }
                        };

                        let local_addr = loc_conn.local_addr()?;
                        let rel_addr = local_addr.ip().to_string();
                        let rel_port = local_addr.port();
                        (loc_conn, rel_addr, rel_port)
                    /*TODO: case url.proto == ProtoType::UDP && url.scheme == SchemeType::TURNS{
                    case a.proxyDialer != nil && url.Proto == ProtoTypeTCP && (url.Scheme == SchemeTypeTURN || url.Scheme == SchemeTypeTURNS):
                    case url.Proto == ProtoTypeTCP && url.Scheme == SchemeTypeTURN:
                    case url.Proto == ProtoTypeTCP && url.Scheme == SchemeTypeTURNS:*/
                    } else {
                        log::warn!(
                            "[{}]: Unable to handle URL in gather_candidates_relay {}",
                            agent_internal2.get_name(),
                            url
                        );
                        return Ok(());
                    };

                let cfg = turn::client::ClientConfig {
                    stun_serv_addr: String::new(),
                    turn_serv_addr: turn_server_addr.clone(),
                    username: url.username,
                    password: url.password,
                    realm: String::new(),
                    software: String::new(),
                    rto_in_ms: 0,
                    conn: loc_conn,
                    vnet: Some(Arc::clone(&net2)),
                };
                let client = match turn::client::Client::new(cfg).await {
                    Ok(client) => Arc::new(client),
                    Err(err) => {
                        log::warn!(
                            "[{}]: Failed to build new turn.Client {} {}\n",
                            agent_internal2.get_name(),
                            turn_server_addr,
                            err
                        );
                        return Ok(());
                    }
                };
                if let Err(err) = client.listen().await {
                    let _ = client.close().await;
                    log::warn!(
                        "[{}]: Failed to listen on turn.Client {} {}",
                        agent_internal2.get_name(),
                        turn_server_addr,
                        err
                    );
                    return Ok(());
                }

                let relay_conn: Arc<dyn Conn + Send + Sync> = match client.allocate().await {
                    Ok(conn) => Arc::new(conn),
                    Err(err) => {
                        let _ = client.close().await;
                        log::warn!(
                            "[{}]: Failed to allocate on turn.Client {} {}",
                            agent_internal2.get_name(),
                            turn_server_addr,
                            err
                        );
                        return Ok(());
                    }
                };

                let raddr = relay_conn.local_addr()?;
                let relay_config = CandidateRelayConfig {
                    base_config: CandidateBaseConfig {
                        network: network.clone(),
                        address: raddr.ip().to_string(),
                        port: raddr.port(),
                        component: COMPONENT_RTP,
                        conn: Some(Arc::clone(&relay_conn)),
                        ..CandidateBaseConfig::default()
                    },
                    rel_addr,
                    rel_port,
                    relay_client: Some(Arc::clone(&client)),
                };

                let candidate: Arc<dyn Candidate + Send + Sync> =
                    match relay_config.new_candidate_relay() {
                        Ok(candidate) => Arc::new(candidate),
                        Err(err) => {
                            let _ = relay_conn.close().await;
                            let _ = client.close().await;
                            log::warn!(
                                "[{}]: Failed to create relay candidate: {} {}: {}",
                                agent_internal2.get_name(),
                                network,
                                raddr,
                                err
                            );
                            return Ok(());
                        }
                    };

                {
                    if let Err(err) = agent_internal2.add_candidate(&candidate).await {
                        if let Err(close_err) = candidate.close().await {
                            log::warn!(
                                "[{}]: Failed to close candidate: {}",
                                agent_internal2.get_name(),
                                close_err
                            );
                        }
                        log::warn!(
                            "[{}]: Failed to append to localCandidates and run onCandidateHdlr: {}",
                            agent_internal2.get_name(),
                            err
                        );
                    }
                }

                Result::<()>::Ok(())
            });
        }

        wg.wait().await;
    }
}
