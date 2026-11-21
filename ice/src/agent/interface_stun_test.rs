use super::*;
use crate::agent::agent_vnet_test::{connect_net2router, start_router};
use std::net::SocketAddrV4;
use util::vnet::router::{Router, RouterConfig};

struct AdapterStun {
    net: Arc<Net>,
    endpoint: SocketAddrV4,
    requests: Mutex<Vec<(Ipv4Addr, String, u16)>>,
}

#[async_trait::async_trait]
impl InterfaceStunProvider for AdapterStun {
    fn supports_source(&self, source: Ipv4Addr) -> bool {
        source.octets()[0] == 10
    }

    async fn bind_and_resolve(
        &self,
        source: Ipv4Addr,
        host: &str,
        server_port: u16,
        min: u16,
        max: u16,
    ) -> Option<(Arc<dyn Conn + Send + Sync>, SocketAddrV4)> {
        self.requests
            .lock()
            .await
            .push((source, host.to_owned(), server_port));
        let conn = listen_udp_in_port_range(&self.net, max, min, SocketAddr::from((source, 0)))
            .await
            .ok()?;
        Some((conn, self.endpoint))
    }
}

async fn serve(
    socket: Arc<dyn Conn + Send + Sync>,
    mapped_ip: IpAddr,
    corrupt: bool,
    data: mpsc::Sender<SocketAddr>,
) {
    let mut buf = [0u8; 1200];
    while let Ok((n, src)) = socket.recv_from(&mut buf).await {
        if &buf[..n] == b"selected-pair data" {
            let _ = data.send(src).await;
            continue;
        }
        let mut message = Message::new();
        message.raw = buf[..n].to_vec();
        message.decode().unwrap();
        if message.contains(ATTR_USERNAME) && message.contains(ATTR_MESSAGE_INTEGRITY) {
            let _ = data.send(src).await;
            continue;
        }
        let tx = if corrupt {
            TransactionId::new()
        } else {
            message.transaction_id
        };
        let mut reply = Message::new();
        reply
            .build(&[
                Box::new(BINDING_SUCCESS),
                Box::new(tx),
                Box::new(XorMappedAddress {
                    ip: mapped_ip,
                    port: src.port(),
                }),
            ])
            .unwrap();
        socket.send_to(&reply.raw, src).await.unwrap();
    }
}

#[tokio::test]
async fn interface_stun_keeps_the_verified_socket_and_preserves_the_system_path() -> Result<()> {
    let router = Arc::new(Mutex::new(Router::new(RouterConfig {
        cidr: "10.0.0.0/24".into(),
        ..Default::default()
    })?));
    let local = Arc::new(Net::new(Some(NetConfig {
        static_ips: ["10.0.0.20", "10.0.0.21", "10.0.0.22"]
            .map(str::to_owned)
            .to_vec(),
        ..Default::default()
    })));
    let server = Arc::new(Net::new(Some(NetConfig {
        static_ips: ["10.0.0.10", "10.0.0.11"].map(str::to_owned).to_vec(),
        ..Default::default()
    })));
    connect_net2router(&local, &router).await?;
    connect_net2router(&server, &router).await?;
    start_router(&router).await?;
    let name = "configured-stun.test";
    router
        .lock()
        .await
        .add_host(name.into(), "10.0.0.10".into())
        .await?;
    let url = Url::parse_url(&format!("stun:{name}:3478"))?;
    let physical: SocketAddrV4 = "10.0.0.11:3478".parse()?;
    let system_ip: IpAddr = "192.0.2.50".parse()?;
    let mapped: IpAddr = "192.0.2.51".parse()?;
    let (tx, mut data) = mpsc::channel(4);
    let system = tokio::spawn(serve(
        server.bind("10.0.0.10:3478".parse()?).await?,
        system_ip,
        false,
        tx.clone(),
    ));
    for (enabled, grouped, corrupt, mode, relay_only, expect_calls) in [
        (true, false, false, MulticastDnsMode::Disabled, false, 2),
        (true, true, false, MulticastDnsMode::Disabled, false, 4),
        (true, false, true, MulticastDnsMode::Disabled, false, 2),
        (false, true, false, MulticastDnsMode::Disabled, false, 0),
        (true, true, false, MulticastDnsMode::QueryAndGather, false, 0),
        (true, true, false, MulticastDnsMode::Disabled, true, 0),
    ] {
        let socket = server.bind(physical.into()).await?;
        let physical_stun = tokio::spawn(serve(socket.clone(), mapped, corrupt, tx.clone()));
        let provider = Arc::new(AdapterStun {
            net: local.clone(),
            endpoint: physical,
            requests: Mutex::default(),
        });
        let agent = Agent::new(AgentConfig {
            net: Some(local.clone()),
            urls: vec![url.clone()],
            network_types: vec![NetworkType::Udp4],
            candidate_types: if relay_only {
                vec![CandidateType::Relay]
            } else {
                vec![CandidateType::Host, CandidateType::ServerReflexive]
            },
            gather_interface_srflx: enabled,
            grouped_physical_stun: grouped,
            interface_stun_provider: Some(provider.clone()),
            ip_filter: Arc::new(Some(Box::new(
                |ip| matches!(ip, IpAddr::V4(v4) if [20,21].contains(&v4.octets()[3])),
            ))),
            multicast_dns_mode: mode,
            ..Default::default()
        })
        .await?;
        let (done, mut done_rx) = mpsc::channel(1);
        agent.on_candidate(Box::new(move |candidate| {
            let done = done.clone();
            Box::pin(async move {
                if candidate.is_none() {
                    let _ = done.send(()).await;
                }
            })
        }));
        agent.gather_candidates()?;
        tokio::time::timeout(Duration::from_secs(7), done_rx.recv())
            .await
            .unwrap()
            .unwrap();
        let candidates = agent.get_local_candidates().await?;
        assert_eq!(
            candidates
                .iter()
                .any(|c| c.address() == system_ip.to_string()),
            !relay_only
        );
        let requests = provider.requests.lock().await;
        assert_eq!(requests.len(), expect_calls);
        assert!(requests.iter().all(
            |(source, host, port)| [20, 21].contains(&source.octets()[3])
                && host == name
                && *port == 3478
        ));
        let paths: Vec<_> = candidates
            .into_iter()
            .filter(|c| c.address() == mapped.to_string())
            .collect();
        assert_eq!(paths.len(), if corrupt { 0 } else { expect_calls });
        let peer: Arc<dyn Candidate + Send + Sync> = Arc::new(
            CandidateHostConfig {
                base_config: CandidateBaseConfig {
                    network: "udp".into(),
                    address: physical.ip().to_string(),
                    port: physical.port(),
                    component: COMPONENT_RTP,
                    ..Default::default()
                },
                ..Default::default()
            }
            .new_candidate_host()?,
        );
        for path in paths {
            let observed = path.get_conn().unwrap().local_addr()?;
            assert_eq!(
                path.port(),
                observed.port(),
                "port observed by the STUN server"
            );
            let pair = CandidatePair::new(path, peer.clone(), true);
            agent.internal.ping_candidate(&pair).await;
            let checked = tokio::time::timeout(Duration::from_secs(1), data.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                checked, observed,
                "authenticated ICE check uses the mapped socket"
            );
            pair.write(b"selected-pair data").await?;
            let arrived = tokio::time::timeout(Duration::from_secs(1), data.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                arrived, observed,
                "same adapter and UDP port carry session data"
            );
        }
        agent.close().await?;
        physical_stun.abort();
        socket.close().await?;
    }
    system.abort();
    router.lock().await.stop().await?;
    Ok(())
}

#[tokio::test]
async fn expanded_pool_owns_distinct_checked_ports_on_native_and_physical_paths() -> Result<()> {
    let router = Arc::new(Mutex::new(Router::new(RouterConfig {
        cidr: "0.0.0.0/0".into(),
        ..Default::default()
    })?));
    let local_ip = "10.0.0.20";
    let observer: SocketAddrV4 = "8.8.4.4:21116".parse()?;
    let mapped: IpAddr = "1.1.1.1".parse()?;
    let local = Arc::new(Net::new(Some(NetConfig {
        static_ips: vec![local_ip.into()],
        ..Default::default()
    })));
    let server = Arc::new(Net::new(Some(NetConfig {
        static_ips: vec![observer.ip().to_string()],
        ..Default::default()
    })));
    for net in [&local, &server] {
        connect_net2router(net, &router).await?;
    }
    start_router(&router).await?;
    let peer_socket = server.bind(SocketAddr::V4(observer)).await?;
    let peer_endpoint = CandidateServerReflexiveConfig {
        base_config: CandidateBaseConfig {
            network: "udp4".into(),
            address: observer.ip().to_string(),
            port: observer.port(),
            component: COMPONENT_RTP,
            ..Default::default()
        },
        rel_addr: observer.ip().to_string(),
        rel_port: observer.port(),
    }
    .new_candidate_server_reflexive()?
    .marshal();
    crate::candidate::candidate_base::unmarshal_candidate(&peer_endpoint)?;
    let provider = Arc::new(AdapterStun {
        net: local.clone(),
        endpoint: observer,
        requests: Mutex::new(Vec::new()),
    });
    for (physical, corrupt, capacity, expected) in [
        (false, false, 32, 32),
        (true, false, 500, 500),
        (true, true, 32, 0),
    ] {
        let (tx, mut reads) = mpsc::channel(40);
        let task = tokio::spawn(serve(peer_socket.clone(), mapped, corrupt, tx));
        let agent = Agent::new(AgentConfig {
            net: Some(local.clone()),
            network_types: vec![NetworkType::Udp4],
            candidate_types: vec![CandidateType::Host, CandidateType::ServerReflexive],
            multicast_dns_mode: MulticastDnsMode::Disabled,
            gather_interface_srflx: true,
            expanded_udp_pool: Some(super::super::agent_config::ExpandedUdpPool { observers: vec![observer], capacity }),
            interface_stun_provider: physical
                .then(|| provider.clone() as Arc<dyn InterfaceStunProvider>),
            ..Default::default()
        })
        .await?;
        let (events, mut gathered) = mpsc::channel(1);
        agent.on_candidate(Box::new(move |c| {
            let events = events.clone();
            Box::pin(async move {
                if c.is_none() {
                    let _ = events.send(()).await;
                }
            })
        }));
        agent.gather_candidates()?;
        tokio::time::timeout(Duration::from_secs(20), gathered.recv())
            .await
            .unwrap()
            .unwrap();
        let pool = agent.expanded_udp_candidates().await;
        assert_eq!(pool.len(), expected);
        assert_eq!(
            pool.iter()
                .map(|(_, a)| a.port())
                .collect::<std::collections::HashSet<_>>()
                .len(),
            expected
        );
        agent
            .set_remote_credentials("remote-ufrag".into(), "remote-password".into())
            .await?;
        for (id, endpoint) in pool {
            assert!(agent.timed_first_check(&id, &peer_endpoint).await);
            let received = tokio::time::timeout(Duration::from_secs(1), reads.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(received.ip().to_string(), local_ip);
            assert_eq!(received.port(), endpoint.port());
        }
        let request_count = provider.requests.lock().await.len();
        if physical {
            assert_eq!(request_count, if corrupt { 1 } else { expected });
        } else {
            assert_eq!(request_count, 0);
        }
        provider.requests.lock().await.clear();
        agent.close().await?;
        assert!(agent.expanded_udp_candidates().await.is_empty());
        task.abort();
        let _ = task.await;
    }
    let interrupted = Agent::new(AgentConfig {
        net: Some(local.clone()),
        network_types: vec![NetworkType::Udp4],
        candidate_types: vec![CandidateType::Host, CandidateType::ServerReflexive],
        multicast_dns_mode: MulticastDnsMode::Disabled,
        gather_interface_srflx: true,
        expanded_udp_pool: Some(super::super::agent_config::ExpandedUdpPool { observers: vec![observer], capacity: 32 }),
        ..Default::default()
    })
    .await?;
    interrupted.on_candidate(Box::new(|_| Box::pin(async {})));
    interrupted.gather_candidates()?;
    let mut packet = [0; 1200];
    let (n, source) =
        tokio::time::timeout(Duration::from_secs(2), peer_socket.recv_from(&mut packet))
            .await
            .unwrap()?;
    let mut request = Message::new();
    request.raw = packet[..n].to_vec();
    request.decode()?;
    interrupted.close().await?;
    let mut reply = Message::new();
    reply.build(&[
        Box::new(BINDING_SUCCESS),
        Box::new(request.transaction_id),
        Box::new(XorMappedAddress {
            ip: mapped,
            port: source.port(),
        }),
    ])?;
    peer_socket.send_to(&reply.raw, source).await?;
    tokio::time::timeout(Duration::from_secs(2), async {
        while !interrupted.expanded_udp_pool_complete() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(interrupted.expanded_udp_candidates().await.is_empty());
    // VNet keeps explicit reservations, so rebinding also verifies closure of the pending socket.
    local.bind(source).await?.close().await?;
    peer_socket.close().await?;
    router.lock().await.stop().await?;
    Ok(())
}
