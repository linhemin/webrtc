use super::*;
use crate::agent::agent_vnet_test::{connect_net2router, start_router};
use util::vnet::router::{Router, RouterConfig};

#[tokio::test]
async fn expanded_pool_depends_on_which_nat64_sources_are_probed() -> Result<()> {
    let router = Arc::new(Mutex::new(Router::new(RouterConfig {
        cidr: "::/0".into(),
        ..Default::default()
    })?));
    let mut sources: Vec<IpAddr> = (1..=5)
        .map(|id| format!("2001:db8::{id}").parse().unwrap())
        .collect();
    let reachable = sources[4];
    let destination: SocketAddr = "[64:ff9b::101:101]:3478".parse()?;
    let observer = "1.1.1.1:3478".parse()?;
    let client = Arc::new(Net::new(Some(NetConfig {
        static_ips: sources.iter().map(ToString::to_string).collect(),
        ..Default::default()
    })));
    let server = Arc::new(Net::new(Some(NetConfig {
        static_ips: vec![destination.ip().to_string()],
        ..Default::default()
    })));
    connect_net2router(&client, &router).await?;
    connect_net2router(&server, &router).await?;
    start_router(&router).await?;
    let socket = server.bind(destination).await?;
    let responder = tokio::spawn(async move {
        let mut packet = [0; 1200];
        while let Ok((n, source)) = socket.recv_from(&mut packet).await {
            if source.ip() != reachable {
                continue;
            }
            let mut request = Message::new();
            request.raw = packet[..n].to_vec();
            request.decode().unwrap();
            let mut reply = Message::new();
            reply
                .build(&[
                    Box::new(BINDING_SUCCESS),
                    Box::new(request.transaction_id),
                    Box::new(XorMappedAddress {
                        ip: "9.9.9.9".parse().unwrap(),
                        port: source.port(),
                    }),
                ])
                .unwrap();
            socket.send_to(&reply.raw, source).await.unwrap();
        }
    });
    for order in [5, 1] {
        let agent = Agent::new(AgentConfig {
            net: Some(client.clone()),
            ..Default::default()
        }).await?;
        let params = GatherCandidatesSrflxParams {
            interface_stun_provider: None,
            urls: Vec::new(),
            network_types: vec![NetworkType::Udp4, NetworkType::Udp6],
            port_min: 49152,
            port_max: 50000,
            net: client.clone(),
            agent_internal: agent.internal.clone(),
            dns64: crate::nat64::Discovery::with_test_prefix(),
            supplement: Some(Nat64Gather::new(false)),
        };
        let start = Instant::now();
        expanded_udp_pool::gather(
            &params,
            sources.clone(),
            crate::agent::agent_config::ExpandedUdpPool {
                observers: vec![observer],
                capacity: 4,
            },
        ).await;
        let count = agent.expanded_udp_candidates().await.len();
        println!(
            "NAT64 source #{}, expanded candidates {count}, {} ms",
            order,
            start.elapsed().as_millis()
        );
        assert_eq!(count, 4);
        agent.close().await?;
        sources.rotate_right(1);
    }
    responder.abort();
    let _ = responder.await;
    router.lock().await.stop().await?;
    Ok(())
}

async fn answer(socket: &Arc<dyn Conn + Send + Sync>, mapped: IpAddr) -> Result<SocketAddr> {
    let mut packet = [0; 1200];
    let (n, source) = socket.recv_from(&mut packet).await?;
    let mut req = Message::new();
    req.raw = packet[..n].to_vec();
    req.decode()?;
    let mut response = Message::new();
    response.build(&[
        Box::new(BINDING_SUCCESS),
        Box::new(req.transaction_id),
        Box::new(XorMappedAddress {
            ip: mapped,
            port: source.port(),
        }),
    ])?;
    socket.send_to(&response.raw, source).await?;
    Ok(source)
}

#[tokio::test]
async fn dual_stack_stun_keeps_native_aaaa_and_adds_verified_translated_a() -> Result<()> {
    let router = Arc::new(Mutex::new(Router::new(RouterConfig {
        cidr: "::/0".into(),
        ..Default::default()
    })?));
    let mobile: IpAddr = "2001:db8::12".parse()?;
    let native_server: SocketAddr = "[2001:db8::ca]:3478".parse()?;
    let translated_server: SocketAddr = "[64:ff9b::101:101]:3478".parse()?;
    let native_map: IpAddr = "2001:db8:123::44".parse()?;
    let v4_map: IpAddr = "9.9.9.9".parse()?;
    let net = Arc::new(Net::new(Some(NetConfig {
        static_ips: vec![mobile.to_string()],
        ..Default::default()
    })));
    let server = Arc::new(Net::new(Some(NetConfig {
        static_ips: vec![
            native_server.ip().to_string(),
            translated_server.ip().to_string(),
        ],
        ..Default::default()
    })));
    connect_net2router(&net, &router).await?;
    connect_net2router(&server, &router).await?;
    start_router(&router).await?;
    let native_stun = server.bind(native_server).await?;
    let translated_stun = server.bind(translated_server).await?;
    // VNet's single-record resolver supplies the native AAAA for the first lookup and
    // the A for the subsequent A lookup, exactly as a dual-stack name answers each query.
    let name = "dual-stack-stun.test";
    router
        .lock()
        .await
        .add_host(name.into(), native_server.ip().to_string())
        .await?;
    let url = Url::parse_url(&format!("stun:{name}:3478"))?;
    let agent = Agent::new(AgentConfig {
        net: Some(net.clone()),
        gather_interface_srflx: true,
        ip_filter: Arc::new(Some(Box::new(|ip| match ip {
            IpAddr::V6(v6) => v6.segments()[0] & 0xffc0 != 0xfe80,
            IpAddr::V4(_) => true,
        }))),
        ..Default::default()
    })
    .await?;
    let params = Arc::new(GatherCandidatesSrflxParams {
        interface_stun_provider: None,
        urls: vec![url.clone()],
        network_types: vec![NetworkType::Udp4, NetworkType::Udp6],
        port_min: 49152,
        port_max: 50000,
        net,
        agent_internal: agent.internal.clone(),
        dns64: crate::nat64::Discovery::with_test_prefix(),
        supplement: Some(Nat64Gather::new(false)),
    });
    let respond = async {
        let first = answer(&native_stun, native_map).await?;
        router
            .lock()
            .await
            .add_host(name.into(), "1.1.1.1".into())
            .await?;
        // A slow or silent NAT64 probe must never hold the first native candidate.
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if agent
                    .get_local_candidates()
                    .await
                    .unwrap()
                    .iter()
                    .any(|c| c.address() == native_map.to_string())
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("native AAAA candidate published before the translated STUN reply");
        let second = answer(&translated_stun, v4_map).await?;
        assert_eq!(
            second.ip(),
            mobile,
            "supplement stays on the permitted source"
        );
        assert_ne!(
            first.port(),
            second.port(),
            "independent native and translated sockets"
        );
        Result::<()>::Ok(())
    };
    let ((), served) = tokio::time::timeout(Duration::from_secs(6), async {
        tokio::join!(
            Agent::gather_interface_srflx(
                params.clone(),
                agent.interface_filter.clone(),
                agent.ip_filter.clone(),
                false,
                false,
                None
            ),
            respond
        )
    })
    .await
    .expect("both virtual STUN listeners should receive checks");
    served?;
    let candidates = agent.get_local_candidates().await?;
    assert!(candidates
        .iter()
        .any(|c| c.address() == native_map.to_string() && c.network_type() == NetworkType::Udp6));
    let translated = candidates
        .into_iter()
        .find(|c| c.address() == v4_map.to_string() && c.network_type() == NetworkType::Udp4)
        .expect("translated IPv4 candidate");
    let remote = CandidateHostConfig {
        base_config: CandidateBaseConfig {
            network: "udp".to_owned(),
            address: "1.1.1.1".to_owned(),
            port: translated_server.port(),
            component: COMPONENT_RTP,
            ..Default::default()
        },
        ..Default::default()
    }
    .new_candidate_host()?;
    let pair = CandidatePair::new(translated, Arc::new(remote), true);
    pair.write(b"session data").await?;
    let mut buffer = [0u8; 64];
    let (n, _) = tokio::time::timeout(
        Duration::from_secs(1),
        translated_stun.recv_from(&mut buffer),
    )
    .await
    .expect("data reached the v6 wire")?;
    assert_eq!(&buffer[..n], b"session data");

    let signed_v4 = "1.1.1.1:3478".parse()?;
    let serve_pool = async {
        for _ in 0..32 {
            let source = answer(&translated_stun, v4_map).await?;
            assert_eq!(source.ip(), mobile);
        }
        Result::<()>::Ok(())
    };
    let ((), served) = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(
            expanded_udp_pool::gather(&params, vec![mobile], super::super::agent_config::ExpandedUdpPool { observers: vec![signed_v4], capacity: 32 }),
            serve_pool
        )
    })
    .await
    .expect("the signed IPv4 observer answers via the discovered NAT64 prefix");
    served?;
    let pool = agent.expanded_udp_candidates().await;
    assert_eq!(pool.len(), 32);
    let (id, mapping) = &pool[31];
    let chosen = agent
        .get_local_candidates()
        .await?
        .into_iter()
        .find(|c| &c.id() == id)
        .unwrap();
    let remote = CandidateServerReflexiveConfig {
        base_config: CandidateBaseConfig {
            network: "udp4".into(),
            address: signed_v4.ip().to_string(),
            port: signed_v4.port(),
            component: COMPONENT_RTP,
            ..Default::default()
        },
        rel_addr: signed_v4.ip().to_string(),
        rel_port: signed_v4.port(),
    }
    .new_candidate_server_reflexive()?;
    CandidatePair::new(chosen, Arc::new(remote), true)
        .write(b"expanded NAT64")
        .await?;
    let (n, from) = tokio::time::timeout(
        Duration::from_secs(1),
        translated_stun.recv_from(&mut buffer),
    )
    .await
    .unwrap()?;
    assert_eq!(from.port(), mapping.port());
    assert_eq!(&buffer[..n], b"expanded NAT64");
    agent.close().await?;
    router.lock().await.stop().await?;
    Ok(())
}
