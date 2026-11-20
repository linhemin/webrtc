use super::*;
use crate::agent::agent_config::AgentConfig;
use crate::candidate::{
    candidate_base::CandidateBaseConfig, candidate_server_reflexive::CandidateServerReflexiveConfig,
};
use crate::state::ConnectionState;
use stun::integrity::MessageIntegrity;
use stun::message::Setter;
use stun::textattrs::Username;
use tokio::net::UdpSocket;

async fn endpoint() -> Arc<UdpSocket> {
    Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap())
}

fn installed_socket(socket: Arc<dyn util::Conn + Send + Sync>) -> Local {
    let addr = socket.local_addr().unwrap();
    installed_at(
        socket,
        SocketAddr::new("8.8.4.4".parse().unwrap(), addr.port()),
    )
}

fn installed_at(socket: Arc<dyn util::Conn + Send + Sync>, advertised: SocketAddr) -> Local {
    let addr = socket.local_addr().unwrap();
    Arc::new(
        CandidateServerReflexiveConfig {
            base_config: CandidateBaseConfig {
                address: advertised.ip().to_string(),
                port: advertised.port(),
                network: "udp".into(),
                component: 1,
                conn: Some(socket),
                ..Default::default()
            },
            rel_addr: addr.ip().to_string(),
            rel_port: addr.port(),
        }
        .new_candidate_server_reflexive()
        .unwrap(),
    )
}

async fn read(socket: &dyn util::Conn) -> (Message, SocketAddr) {
    let mut buf = [0u8; 1024];
    let (size, src) = timeout(Duration::from_secs(2), socket.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let mut msg = Message::new();
    msg.unmarshal_binary(&buf[..size]).unwrap();
    (msg, src)
}

fn success(id: TransactionId, mapped: SocketAddrV4) -> Message {
    let mut msg = Message::new();
    msg.build(&[
        Box::new(BINDING_SUCCESS),
        Box::new(id),
        Box::new(XorMappedAddress {
            ip: IpAddr::V4(*mapped.ip()),
            port: mapped.port(),
        }),
    ])
    .unwrap();
    msg
}

#[tokio::test]
async fn independent_observers_measure_same_live_socket_while_peer_ice_still_works() {
    for (second, expected) in [
        (Some("8.8.4.4:41800"), (1, 0, 0, 0)),
        (Some("8.8.4.4:42013"), (0, 1, 0, 0)),
        (Some("1.1.1.1:41800"), (0, 0, 1, 0)),
        (None, (0, 0, 0, 1)),
    ] {
        let agent = Agent::new(AgentConfig {
            is_controlling: true,
            ..Default::default()
        })
        .await
        .unwrap();
        agent.internal.started_ch_tx.lock().await.take();
        let socket = endpoint().await;
        let address = socket.local_addr().unwrap();
        let candidate = installed_socket(socket.clone());
        agent.internal.add_candidate(&candidate).await.unwrap();
        let (one, two, peer) = tokio::join!(endpoint(), endpoint(), endpoint());
        let observers = [one.local_addr().unwrap(), two.local_addr().unwrap()];
        let (user, pwd) = {
            let creds = agent.internal.ufrag_pwd.lock().await;
            (
                format!("{}:{}", creds.local_ufrag, creds.remote_ufrag),
                creds.local_pwd.clone(),
            )
        };
        let mut check = Message::new();
        check
            .build(&[
                Box::new(BINDING_REQUEST),
                Box::new(TransactionId::new()),
                Box::new(Username::new(ATTR_USERNAME, user)),
                Box::new(MessageIntegrity::new_short_term_integrity(pwd)),
                Box::new(FINGERPRINT),
            ])
            .unwrap();
        let other_socket = endpoint().await;
        let other_candidate = installed_socket(other_socket.clone());
        agent
            .internal
            .add_candidate(&other_candidate)
            .await
            .unwrap();
        let reply = async {
            let ((a, src1), (b, src2)) = tokio::join!(read(&*one), read(&*two));
            assert_eq!(a.typ, BINDING_REQUEST);
            assert_eq!(b.typ, BINDING_REQUEST);
            assert_eq!((src1, src2), (address, address));
            assert_ne!(a.transaction_id, b.transaction_id);
            let valid = success(a.transaction_id, "8.8.4.4:41800".parse().unwrap());
            let wrong = success(a.transaction_id, "1.1.1.1:43890".parse().unwrap());
            // None of these may steal the pending transaction.
            one.send_to(&wrong.raw, other_socket.local_addr().unwrap())
                .await
                .unwrap();
            peer.send_to(&wrong.raw, src1).await.unwrap();
            let mut bad = success(a.transaction_id, "1.1.1.1:43890".parse().unwrap());
            bad.add(ATTR_FINGERPRINT, &[0; 4]);
            one.send_to(&bad.raw, src1).await.unwrap();
            one.send_to(
                &success(TransactionId::new(), "1.1.1.1:43890".parse().unwrap()).raw,
                src1,
            )
            .await
            .unwrap();
            // This is a real authenticated ICE request interleaved with outstanding observers.
            peer.send_to(&check.raw, address).await.unwrap();
            let (reply, from) = read(&*peer).await;
            assert_eq!(from, address);
            assert_eq!(
                (reply.typ, reply.transaction_id),
                (BINDING_SUCCESS, check.transaction_id)
            );
            one.send_to(&valid.raw, src1).await.unwrap();
            if let Some(mapped) = second {
                two.send_to(
                    &success(b.transaction_id, mapped.parse().unwrap()).raw,
                    src2,
                )
                .await
                .unwrap();
            }
        };
        let (outcome, ()) = tokio::join!(
            sample(&agent.internal.mapping_probes, &candidate, &observers, false),
            reply
        );
        let mut stats = MappingProbeStats::default();
        outcome.record(&mut stats);
        assert_eq!(stats.sockets, 1);
        assert_eq!(
            (
                stats.stable,
                stats.port_changed,
                stats.address_changed,
                stats.inconclusive
            ),
            expected
        );
        assert_eq!(agent.udp_socket_diagnostics().unwrap().req_accepted, 1);
        assert!(agent.internal.mapping_probes.pending.lock().is_empty());
        agent.close().await.unwrap();
    }
}

#[test]
fn alternate_requires_validated_same_public_server_with_advertised_known_port() {
    let primary: SocketAddr = "8.8.4.4:443".parse().unwrap();
    let mapped = "1.1.1.1:47888".parse().unwrap();
    for (advertised, eligible) in [
        ("8.8.4.4:3478", true),
        ("8.8.4.4:443", false),
        ("8.8.4.4:8000", false),
        ("1.1.1.1:3478", true),
        ("10.0.0.1:3478", false),
    ] {
        let mut msg = success(TransactionId::new(), mapped);
        let alt: SocketAddr = advertised.parse().unwrap();
        MappedAddress {
            ip: alt.ip(),
            port: alt.port(),
        }
        .add_to_as(&mut msg, ATTR_OTHER_ADDRESS)
        .unwrap();
        MappedAddress {
            ip: primary.ip(),
            port: primary.port(),
        }
        .add_to_as(&mut msg, ATTR_RESPONSE_ORIGIN)
        .unwrap();
        FINGERPRINT.add_to(&mut msg).unwrap();
        assert_eq!(
            observed(primary, &msg).unwrap().alternate,
            eligible.then_some(SocketAddr::new(primary.ip(), alt.port()))
        );
        assert!(observed("8.8.4.4:3478".parse().unwrap(), &msg).is_none());
    }
    let mut msg = success(TransactionId::new(), mapped);
    msg.add(ATTR_OTHER_ADDRESS, &[0; 2]);
    assert!(observed(primary, &msg).unwrap().alternate.is_none());
    assert!(observed(
        primary,
        &success(TransactionId::new(), "192.168.0.5:4000".parse().unwrap())
    )
    .is_none());
}

#[tokio::test]
async fn wake_only_installed_unsatisfied_direct_pairs_with_credentials() {
    let agent = Agent::new(AgentConfig::default()).await.unwrap();
    agent.internal.started_ch_tx.lock().await.take();
    assert!(!agent.request_connectivity_check().await);
    let (sa, sb) = tokio::join!(endpoint(), endpoint());
    let (a, b) = (installed_socket(sa), installed_socket(sb));
    agent.internal.add_candidate(&a).await.unwrap();
    let p = agent.internal.add_pair(a, b).await;
    agent
        .internal
        .connection_state
        .store(ConnectionState::Checking as u8, Ordering::SeqCst);
    assert!(!agent.request_connectivity_check().await);
    {
        let mut creds = agent.internal.ufrag_pwd.lock().await;
        creds.remote_ufrag = "test-user".into();
        creds.remote_pwd = "remote test password".into();
    }
    assert!(agent.request_connectivity_check().await);
    p.state
        .store(CandidatePairState::Failed as u8, Ordering::SeqCst);
    assert!(!agent.request_connectivity_check().await);
    p.state
        .store(CandidatePairState::InProgress as u8, Ordering::SeqCst);
    agent.internal.set_selected_pair(Some(p)).await;
    assert!(!agent.request_connectivity_check().await);
    agent.close().await.unwrap();
    assert!(!agent.request_connectivity_check().await);
}

#[tokio::test]
async fn authenticated_socket_measurement_tests_change_port_and_caches_per_generation() {
    // Entirely isolated router: exercise the real Agent API and RFC 5780 source-port switch
    // using public-shaped addresses without sending network traffic to Internet servers.
    use crate::agent::agent_vnet_test::connect_net2router;
    use util::vnet::{
        net::{Net, NetConfig},
        router::{Router, RouterConfig},
    };
    let router = Arc::new(tokio::sync::Mutex::new(
        Router::new(RouterConfig {
            cidr: "0.0.0.0/0".into(),
            ..Default::default()
        })
        .unwrap(),
    ));
    let public = "8.8.4.4";
    let server = Arc::new(Net::new(Some(NetConfig {
        static_ips: vec![public.into()],
        ..Default::default()
    })));
    let client = Arc::new(Net::new(Some(NetConfig {
        static_ips: vec!["1.1.1.1".into()],
        ..Default::default()
    })));
    for net in [&server, &client] {
        connect_net2router(net, &router).await.unwrap();
    }
    router.lock().await.start().await.unwrap();
    let primary = server
        .bind(format!("{public}:443").parse().unwrap())
        .await
        .unwrap();
    let alternate = server
        .bind(format!("{public}:3478").parse().unwrap())
        .await
        .unwrap();
    let ordinary = server.bind(format!("{public}:3479").parse().unwrap()).await.unwrap();
    let original: SocketAddr = "1.1.1.1:45000".parse().unwrap();
    let source: SocketAddr = "1.1.1.1:45223".parse().unwrap();
    let socket = client.bind(source).await.unwrap();
    let agent = Arc::new(
        Agent::new(AgentConfig {
            net: Some(client.clone()),
            urls: vec![
                Url::parse_url("stun:8.8.4.4:443").unwrap(),
                Url::parse_url("stun:8.8.4.4:3479").unwrap(),
            ],
            grouped_physical_stun: true,
            ..Default::default()
        })
        .await
        .unwrap(),
    );
    let cand = installed_at(socket, original);
    agent.internal.add_candidate(&cand).await.unwrap();
    // Only the alternate observer reports the reachable address. The original
    // published port is unbound and the first agent knows no endpoint for its peer.
    let peer = Arc::new(
        Agent::new(AgentConfig {
            net: Some(server.clone()),
            ..Default::default()
        })
        .await
        .unwrap(),
    );
    let peer_addr: SocketAddr = "8.8.4.4:46000".parse().unwrap();
    let peer_local = installed_at(server.bind(peer_addr).await.unwrap(), peer_addr);
    peer.internal.add_candidate(&peer_local).await.unwrap();
    let signaled: Local =
        Arc::new(crate::candidate::candidate_base::unmarshal_candidate(&cand.marshal()).unwrap());
    peer.add_remote_candidate(&signaled).unwrap();
    let (a_user, a_pwd) = agent.get_local_user_credentials().await;
    let (b_user, b_pwd) = peer.get_local_user_credentials().await;
    let (_tx_a, rx_a) = tokio::sync::mpsc::channel(1);
    let (_tx_b, rx_b) = tokio::sync::mpsc::channel(1);
    let a = agent.clone();
    let b = peer.clone();
    let a_task = tokio::spawn(async move { a.dial(rx_a, b_user, b_pwd).await });
    let b_task = tokio::spawn(async move { b.accept(rx_b, a_user, a_pwd).await });
    agent.gathering_state.store(
        super::super::GatheringState::Complete as u8,
        Ordering::SeqCst,
    );
    let watcher = async {
        let baseline = "1.1.1.1:45000".parse().unwrap();
        let (request, from) = read(&*primary).await;
        assert_eq!(from, source);
        // Drop the first datagram. A single retry must keep both source and transaction ID.
        let (retry, retry_source) = read(&*primary).await;
        assert_eq!(
            (retry.transaction_id, retry_source),
            (request.transaction_id, source)
        );
        let mut response = success(request.transaction_id, baseline);
        MappedAddress {
            ip: "9.9.9.9".parse().unwrap(),
            port: 3478,
        }
        .add_to_as(&mut response, ATTR_OTHER_ADDRESS)
        .unwrap();
        primary.send_to(&response.raw, from).await.unwrap();
        let (next, from) = read(&*ordinary).await;
        ordinary.send_to(&success(next.transaction_id, baseline).raw, from).await.unwrap();
        let (change, from) = read(&*primary).await;
        assert_eq!(from, source);
        assert_eq!(change.get(ATTR_CHANGE_REQUEST).unwrap(), 2u32.to_be_bytes());
        let response = success(change.transaction_id, baseline);
        alternate.send_to(&response.raw, from).await.unwrap();
        let (request, from) = read(&*alternate).await;
        assert_eq!(from, source);
        assert!(!request.contains(ATTR_CHANGE_REQUEST));
        let changed = success(request.transaction_id, "1.1.1.1:45223".parse().unwrap());
        alternate.send_to(&changed.raw, from).await.unwrap();
    };
    assert!(agent.udp_mapping_stats().is_none());
    let (stats, (), other) = tokio::join!(
        agent.measure_udp_mappings(),
        watcher,
        agent.measure_udp_mappings()
    );
    assert_eq!(
        stats,
        MappingProbeStats {
            sockets: 1,
            port_changed: 1,
            alternate_tested: 1,
            alternate_changed: 1,
            // The first two live destinations agree, the third differs. Calling
            // this socket stable would ignore the validated alternate.
            ordered_profiles: [0, 0, 0, 1],
            ..Default::default()
        }
    );
    assert_eq!(other, stats);
    assert_eq!(agent.udp_mapping_stats(), Some(stats));
    assert!(agent.get_selected_candidate_pair().is_none());
    assert!(peer.get_selected_candidate_pair().is_none());
    let alternates = agent.observed_udp_candidates().await;
    assert_eq!(alternates.len(), 1);
    assert_eq!(alternates[0].addr(), source);
    assert!(alternates[0].get_conn().is_none());
    let group = agent.grouped_public_candidates().await;
    assert_eq!(group, vec![(cand.id(), match original {
        SocketAddr::V4(addr) => addr,
        _ => unreachable!(),
    }, 2)]);
    let stable: SocketAddrV4 = "1.1.1.1:46500".parse().unwrap();
    let stable_socket = installed_at(client.bind(SocketAddr::V4(stable)).await.unwrap(), SocketAddr::V4(stable));
    agent.internal.add_candidate(&stable_socket).await.unwrap();
    let group = agent.grouped_public_candidates().await;
    assert_eq!(group.len(), 2);
    assert_eq!(group[0].1, stable);
    assert_eq!(group[1].0, cand.id());
    assert_eq!(SocketAddr::V4(group[1].1), source);
    let trickled: Local = Arc::new(
        crate::candidate::candidate_base::unmarshal_candidate(&alternates[0].marshal()).unwrap(),
    );
    peer.add_remote_candidate(&trickled).unwrap();
    use util::Conn;
    timeout(Duration::from_secs(6), async {
        let a = a_task.await.unwrap().unwrap();
        let b = b_task.await.unwrap().unwrap();
        let p = agent.get_selected_candidate_pair().unwrap();
        assert_eq!(p.local.id(), cand.id());
        assert_eq!(p.remote.candidate_type(), CandidateType::PeerReflexive);
        assert_eq!(
            peer.get_selected_candidate_pair().unwrap().remote.addr(),
            source
        );
        let mut buf = [0; 32];
        a.send(b"from original socket").await.unwrap();
        let n = b.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"from original socket");
        b.send(b"to observed port").await.unwrap();
        let n = a.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"to observed port");
    })
    .await
    .unwrap();
    assert_eq!(agent.udp_socket_diagnostics().unwrap().candidate_readers, 2);
    agent.restart(String::new(), String::new()).await.unwrap();
    assert!(agent.udp_mapping_stats().is_none());
    assert!(agent.observed_udp_candidates().await.is_empty());
    agent.close().await.unwrap();
    peer.close().await.unwrap();
    router.lock().await.stop().await.unwrap();
}
