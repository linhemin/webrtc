use super::*;
use crate::candidate::{candidate_base::CandidateBaseConfig, candidate_host::CandidateHostConfig};
use stun::{attributes::ATTR_USERNAME, textattrs::Username};
use stun::{fingerprint::FINGERPRINT, integrity::MessageIntegrity, message::*};

type TestCandidate = Arc<dyn Candidate + Send + Sync>;

fn host(
    addr: SocketAddr,
    conn: Option<Arc<dyn util::Conn + Send + Sync>>,
) -> Result<TestCandidate> {
    Ok(Arc::new(
        CandidateHostConfig {
            base_config: CandidateBaseConfig {
                address: addr.ip().to_string(),
                port: addr.port(),
                network: "udp".into(),
                component: 1,
                conn,
                ..Default::default()
            },
            ..Default::default()
        }
        .new_candidate_host()?,
    ))
}

fn incoming_check(username: &str, password: &str) -> Result<Message> {
    let mut msg = Message::new();
    msg.build(&[
        Box::new(BINDING_REQUEST),
        Box::new(TransactionId::new()),
        Box::new(Username::new(ATTR_USERNAME, username.to_owned())),
        Box::new(MessageIntegrity::new_short_term_integrity(
            password.to_owned(),
        )),
        Box::new(FINGERPRINT),
    ])?;
    Ok(msg)
}

fn peer_success(id: TransactionId, password: &str) -> Result<Message> {
    let mut msg = Message::new();
    msg.build(&[
        Box::new(BINDING_SUCCESS),
        Box::new(id),
        Box::new(MessageIntegrity::new_short_term_integrity(
            password.to_owned(),
        )),
        Box::new(FINGERPRINT),
    ])?;
    Ok(msg)
}

#[tokio::test]
async fn check_io_counts_only_authenticated_requests_and_matched_socket_writes() -> Result<()> {
    use tokio::net::UdpSocket;

    for controlling in [true, false] {
        let agent = Agent::new(AgentConfig {
            is_controlling: controlling,
            ..Default::default()
        })
        .await?;
        let a = &agent.internal;
        let (username, local_pwd) = {
            let mut creds = a.ufrag_pwd.lock().await;
            creds.remote_pwd = "remote test password".to_owned();
            (
                format!("{}:{}", creds.local_ufrag, creds.remote_ufrag),
                creds.local_pwd.clone(),
            )
        };
        let sender = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
        let src = sender.local_addr()?;
        let local = host(src, Some(sender))?;
        let peer = UdpSocket::bind("127.0.0.1:0").await?;
        let dst = peer.local_addr()?;
        for (user, pwd) in [
            ("wrong-user", local_pwd.as_str()),
            (username.as_str(), "wrong-password"),
        ] {
            a.handle_inbound(&mut incoming_check(user, pwd)?, &local, dst)
                .await;
        }
        assert!(agent.get_candidate_pairs_stats().await.is_empty());
        // The first authenticated inbound check creates a peer-reflexive candidate and pair.
        let mut check = incoming_check(&username, &local_pwd)?;
        a.handle_inbound(&mut check, &local, dst).await;
        let remote = a
            .find_remote_candidate(local.network_type(), dst)
            .await
            .unwrap();
        assert_eq!(remote.candidate_type(), CandidateType::PeerReflexive);
        let pair = a.find_pair(&local, &remote).await.unwrap();
        if controlling {
            a.ping_candidate(&pair).await;
        }
        // Controlled already issued its triggered check. The peer must receive both
        // datagrams from the same local UDP endpoint that was charged for the write.
        let mut req_id = None;
        for _ in 0..2 {
            let mut buf = [0u8; 1024];
            let (n, from) = tokio::time::timeout(Duration::from_secs(2), peer.recv_from(&mut buf))
                .await
                .unwrap()?;
            assert_eq!(from, src);
            let mut msg = Message::new();
            msg.unmarshal_binary(&buf[..n])?;
            if msg.typ == BINDING_REQUEST {
                req_id = Some(msg.transaction_id);
            } else {
                assert_eq!(msg.typ, BINDING_SUCCESS);
                assert_eq!(msg.transaction_id, check.transaction_id);
            }
        }
        let req_id = req_id.unwrap();
        let alternate = UdpSocket::bind("127.0.0.1:0").await?;
        let password = "remote test password";
        for (id, pwd, from) in [
            (req_id, password, alternate.local_addr()?),
            (TransactionId::new(), password, dst),
            (req_id, "incorrect", dst),
        ] {
            a.handle_inbound(&mut peer_success(id, pwd)?, &local, from)
                .await;
            assert_eq!(
                agent.get_candidate_pairs_stats().await[0].responses_received,
                0
            );
        }
        for _ in 0..2 {
            a.handle_inbound(&mut peer_success(req_id, password)?, &local, dst)
                .await;
        }
        let stats = agent.get_candidate_pairs_stats().await;
        assert_eq!(stats.len(), 1);
        assert_eq!(
            (
                stats[0].requests_sent,
                stats[0].requests_received,
                stats[0].responses_sent,
                stats[0].responses_received
            ),
            (1, 1, 1, 1)
        );
        assert_eq!(
            (
                stats[0].request_send_failures,
                stats[0].response_send_failures
            ),
            (0, 0)
        );
        let ingress = agent.udp_socket_diagnostics().unwrap();
        assert_eq!(ingress.req_username_invalid, 1);
        assert_eq!(ingress.req_integrity_invalid, 1);
        assert_eq!(ingress.req_accepted, 1);
        assert_eq!(ingress.resp_integrity_invalid, 1);
        assert_eq!(ingress.resp_unknown_remote, 1);
        assert_eq!(ingress.resp_unknown_transaction, 2);
        assert_eq!(ingress.resp_accepted, 1);
        agent.close().await?;
    }
    Ok(())
}

#[tokio::test]
async fn check_io_no_candidate_socket_does_not_count_datagrams_as_sent() -> Result<()> {
    let agent = Agent::new(AgentConfig::default()).await?;
    let a = &agent.internal;
    let (username, password) = {
        let c = a.ufrag_pwd.lock().await;
        (
            format!("{}:{}", c.local_ufrag, c.remote_ufrag),
            c.local_pwd.clone(),
        )
    };
    let local = host("127.0.0.1:31450".parse()?, None)?;
    a.handle_inbound(
        &mut incoming_check(&username, &password)?,
        &local,
        "127.0.0.1:31451".parse()?,
    )
    .await;
    let stats = agent.get_candidate_pairs_stats().await;
    assert_eq!(stats.len(), 1);
    assert_eq!(
        (
            stats[0].requests_sent,
            stats[0].responses_sent,
            stats[0].responses_received
        ),
        (0, 0, 0)
    );
    assert_eq!(
        (
            stats[0].requests_received,
            stats[0].request_send_failures,
            stats[0].response_send_failures
        ),
        (1, 1, 1)
    );
    agent.close().await
}

#[tokio::test]
async fn check_io_records_kernel_send_errors() -> Result<()> {
    let agent = Agent::new(AgentConfig::default()).await?;
    let a = &agent.internal;
    let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await?);
    let src = socket.local_addr()?;
    let unreachable: SocketAddr = "[::1]:31452".parse()?;
    assert!(socket.send_to(&[0], unreachable).await.is_err());
    let local = host(src, Some(socket))?;
    let remote = host(unreachable, None)?;
    let pair = a.add_pair(local, remote).await;
    // Deliberately place an IPv6 destination on an IPv4-only socket to exercise
    // an actual send_to error independently from the zero-byte/no-socket case.
    a.ping_candidate(&pair).await;
    a.send_binding_success(&incoming_check("user", "test-key")?, &pair)
        .await;
    let stats = agent.get_candidate_pairs_stats().await;
    assert_eq!((stats[0].requests_sent, stats[0].responses_sent), (0, 0));
    assert_eq!(
        (
            stats[0].request_send_failures,
            stats[0].response_send_failures
        ),
        (1, 1)
    );
    agent.close().await
}

#[tokio::test]
async fn udp_socket_diagnostics_reads_before_decode_and_attributes_the_drop() -> Result<()> {
    use tokio::net::UdpSocket;

    let agent = Agent::new(AgentConfig {
        is_controlling: true,
        ..Default::default()
    })
    .await?;
    let network = &agent.internal;
    // Start the production recv_from loop without also starting a periodic ICE checklist.
    network.started_ch_tx.lock().await.take();
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
    let local = socket.local_addr()?;
    network.add_candidate(&host(local, Some(socket))?).await?;
    let peer = UdpSocket::bind("127.0.0.1:0").await?;
    let (username, password) = {
        let creds = network.ufrag_pwd.lock().await;
        (
            format!("{}:{}", creds.local_ufrag, creds.remote_ufrag),
            creds.local_pwd.clone(),
        )
    };
    let mut bare = Message::new();
    bare.build(&[Box::new(BINDING_REQUEST), Box::new(TransactionId::new())])?;
    let mut username_only = Message::new();
    username_only.build(&[
        Box::new(BINDING_REQUEST),
        Box::new(TransactionId::new()),
        Box::new(Username::new(ATTR_USERNAME, username.clone())),
    ])?;
    let mut conflict = Message::new();
    conflict.build(&[
        Box::new(BINDING_REQUEST),
        Box::new(TransactionId::new()),
        Box::new(crate::control::AttrControlling(17)),
    ])?;
    let mut incomplete = bare.raw.clone();
    incomplete[3] = 4; // Recognizable Binding request header with a missing attribute body.
    let valid = incoming_check(&username, &password)?;
    for bytes in [
        b"data".to_vec(),
        incomplete,
        bare.raw,
        username_only.raw,
        incoming_check("wrong", &password)?.raw,
        incoming_check(&username, "wrong")?.raw,
        conflict.raw,
        valid.raw.clone(),
        valid.raw,
    ] {
        peer.send_to(&bytes, local).await?;
    }
    let result = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let s = agent.udp_socket_diagnostics().unwrap();
            if s.req_accepted == 2 {
                break s;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("peer's two valid packets must traverse the real socket");
    assert_eq!(result.candidate_readers, 1);
    assert_eq!(result.udp_reads, 9);
    assert_eq!(result.binding_request_headers, 8);
    assert_eq!(result.non_stun, 1);
    assert_eq!(result.stun_decode_error, 1);
    assert_eq!(result.binding_request, 7);
    assert_eq!(result.req_role_conflict, 1);
    assert_eq!(result.req_username_missing, 1);
    assert_eq!(result.req_username_invalid, 1);
    assert_eq!(result.req_integrity_missing, 1);
    assert_eq!(result.req_integrity_invalid, 1);
    assert_eq!(result.req_unlisted_source, 5);
    assert_eq!(result.req_known_source, 1);
    assert_eq!(result.gather_reads, 0);
    // Another agent cannot observe the first agent's socket.
    let independent = Agent::new(AgentConfig::default()).await?;
    assert_eq!(
        independent.udp_socket_diagnostics().unwrap(),
        Default::default()
    );
    independent.close().await?;
    agent.close().await
}
