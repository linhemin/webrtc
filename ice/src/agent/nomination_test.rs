use super::*;
use crate::candidate::{
    candidate_base::CandidateBaseConfig, candidate_host::CandidateHostConfig,
    candidate_relay::CandidateRelayConfig,
};
use stun::{fingerprint::FINGERPRINT, integrity::MessageIntegrity, message::*};

type TestCandidate = Arc<dyn Candidate + Send + Sync>;

fn candidate(port: u16, priority: u32, relay: bool) -> TestCandidate {
    let base_config = CandidateBaseConfig {
        network: "udp".to_owned(),
        address: "127.0.0.1".to_owned(),
        port,
        component: 1,
        priority,
        ..Default::default()
    };
    if relay {
        Arc::new(
            CandidateRelayConfig {
                base_config,
                ..Default::default()
            }
            .new_candidate_relay()
            .unwrap(),
        )
    } else {
        Arc::new(
            CandidateHostConfig {
                base_config,
                ..Default::default()
            }
            .new_candidate_host()
            .unwrap(),
        )
    }
}

#[tokio::test]
async fn rank_only_successful_direct_pairs_and_keep_priority_for_ties() -> Result<()> {
    let agent = Agent::new(AgentConfig::default()).await?;
    let conn = &agent.internal.agent_conn;
    let local = candidate(30000, 1000, false);
    let make_pair = |port, priority, relay, rtt_ms| {
        let p = Arc::new(CandidatePair::new(
            local.clone(),
            candidate(port, priority, relay),
            true,
        ));
        p.state
            .store(CandidatePairState::Succeeded as u8, Ordering::SeqCst);
        p.check_rtt.lock().record(Duration::from_millis(rtt_ms));
        p
    };
    let preferred = make_pair(30001, 900, false, 80);
    let fast = make_pair(30002, 500, false, 15);
    let relay = make_pair(30003, 999, true, 1);
    let unverified = make_pair(30004, 998, false, 0);
    unverified
        .state
        .store(CandidatePairState::InProgress as u8, Ordering::SeqCst);
    conn.checklist.lock().await.extend([
        relay.clone(),
        fast.clone(),
        preferred.clone(),
        unverified,
    ]);
    assert_eq!(
        conn.get_best_valid_candidate_pair(|_| true).await.unwrap(),
        fast
    );
    preferred.check_rtt.lock().record(Duration::from_millis(16));
    assert_eq!(
        conn.get_best_valid_candidate_pair(|_| true).await.unwrap(),
        preferred
    );
    *preferred.check_rtt.lock() = Default::default();
    assert_eq!(
        conn.get_best_valid_candidate_pair(|_| true).await.unwrap(),
        preferred
    );
    assert_eq!(
        conn.get_best_valid_candidate_pair(|p| *p == *relay)
            .await
            .unwrap(),
        relay
    );
    agent.close().await
}

#[tokio::test(start_paused = true)]
async fn authenticated_checks_compare_paths_and_nominate_once_after_deadline() -> Result<()> {
    let agent = Agent::new(AgentConfig {
        is_controlling: true,
        ..Default::default()
    })
    .await?;
    let state = &agent.internal;
    let local = candidate(31000, 1000, false);
    let other_local = candidate(31001, 1000, false);
    let slow = candidate(31002, 900, false);
    let fast = candidate(31003, 500, false);
    state.ufrag_pwd.lock().await.remote_pwd = "test remote secret".into();
    for remote in [&slow, &fast] {
        state.add_remote_candidate(remote).await;
        state.add_pair(local.clone(), remote.clone()).await;
    }
    state.add_pair(other_local.clone(), slow.clone()).await;

    // Inject binding responses through the production integrity and transaction checks.
    for (remote, received_on, password, known, rtt) in [
        (&slow, &local, "wrong secret", true, 1),
        (&slow, &local, "test remote secret", false, 1),
        (&slow, &other_local, "test remote secret", true, 1),
        (&slow, &local, "test remote secret", true, 80),
        (&fast, &local, "test remote secret", true, 10),
    ] {
        if remote.id() == fast.id() {
            tokio::time::advance(Duration::from_millis(30)).await;
        }
        let id = TransactionId::new();
        if known {
            state
                .pending_binding_requests
                .lock()
                .await
                .push(BindingRequest {
                    timestamp: Instant::now() - Duration::from_millis(rtt),
                    transaction_id: id,
                    local_id: local.id(),
                    destination: remote.addr(),
                    is_use_candidate: false,
                });
        }
        let mut response = Message::new();
        response.build(&[
            Box::new(BINDING_SUCCESS),
            Box::new(id),
            Box::new(MessageIntegrity::new_short_term_integrity(password.into())),
            Box::new(FINGERPRINT),
        ])?;
        state
            .handle_inbound(&mut response, received_on, remote.addr())
            .await;
    }
    let pairs = agent.get_candidate_pairs_stats().await;
    assert_eq!(pairs.len(), 3);
    for pair in pairs {
        if pair.local_candidate_id == other_local.id() {
            assert_eq!(pair.responses_received, 0);
            continue;
        }
        let rtt = if pair.remote_candidate_id == fast.id() {
            0.010
        } else {
            0.080
        };
        assert_eq!(pair.responses_received, 1);
        assert_eq!(pair.current_round_trip_time, rtt);
        assert_eq!(pair.total_round_trip_time, rtt);
    }

    tokio::time::advance(Duration::from_millis(69)).await;
    state.contact_candidates().await;
    assert!(state.nominated_pair.lock().await.is_none());
    tokio::time::advance(Duration::from_millis(1)).await;
    state.contact_candidates().await;
    let nominated = state.nominated_pair.lock().await.clone().unwrap();
    assert_eq!(nominated.remote.id(), fast.id());
    let slow_pair = state.find_pair(&local, &slow).await.unwrap();
    slow_pair.check_rtt.lock().record(Duration::from_millis(1));
    state.contact_candidates().await;
    assert_eq!(
        state
            .nominated_pair
            .lock()
            .await
            .as_ref()
            .unwrap()
            .remote
            .id(),
        fast.id()
    );
    assert!(!slow_pair.nominated.load(Ordering::SeqCst));
    agent.close().await
}

#[tokio::test(start_paused = true)]
async fn single_working_path_wakes_nomination_even_if_alternatives_are_silent() -> Result<()> {
    let agent = Agent::new(AgentConfig {
        is_controlling: true,
        ..Default::default()
    })
    .await?;
    let state = &agent.internal;
    let local = candidate(32000, 1000, false);
    let only = candidate(32001, 100, false);
    state.add_pair(local.clone(), only.clone()).await;
    state
        .add_pair(local.clone(), candidate(32002, 900, false))
        .await;
    let working = state.find_pair(&local, &only).await.unwrap();
    working
        .state
        .store(CandidatePairState::Succeeded as u8, Ordering::SeqCst);
    working.check_rtt.lock().record(Duration::from_millis(20));
    let (_done, mut wake) = state
        .done_and_force_candidate_contact_rx
        .lock()
        .await
        .take()
        .unwrap();
    tokio::time::advance(Duration::from_millis(1)).await;
    state.contact_candidates().await;
    assert!(state.nominated_pair.lock().await.is_none());
    assert!(wake.try_recv().is_err());
    assert_eq!(
        tokio::time::timeout(Duration::from_millis(101), wake.recv()).await,
        Ok(Some(true))
    );
    state.contact_candidates().await;
    assert_eq!(state.nominated_pair.lock().await.as_ref(), Some(&working));
    agent.close().await
}
