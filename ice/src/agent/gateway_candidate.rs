use std::net::SocketAddr;
use std::sync::Arc;

use tokio::time::{sleep, timeout, Duration, Instant};

use super::Agent;
use crate::candidate::candidate_base::CandidateBaseConfig;
use crate::candidate::candidate_server_reflexive::CandidateServerReflexiveConfig;
use crate::candidate::{Candidate, CandidateType, COMPONENT_RTP};
use crate::network_type::NetworkType;
use crate::udp_network::UDPNetwork;
use crate::util::globally_reachable_ipv4;

impl Agent {
    /// Called by the authenticated relay upgrade. Return a trickle candidate after
    /// installing its actual socket in ICE; a normal gather may already have ended.
    pub async fn gather_gateway_candidate(&self) -> Option<Arc<dyn Candidate + Send + Sync>> {
        let provider = self.interface_stun_provider.as_ref()?;
        let UDPNetwork::Ephemeral(ports) = &self.udp_network else {
            return None;
        };
        if !self
            .candidate_types
            .contains(&CandidateType::ServerReflexive)
            || (!self.network_types.is_empty() && !self.network_types.contains(&NetworkType::Udp4))
        {
            return None;
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        let (peer, epoch) = loop {
            let candidates = self.internal.remote_candidates.lock().await;
            let peer = candidates
                .get(&NetworkType::Udp4)
                .into_iter()
                .flatten()
                .filter(|c| {
                    matches!(
                        c.candidate_type(),
                        CandidateType::ServerReflexive | CandidateType::Host
                    )
                })
                .filter_map(|c| match c.addr() {
                    SocketAddr::V4(addr)
                        if addr.port() != 0 && globally_reachable_ipv4(*addr.ip()) =>
                    {
                        Some(*addr.ip())
                    }
                    _ => None,
                })
                .next();
            drop(candidates);
            let creds = self.internal.ufrag_pwd.lock().await;
            if let Some(peer) = peer.filter(|_| !creds.remote_ufrag.is_empty()) {
                break (
                    peer,
                    (creds.local_ufrag.clone(), creds.remote_ufrag.clone()),
                );
            }
            drop(creds);
            if Instant::now() >= deadline {
                return None;
            }
            sleep(Duration::from_millis(60)).await;
        };
        {
            let mut attempted = self.gateway_attempt.lock().await;
            if attempted.as_ref() == Some(&epoch) {
                return None;
            }
            *attempted = Some(epoch.clone());
        }
        let (conn, external) = timeout(
            Duration::from_secs(4),
            provider.bind_mapped_peer(peer, ports.port_min(), ports.port_max()),
        )
        .await
        .ok()??;
        let local = match conn.local_addr() {
            Ok(SocketAddr::V4(addr))
                if addr.port() > 0
                    && provider.supports_source(*addr.ip())
                    && self
                        .ip_filter
                        .as_ref()
                        .as_ref()
                        .map_or(true, |allow| allow(std::net::IpAddr::V4(*addr.ip())))
                    && (ports.port_min() == 0 || addr.port() >= ports.port_min())
                    && (ports.port_max() == 0 || addr.port() <= ports.port_max())
                    && conn.remote_addr().is_none()
                    && external.port() > 0
                    && globally_reachable_ipv4(*external.ip()) =>
            {
                addr
            }
            _ => {
                let _ = conn.close().await;
                return None;
            }
        };
        let config = CandidateServerReflexiveConfig {
            base_config: CandidateBaseConfig {
                network: NetworkType::Udp4.to_string(),
                address: external.ip().to_string(),
                port: external.port(),
                component: COMPONENT_RTP,
                conn: Some(conn.clone()),
                ..Default::default()
            },
            rel_addr: local.ip().to_string(),
            rel_port: local.port(),
        };
        let candidate: Arc<dyn Candidate + Send + Sync> =
            match config.new_candidate_server_reflexive() {
                Ok(c) => Arc::new(c),
                Err(_) => {
                    let _ = conn.close().await;
                    return None;
                }
            };
        // A close or restart during the router exchange must not install a stale lease.
        // Candidate installation below never waits on the application's signaling callback.
        let done = self.internal.done_tx.lock().await;
        let creds = self.internal.ufrag_pwd.lock().await;
        if done.is_none() || creds.local_ufrag != epoch.0 || creds.remote_ufrag != epoch.1 {
            drop(creds);
            drop(done);
            let _ = conn.close().await;
            return None;
        }
        self.internal
            .install_candidate(&candidate, false)
            .await
            .ok()?;
        let locals = self.internal.local_candidates.lock().await;
        locals
            .get(&NetworkType::Udp4)?
            .iter()
            .find(|c| Arc::ptr_eq(c, &candidate))
            .cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::agent_config::{AgentConfig, InterfaceStunProvider};
    use std::net::{Ipv4Addr, SocketAddrV4};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::net::UdpSocket;
    use util::Conn;

    type Socket = Arc<dyn Conn + Send + Sync>;

    struct Gateway {
        socket: Socket,
        external: SocketAddrV4,
        requests: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl InterfaceStunProvider for Gateway {
        fn supports_source(&self, ip: Ipv4Addr) -> bool {
            ip.is_loopback()
        }
        async fn bind_and_resolve(
            &self,
            _: Ipv4Addr,
            _: &str,
            _: u16,
            _: u16,
            _: u16,
        ) -> Option<(Socket, SocketAddrV4)> {
            None
        }
        async fn bind_mapped_peer(
            &self,
            peer: Ipv4Addr,
            _: u16,
            _: u16,
        ) -> Option<(Socket, SocketAddrV4)> {
            assert_eq!(peer, Ipv4Addr::new(8, 8, 4, 4));
            self.requests.fetch_add(1, Ordering::SeqCst);
            Some((self.socket.clone(), self.external))
        }
    }

    #[tokio::test]
    async fn public_gateway_candidate_uses_leased_socket_once_and_rejects_private_wan() {
        for (external, valid) in [("1.1.1.1:42567", true), ("100.64.1.1:42567", false)] {
            let gateway = Arc::new(Gateway {
                socket: Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap()),
                external: external.parse().unwrap(),
                requests: AtomicUsize::new(0),
            });
            let agent = Agent::new(AgentConfig {
                interface_stun_provider: Some(gateway.clone()),
                ..Default::default()
            })
            .await
            .unwrap();
            let peer: Arc<dyn Candidate + Send + Sync> = Arc::new(
                CandidateServerReflexiveConfig {
                    base_config: CandidateBaseConfig {
                        network: "udp4".into(),
                        component: COMPONENT_RTP,
                        address: "8.8.4.4".into(),
                        port: 40000,
                        ..Default::default()
                    },
                    ..Default::default()
                }
                .new_candidate_server_reflexive()
                .unwrap(),
            );
            agent
                .internal
                .remote_candidates
                .lock()
                .await
                .insert(NetworkType::Udp4, vec![peer]);
            agent.internal.ufrag_pwd.lock().await.remote_ufrag = "peer".into();
            let (a, b) = tokio::join!(
                agent.gather_gateway_candidate(),
                agent.gather_gateway_candidate()
            );
            assert_eq!(gateway.requests.load(Ordering::SeqCst), 1);
            assert_eq!(
                usize::from(a.is_some()) + usize::from(b.is_some()),
                usize::from(valid)
            );
            if let Some(candidate) = a.or(b) {
                assert_eq!(candidate.addr(), SocketAddr::V4(gateway.external));
                assert!(Arc::ptr_eq(candidate.get_conn().unwrap(), &gateway.socket));
                assert_eq!(agent.internal.agent_conn.checklist.lock().await.len(), 1);
                let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
                candidate
                    .get_conn()
                    .unwrap()
                    .send_to(b"leased", peer.local_addr().unwrap())
                    .await
                    .unwrap();
                let mut buf = [0; 10];
                let (n, from) = timeout(Duration::from_secs(2), peer.recv_from(&mut buf))
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(
                    (&buf[..n], from),
                    (&b"leased"[..], gateway.socket.local_addr().unwrap())
                );
            }
            agent.close().await.unwrap();
        }
    }
}
