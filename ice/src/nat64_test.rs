use super::*;
use crate::util::observed_mapping;
use stun::{
    agent::TransactionId,
    message::{Message, BINDING_REQUEST, BINDING_SUCCESS},
};
use tokio::{
    net::UdpSocket,
    sync::{mpsc, Mutex},
};

fn prefix(network: &str, bits: usize) -> Prefix {
    Prefix {
        network: network.parse::<Ipv6Addr>().unwrap().octets(),
        octets: bits / 8,
    }
}

#[test]
fn rfc6052_vectors_and_rfc7050_discovery() {
    let peer = Ipv4Addr::new(192, 0, 2, 33);
    for (net, bits, address) in [
        ("2001:db8::", 32, "2001:db8:c000:221::"),
        ("2001:db8:100::", 40, "2001:db8:1c0:2:21::"),
        ("2001:db8:122::", 48, "2001:db8:122:c000:2:2100::"),
        ("2001:db8:122:300::", 56, "2001:db8:122:3c0:0:221::"),
        ("2001:db8:122:344::", 64, "2001:db8:122:344:c0:2:2100::"),
        ("2001:db8:122:344::", 96, "2001:db8:122:344::c000:221"),
        ("64:ff9b::", 96, "64:ff9b::c000:221"),
    ] {
        let p = prefix(net, bits);
        let address = address.parse().unwrap();
        assert_eq!(p.embed(peer), address);
        assert_eq!(p.extract(address), Some(peer));
        let dns = RFC7050.map(|ip| IpAddr::V6(p.embed(ip)));
        assert_eq!(discovered_prefixes(dns.into_iter()), vec![p]);
        assert!(p.extract("2001:db8:8888::feed".parse().unwrap()).is_none() || bits == 32);
    }
    let forgery = [
        "::ffff:192.0.0.170",
        "::192.0.0.171",
        "2001:db8:122:344:1c0:0:aa00:1",
        "fe80::c000:aa",
        "ff02::c000:aa",
        "192.0.0.170",
    ];
    assert!(discovered_prefixes(forgery.map(|s| s.parse().unwrap()).into_iter()).is_empty());
}

#[tokio::test]
async fn address_scope_restricts_the_well_known_prefix_and_allows_private_nsp_unicast() {
    let nsp = prefix("2001:db8:1122::", 96);
    let wkp = prefix("64:ff9b::", 96);
    for addr in [
        "10.2.3.4",
        "192.168.17.4",
        "172.27.34.5",
        "100.80.0.1",
        "198.19.0.8",
        "198.51.100.2",
        "192.0.2.1",
        "203.0.113.220",
        "192.88.99.1",
        "192.0.0.170",
    ] {
        assert!(!wkp.permits(addr.parse().unwrap()), "{addr}");
        assert!(nsp.permits(addr.parse().unwrap()), "{addr}");
    }
    for addr in [
        "127.0.0.1",
        "0.0.0.0",
        "0.0.0.1",
        "169.254.1.1",
        "224.0.0.1",
        "255.255.255.255",
        "240.0.0.1",
    ] {
        assert!(!wkp.permits(addr.parse().unwrap()), "{addr}");
        assert!(!nsp.permits(addr.parse().unwrap()), "{addr}");
    }
    let d = Discovery::with_test_prefix();
    for addr in ["1.2.3.4", "192.0.0.9", "192.0.0.10"] {
        let ip = addr.parse().unwrap();
        assert_eq!(
            d.stun_destinations(SocketAddrV4::new(ip, 3479)).await,
            vec![SocketAddr::new(wkp.embed(ip).into(), 3479)]
        );
        assert!(d
            .stun_destinations(SocketAddrV4::new(ip, 0))
            .await
            .is_empty());
    }
    assert!(d
        .stun_destinations("10.0.0.1:3478".parse().unwrap())
        .await
        .is_empty());
}

type Datagram = (Vec<u8>, SocketAddr);
// A bound IPv6 socket on a synthetic network. The peer below observes exactly what
// reached the wire, including its destination, without needing a NAT64 gateway on CI.
struct Wire {
    addr: SocketAddr,
    sends: mpsc::Sender<Datagram>,
    receives: Mutex<mpsc::Receiver<Datagram>>,
}

#[async_trait]
impl Conn for Wire {
    async fn connect(&self, _: SocketAddr) -> IoResult<()> {
        unreachable!()
    }
    async fn recv(&self, _: &mut [u8]) -> IoResult<usize> {
        unreachable!()
    }
    async fn recv_from(&self, dst: &mut [u8]) -> IoResult<(usize, SocketAddr)> {
        let (data, addr) = self.receives.lock().await.recv().await.unwrap();
        dst[..data.len()].copy_from_slice(&data);
        Ok((data.len(), addr))
    }
    async fn send(&self, _: &[u8]) -> IoResult<usize> {
        unreachable!()
    }
    async fn send_to(&self, data: &[u8], addr: SocketAddr) -> IoResult<usize> {
        self.sends.send((data.to_vec(), addr)).await.unwrap();
        Ok(data.len())
    }
    fn local_addr(&self) -> IoResult<SocketAddr> {
        Ok(self.addr)
    }
    fn remote_addr(&self) -> Option<SocketAddr> {
        None
    }
    async fn close(&self) -> IoResult<()> {
        Ok(())
    }
    fn as_any(&self) -> &(dyn Any + Send + Sync) {
        self
    }
}

#[tokio::test]
async fn measured_socket_writes_translated_peer_and_restores_only_its_prefix() {
    let (out, mut wire) = mpsc::channel(4);
    let (back, rx) = mpsc::channel(4);
    let conn: Socket = Arc::new(Wire {
        addr: "[2001:db8:1234::13]:4000".parse().unwrap(),
        sends: out,
        receives: Mutex::new(rx),
    });
    let p = prefix("2001:db8:122:344::", 64);
    let discovery = Discovery::default();
    discovery.0.set(vec![p]).unwrap();
    let stun = Ipv4Addr::new(198, 51, 100, 71);
    let server = SocketAddr::new(p.embed(stun).into(), 3478);
    let mapped = XorMappedAddress {
        ip: "203.0.113.1".parse().unwrap(),
        port: 44123,
    };
    let rx = SocketCounters::default();
    let socket = candidate_socket(
        &conn,
        server,
        &mapped,
        true,
        &stun.to_string(),
        &discovery,
        &rx,
    )
    .await
    .unwrap();
    let peer: SocketAddr = "192.0.2.33:7331".parse().unwrap();
    let wire_peer: SocketAddr = "[2001:db8:122:344:c0:2:2100:0]:7331".parse().unwrap();
    socket.send_to(b"check", peer).await.unwrap();
    assert_eq!(wire.recv().await, Some((b"check".to_vec(), wire_peer)));
    assert_eq!(socket.local_addr().unwrap(), conn.local_addr().unwrap());
    assert!(socket.send_to(b"wrong family", wire_peer).await.is_err());
    assert!(socket
        .send_to(b"bad port", "192.0.2.33:0".parse().unwrap())
        .await
        .is_err());
    for impostor in [
        "[2001:db8:122:344:c0:2:2100:0]:0",
        "[2001:db8:999:344:c0:2:2100:0]:7331",
        "[2001:db8:122:344:c0:2:2100:1]:7331",
    ] {
        let mut check = stun::message::Message::new();
        check
            .build(&[Box::new(stun::message::BINDING_REQUEST)])
            .unwrap();
        back.send((check.raw, impostor.parse().unwrap()))
            .await
            .unwrap();
    }
    back.send((b"reply".to_vec(), wire_peer)).await.unwrap();
    let mut buf = [0; 64];
    let (n, from) = socket.recv_from(&mut buf).await.unwrap();
    assert_eq!((from, &buf[..n]), (peer, &b"reply"[..]));
    let counts = rx.snapshot().unwrap();
    assert_eq!(
        (
            counts.nat64_source_drops,
            counts.nat64_binding_request_drops
        ),
        (3, 3)
    );
    assert_eq!(counts.udp_reads, 0);
    assert!(candidate_socket(
        &conn,
        server,
        &mapped,
        false,
        &stun.to_string(),
        &discovery,
        &rx
    )
    .await
    .is_err());
    assert!(
        candidate_socket(&conn, server, &mapped, true, "192.0.2.99", &discovery, &rx)
            .await
            .is_err()
    );
    let unavailable = Discovery::default();
    unavailable.0.set(Vec::new()).unwrap();
    assert!(candidate_socket(
        &conn,
        server,
        &mapped,
        true,
        &stun.to_string(),
        &unavailable,
        &rx
    )
    .await
    .is_err());
    let other_network = Discovery::default();
    other_network.0.set(vec![prefix("64:ff9b::", 96)]).unwrap();
    assert!(candidate_socket(
        &conn,
        server,
        &mapped,
        true,
        &stun.to_string(),
        &other_network,
        &rx
    )
    .await
    .is_err());
}

#[tokio::test]
async fn native_sockets_are_unchanged_and_do_not_resolve_any_prefix() {
    let discovery = Discovery::default();
    for addr in ["127.0.0.1:0", "[::1]:0"] {
        let conn: Socket = Arc::new(UdpSocket::bind(addr).await.unwrap());
        let server = conn.local_addr().unwrap();
        let mapped = XorMappedAddress {
            ip: server.ip(),
            port: server.port(),
        };
        let candidate = candidate_socket(
            &conn,
            server,
            &mapped,
            false,
            "does-not-resolve.invalid",
            &discovery,
            &SocketCounters::default(),
        )
        .await
        .unwrap();
        assert!(Arc::ptr_eq(&candidate, &conn));
    }
    assert!(discovery.0.get().is_none());
}

#[tokio::test]
async fn only_expected_stun_source_transaction_and_success_witness_the_mapping() {
    for invalid in [None, Some("source"), Some("txid"), Some("type")] {
        let client: Socket = Arc::new(UdpSocket::bind("[::1]:0").await.unwrap());
        let server = UdpSocket::bind("[::1]:0").await.unwrap();
        let other = UdpSocket::bind("[::1]:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        let response = async {
            let mut packet = [0; 1000];
            let (n, client) = server.recv_from(&mut packet).await.unwrap();
            let mut req = Message::new();
            req.raw = packet[..n].to_vec();
            req.decode().unwrap();
            let mut reply = Message::new();
            reply
                .build(&[
                    Box::new(if invalid == Some("type") {
                        BINDING_REQUEST
                    } else {
                        BINDING_SUCCESS
                    }),
                    Box::new(if invalid == Some("txid") {
                        TransactionId::new()
                    } else {
                        req.transaction_id
                    }),
                    Box::new(XorMappedAddress {
                        ip: "203.0.113.11".parse().unwrap(),
                        port: 34567,
                    }),
                ])
                .unwrap();
            let socket = if invalid == Some("source") {
                &other
            } else {
                &server
            };
            socket.send_to(&reply.raw, client).await.unwrap();
        };
        let rx = SocketCounters::default();
        let (result, ()) = tokio::join!(
            observed_mapping(&client, addr, Duration::from_secs(1), &rx),
            response
        );
        let (mapped, matched, _) = result.unwrap();
        assert_eq!(mapped.port, 34567);
        assert_eq!(matched, invalid.is_none());
        let snap = rx.snapshot().unwrap();
        assert_eq!(snap.gather_reads, 1);
        assert_eq!(
            snap.gather_binding_requests,
            u64::from(invalid == Some("type"))
        );
        assert_eq!(snap.gather_matched_responses, u64::from(invalid.is_none()));
        assert_eq!(snap.udp_reads, 0);
    }
}
