//! An IPv4 server-reflexive candidate can have an IPv6-only base (RFC 8445 §5.1.1.2).
//! Keep the candidate and its ICE transactions in IPv4 coordinates, and its original bound
//! socket on the system's IPv6 route. Enable this only with evidence from that socket.
use std::{
    any::Any,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4},
    sync::Arc,
};

use async_trait::async_trait;
use stun::xoraddr::XorMappedAddress;
use tokio::{
    net::lookup_host,
    sync::OnceCell,
    time::{timeout, Duration},
};
use util::Conn;

use crate::error::{Error, Result};

type Socket = Arc<dyn Conn + Send + Sync>;
type IoResult<T> = std::result::Result<T, util::Error>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Prefix {
    network: [u8; 16],
    octets: usize,
}

fn usable_unicast(v4: Ipv4Addr) -> bool {
    let [first, ..] = v4.octets();
    first != 0 && first != 127 && first < 224 && !v4.is_link_local()
}

pub(crate) use crate::util::globally_reachable_ipv4;

impl Prefix {
    fn permits(self, v4: Ipv4Addr) -> bool {
        // RFC 6052 §3.1 prohibits non-global IPv4 addresses under 64:ff9b::/96.
        // A network-specific translator may legitimately reach RFC 1918 or shared space.
        let wkp = Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0, 0);
        if self.octets == 12 && self.network == wkp.octets() {
            globally_reachable_ipv4(v4)
        } else {
            usable_unicast(v4)
        }
    }

    // RFC 6052 §2.2. The /96 form stores all four octets at the end. Shorter
    // prefixes skip the reserved 8-bit u field at byte 8.
    fn positions(self) -> [usize; 4] {
        [0, 1, 2, 3].map(|i| {
            let n = self.octets + i;
            if self.octets != 12 && n >= 8 {
                n + 1
            } else {
                n
            }
        })
    }

    fn embed(self, ip: Ipv4Addr) -> Ipv6Addr {
        let mut result = self.network;
        for (i, byte) in self.positions().into_iter().zip(ip.octets()) {
            result[i] = byte;
        }
        result.into()
    }

    fn extract(self, ip: Ipv6Addr) -> Option<Ipv4Addr> {
        let address = ip.octets();
        let v4 = Ipv4Addr::from(self.positions().map(|i| address[i]));
        // Reject unrelated addresses and noncanonical encodings (u/suffix bits).
        (self.embed(v4) == ip).then_some(v4)
    }
}

const RFC7050: [Ipv4Addr; 2] = [Ipv4Addr::new(192, 0, 0, 170), Ipv4Addr::new(192, 0, 0, 171)];

fn discovered_prefixes(addresses: impl Iterator<Item = IpAddr>) -> Vec<Prefix> {
    let mut prefixes = Vec::new();
    for ip in addresses {
        let IpAddr::V6(address) = ip else { continue };
        for octets in [4, 5, 6, 7, 8, 12] {
            let mut network = address.octets();
            network[octets..].fill(0);
            let base = Ipv6Addr::from(network);
            if network[8] != 0
                || base.is_unspecified()
                || base.is_multicast()
                || (network[0] == 0xfe && network[1] & 0xc0 == 0x80)
                || base.to_ipv4().is_some()
            {
                continue;
            }
            let p = Prefix { network, octets };
            if RFC7050.iter().any(|&known| p.embed(known) == address) && !prefixes.contains(&p) {
                prefixes.push(p);
            }
        }
    }
    prefixes
}

// Per gathering round: a new ICE session after a Wi-Fi/cellular/VPN handoff performs its
// own discovery. The STUN destination still has to match on every translated socket.
#[derive(Default)]
pub(crate) struct Discovery(OnceCell<Vec<Prefix>>);

impl Discovery {
    async fn prefixes(&self) -> &[Prefix] {
        self.0
            .get_or_init(|| async {
                match timeout(
                    Duration::from_millis(1250),
                    lookup_host(("ipv4only.arpa.", 0)),
                )
                .await
                {
                    Ok(Ok(addresses)) => discovered_prefixes(addresses.map(|a| a.ip())),
                    _ => Vec::new(),
                }
            })
            .await
    }

    pub(crate) async fn stun_destinations(&self, stun: SocketAddrV4) -> Vec<SocketAddr> {
        if stun.port() == 0 {
            return Vec::new();
        }
        self.prefixes()
            .await
            .iter()
            .filter(|p| p.permits(*stun.ip()))
            .map(|p| SocketAddr::new(p.embed(*stun.ip()).into(), stun.port()))
            .collect()
    }

    async fn for_server(&self, server: Ipv6Addr, host: &str) -> Option<Prefix> {
        let mut matches = self.prefixes().await.iter().filter_map(|p| {
            p.extract(server)
                .filter(|v4| p.permits(*v4))
                .map(|v4| (*p, v4))
        });
        let (prefix, embedded) = matches.next()?;
        if matches.next().is_some() {
            return None;
        }
        if let Ok(literal) = host.parse::<IpAddr>() {
            return (literal == IpAddr::V4(embedded) || literal == IpAddr::V6(server))
                .then_some(prefix);
        }
        // This exact DNS64 destination was already resolved for the configured hostname
        // and answered our transaction. Another lookup may return a different server.
        Some(prefix)
    }

    #[cfg(test)]
    pub(crate) fn with_test_prefix() -> Self {
        let dns = [
            IpAddr::V6(Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0xc000, 0xaa)),
            IpAddr::V6(Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0xc000, 0xab)),
        ];
        let d = Self::default();
        d.0.set(discovered_prefixes(dns.into_iter())).unwrap();
        d
    }
}

use crate::agent::socket_diagnostics::{binding_request_header, SocketCounters};

pub(crate) async fn candidate_socket(
    socket: &Socket,
    server: SocketAddr,
    mapped: &XorMappedAddress,
    response_matches: bool,
    host: &str,
    discovery: &Discovery,
    socket_rx: &SocketCounters,
) -> Result<Socket> {
    let (IpAddr::V6(server_ip), IpAddr::V4(public)) = (server.ip(), mapped.ip) else {
        return Ok(socket.clone());
    };
    if !socket.local_addr()?.is_ipv6()
        || !response_matches
        || mapped.port == 0
        || public.is_unspecified()
        || public.is_multicast()
        || public.is_broadcast()
    {
        return Err(Error::ErrGetXorMappedAddrResponse);
    }
    let prefix = discovery
        .for_server(server_ip, host)
        .await
        .ok_or(Error::ErrGetXorMappedAddrResponse)?;
    if !prefix.permits(public) {
        return Err(Error::ErrGetXorMappedAddrResponse);
    }
    Ok(Arc::new(Translated {
        socket: socket.clone(),
        socket_rx: socket_rx.clone(),
        prefix,
    }))
}

struct Translated {
    socket_rx: SocketCounters,
    socket: Socket,
    prefix: Prefix,
}

impl Translated {
    fn destination(&self, peer: SocketAddr) -> IoResult<SocketAddr> {
        match peer.ip() {
            IpAddr::V4(v4) if peer.port() != 0 && self.prefix.permits(v4) => {
                Ok(SocketAddr::new(self.prefix.embed(v4).into(), peer.port()))
            }
            _ => Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid IPv4 NAT64 peer").into()),
        }
    }

    fn source(&self, address: SocketAddr) -> Option<SocketAddr> {
        let IpAddr::V6(v6) = address.ip() else {
            return None;
        };
        self.prefix
            .extract(v6)
            .filter(|ip| address.port() != 0 && self.prefix.permits(*ip))
            .map(|ip| SocketAddr::new(ip.into(), address.port()))
    }
}

/// Convert an already-resolved DNS64 observer to the address family exposed by this candidate.
pub(crate) fn observer_v4(socket: &Socket, address: SocketAddr) -> Option<SocketAddr> {
    socket.as_any().downcast_ref::<Translated>()?.source(address)
}

#[async_trait]
impl Conn for Translated {
    async fn connect(&self, peer: SocketAddr) -> IoResult<()> {
        self.socket.connect(self.destination(peer)?).await
    }
    async fn send_to(&self, bytes: &[u8], peer: SocketAddr) -> IoResult<usize> {
        self.socket.send_to(bytes, self.destination(peer)?).await
    }
    async fn recv_from(&self, buf: &mut [u8]) -> IoResult<(usize, SocketAddr)> {
        loop {
            let (n, addr) = self.socket.recv_from(buf).await?;
            if let Some(peer) = self.source(addr) {
                return Ok((n, peer));
            }
            self.socket_rx.add(|c| &c.nat64_source_drops);
            if binding_request_header(&buf[..n]) {
                self.socket_rx.add(|c| &c.nat64_binding_request_drops);
            }
        }
    }
    async fn send(&self, bytes: &[u8]) -> IoResult<usize> {
        self.socket.send(bytes).await
    }
    async fn recv(&self, buf: &mut [u8]) -> IoResult<usize> {
        Ok(self.recv_from(buf).await?.0)
    }
    fn local_addr(&self) -> IoResult<SocketAddr> {
        self.socket.local_addr()
    }
    fn remote_addr(&self) -> Option<SocketAddr> {
        self.source(self.socket.remote_addr()?)
    }
    async fn close(&self) -> IoResult<()> {
        self.socket.close().await
    }
    fn as_any(&self) -> &(dyn Any + Send + Sync) {
        self
    }
}

#[cfg(test)]
#[path = "nat64_test.rs"]
mod tests;
