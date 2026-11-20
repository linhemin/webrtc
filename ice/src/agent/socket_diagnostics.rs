//! Receive counters for one ICE agent. These contain no addressing or STUN attribute values.
#[cfg(any(test, target_os = "ios", feature = "ice-socket-diagnostics"))]
use std::sync::atomic::Ordering;
use std::sync::Arc;

use portable_atomic::AtomicU64;
use stun::attributes::{ATTR_MESSAGE_INTEGRITY, ATTR_USERNAME};
use stun::message::{
    Message, MessageType, BINDING_ERROR, BINDING_REQUEST, BINDING_SUCCESS, CLASS_INDICATION,
    METHOD_BINDING,
};

use crate::candidate::{Candidate, CandidateType};

const ENABLED: bool = cfg!(any(
    test,
    target_os = "ios",
    feature = "ice-socket-diagnostics"
));

macro_rules! counters {
    ($($field:ident),+ $(,)?) => {
        /// Cumulative per-agent counters. Candidate socket reads exclude TCP and relayed
        /// candidates. With a shared UDP mux, candidate reads are after mux delivery.
        /// STUN discovery reads and pre-delivery NAT64 source drops are separate populations.
        /// A type/cookie match or known source alone never authenticates a datagram.
        #[derive(Clone, Debug, Default, PartialEq, Eq)]
        pub struct UdpSocketDiagnostics { $(pub $field: u64),+ }

        #[derive(Default)]
        pub(crate) struct Counts { $(pub(crate) $field: AtomicU64),+ }

        #[cfg(any(test, target_os = "ios", feature = "ice-socket-diagnostics"))]
        impl Counts {
            fn snapshot(&self) -> UdpSocketDiagnostics {
                UdpSocketDiagnostics { $($field: self.$field.load(Ordering::Relaxed)),+ }
            }
        }
    };
}

counters! {
    candidate_readers, udp_reads, udp_read_errors, non_stun, binding_request_headers,
    stun_decode_error, binding_request, binding_success, binding_error, binding_indication, other_stun,
    req_known_source, req_unlisted_source, req_role_conflict, req_username_missing, req_username_invalid,
    req_integrity_missing, req_integrity_invalid, req_candidate_failed, req_accepted,
    response_writes, response_write_errors,
    resp_role_conflict, resp_integrity_missing, resp_integrity_invalid, resp_unknown_remote,
    resp_unknown_transaction, resp_wrong_endpoint, resp_no_pair, resp_accepted,
    gather_reads, gather_binding_requests, gather_matched_responses,
    nat64_source_drops, nat64_binding_request_drops,
}

pub(crate) fn binding_request_header(bytes: &[u8]) -> bool {
    bytes.get(..2) == Some(&[0, 1]) && bytes.get(4..8) == Some(&[0x21, 0x12, 0xa4, 0x42])
}

type Local = Arc<dyn Candidate + Send + Sync>;

// On other builds this is zero-sized: no allocation, atomics or address/packet lookups.
#[derive(Clone, Default)]
pub(crate) struct SocketCounters(
    #[cfg(any(test, target_os = "ios", feature = "ice-socket-diagnostics"))] Arc<Counts>,
);

impl SocketCounters {
    pub(crate) fn snapshot(&self) -> Option<UdpSocketDiagnostics> {
        #[cfg(any(test, target_os = "ios", feature = "ice-socket-diagnostics"))]
        {
            Some(self.0.snapshot())
        }
        #[cfg(not(any(test, target_os = "ios", feature = "ice-socket-diagnostics")))]
        {
            None
        }
    }

    #[inline]
    pub(crate) fn add(&self, _field: impl FnOnce(&Counts) -> &AtomicU64) {
        #[cfg(any(test, target_os = "ios", feature = "ice-socket-diagnostics"))]
        _field(&self.0).fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub(crate) fn direct(&self, local: &Local, field: impl FnOnce(&Counts) -> &AtomicU64) {
        if ENABLED
            && local.network_type().is_udp()
            && local.candidate_type() != CandidateType::Relay
        {
            self.add(field);
        }
    }

    pub(crate) fn read(&self, local: &Local, bytes: &[u8]) {
        if ENABLED {
            self.direct(local, |c| &c.udp_reads);
            if binding_request_header(bytes) {
                self.direct(local, |c| &c.binding_request_headers);
            }
        }
    }

    pub(crate) fn decoded(&self, local: &Local, typ: MessageType) {
        self.direct(local, |c| match typ {
            BINDING_REQUEST => &c.binding_request,
            BINDING_SUCCESS => &c.binding_success,
            BINDING_ERROR => &c.binding_error,
            MessageType {
                method: METHOD_BINDING,
                class: CLASS_INDICATION,
            } => &c.binding_indication,
            _ => &c.other_stun,
        });
    }

    pub(crate) fn conflict(&self, local: &Local, typ: MessageType) {
        if typ == BINDING_REQUEST {
            self.direct(local, |c| &c.req_role_conflict);
        } else if typ == BINDING_SUCCESS {
            self.direct(local, |c| &c.resp_role_conflict);
        }
    }

    pub(crate) fn bad_username(&self, local: &Local, m: &Message) {
        self.direct(local, |c| {
            if m.contains(ATTR_USERNAME) {
                &c.req_username_invalid
            } else {
                &c.req_username_missing
            }
        });
    }

    pub(crate) fn bad_integrity(&self, local: &Local, m: &Message) {
        self.direct(local, |c| {
            match (m.typ == BINDING_REQUEST, m.contains(ATTR_MESSAGE_INTEGRITY)) {
                (true, false) => &c.req_integrity_missing,
                (true, true) => &c.req_integrity_invalid,
                (false, false) => &c.resp_integrity_missing,
                (false, true) => &c.resp_integrity_invalid,
            }
        });
    }

    pub(crate) fn gathering_read(&self, bytes: &[u8]) {
        if ENABLED {
            self.add(|c| &c.gather_reads);
            if binding_request_header(bytes) {
                self.add(|c| &c.gather_binding_requests);
            }
        }
    }
}
