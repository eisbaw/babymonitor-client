//! Media-plane transport: ICE candidate parsing/selection + the UDP datagram
//! seam that feeds [`super::MediaEngine`] (`re/media_decode_spec.md` §1 step 1).
//!
//! # What is offline-real vs live-gated (honest scope)
//!
//! - **Offline-real, unit-tested:** parsing the device answer's `a=candidate:`
//!   lines ([`parse_candidate`]) into typed [`IceCandidate`]s and ordering them
//!   host → srflx → relay ([`order_candidates`]) — the "try the answer's
//!   host/srflx/TURN candidates" selection logic. Validated against the cap3
//!   candidate shapes (`emulator_captures/cap3`).
//! - **Live-gated (NOT exercised offline):** the [`MediaTransport`] seam's real
//!   implementation [`UdpMediaTransport`]. It binds a UDP socket and receives
//!   datagrams, but it does **not** implement a full ICE agent: STUN binding
//!   requests (to confirm srflx reachability) and TURN Allocate/CreatePermission
//!   /ChannelBind (to use relay candidates) are a named follow-up — webrtc-rs is
//!   deliberately excluded to protect the offline gate (see `stream::mod`). So
//!   today [`UdpMediaTransport`] only reaches a directly-routable **host**
//!   candidate; srflx/relay need the STUN/TURN handshake. This is stated, not
//!   papered over: there is no live camera in this sandbox to test against.
//!
//! The offline pipeline tests therefore drive [`super::MediaEngine`] through the
//! [`MediaTransport`] seam with an in-memory fake (datagrams fed from synthetic
//! vectors / a capture), exactly as the signaling layer is tested with a fake
//! MQTT transport — no live socket.

use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::time::Duration;

use crate::stream::media::stun::{self, BindingRequest, IceRole};
use crate::Error;

/// The kind of an ICE candidate (`typ <kind>` in the candidate line).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateKind {
    /// A local-interface address (`typ host`) — directly routable when on-path.
    Host,
    /// A server-reflexive address discovered via STUN (`typ srflx`).
    Srflx,
    /// A peer-reflexive address (`typ prflx`).
    Prflx,
    /// A TURN relay address (`typ relay`).
    Relay,
}

impl CandidateKind {
    /// Connectivity-try order rank (lower = try first): host < srflx < prflx <
    /// relay, matching the standard ICE preference (cheapest/most-direct first).
    #[must_use]
    pub fn try_rank(self) -> u8 {
        match self {
            Self::Host => 0,
            Self::Srflx => 1,
            Self::Prflx => 2,
            Self::Relay => 3,
        }
    }

    fn parse(s: &str) -> Option<Self> {
        match s {
            "host" => Some(Self::Host),
            "srflx" => Some(Self::Srflx),
            "prflx" => Some(Self::Prflx),
            "relay" => Some(Self::Relay),
            _ => None,
        }
    }
}

/// A parsed ICE candidate from an `a=candidate:` SDP attribute / trickle line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IceCandidate {
    /// Foundation string.
    pub foundation: String,
    /// RTP/RTCP component id (1 = RTP).
    pub component: u32,
    /// Transport protocol (`UDP`/`TCP`).
    pub transport: String,
    /// ICE priority (higher = preferred at the same kind).
    pub priority: u32,
    /// Candidate IP address.
    pub ip: IpAddr,
    /// Candidate UDP/TCP port.
    pub port: u16,
    /// Candidate kind (`typ host/srflx/prflx/relay`).
    pub kind: CandidateKind,
}

impl IceCandidate {
    /// The peer socket address (`ip:port`) to send/receive media on.
    #[must_use]
    pub fn socket_addr(&self) -> SocketAddr {
        SocketAddr::new(self.ip, self.port)
    }
}

/// Parse one ICE candidate line, with or without the leading `a=` and/or
/// `candidate:` prefix and an optional trailing CRLF.
///
/// Accepts the cap3 answer shape, e.g.
/// `a=candidate:1058984092 1 UDP 2130706431 10.0.2.15 58363 typ host`.
///
/// # Errors
/// [`Error::Transport`] if the line is not a well-formed candidate (missing
/// fields, a bad number/IP/port, or an unknown `typ`).
pub fn parse_candidate(line: &str) -> Result<IceCandidate, Error> {
    let line = line.trim();
    let line = line.strip_prefix("a=").unwrap_or(line);
    let body = line
        .strip_prefix("candidate:")
        .ok_or_else(|| Error::Transport(format!("not an ICE candidate line: {line:?}")))?;
    let f: Vec<&str> = body.split_whitespace().collect();
    // foundation component transport priority ip port "typ" kind [...]
    if f.len() < 8 || f[6] != "typ" {
        return Err(Error::Transport(format!(
            "malformed ICE candidate (need `<foundation> <comp> <transport> <prio> <ip> <port> typ <kind>`): {body:?}"
        )));
    }
    let component = f[1]
        .parse::<u32>()
        .map_err(|_| Error::Transport(format!("bad candidate component {:?}", f[1])))?;
    let priority = f[3]
        .parse::<u32>()
        .map_err(|_| Error::Transport(format!("bad candidate priority {:?}", f[3])))?;
    let ip = f[4]
        .parse::<IpAddr>()
        .map_err(|_| Error::Transport(format!("bad candidate ip {:?}", f[4])))?;
    let port = f[5]
        .parse::<u16>()
        .map_err(|_| Error::Transport(format!("bad candidate port {:?}", f[5])))?;
    let kind = CandidateKind::parse(f[7])
        .ok_or_else(|| Error::Transport(format!("unknown ICE candidate type {:?}", f[7])))?;
    Ok(IceCandidate {
        foundation: f[0].to_string(),
        component,
        transport: f[2].to_ascii_uppercase(),
        priority,
        ip,
        port,
        kind,
    })
}

/// Parse every `a=candidate:` line in an SDP (skips non-candidate lines).
///
/// # Errors
/// [`Error::Transport`] if any candidate line present is malformed.
pub fn parse_candidates_from_sdp(sdp: &str) -> Result<Vec<IceCandidate>, Error> {
    sdp.lines()
        .map(|l| l.strip_suffix('\r').unwrap_or(l))
        .filter(|l| l.trim_start().starts_with("a=candidate:"))
        .map(parse_candidate)
        .collect()
}

/// Order candidates by connectivity-try preference: host → srflx → prflx →
/// relay, then by descending ICE priority within a kind. The returned order is
/// the sequence to attempt connectivity in (component 1 / RTP only is left to the
/// caller; both are kept).
#[must_use]
pub fn order_candidates(mut candidates: Vec<IceCandidate>) -> Vec<IceCandidate> {
    candidates.sort_by(|a, b| {
        a.kind
            .try_rank()
            .cmp(&b.kind.try_rank())
            .then(b.priority.cmp(&a.priority))
    });
    candidates
}

/// The ICE short-term credentials for one media session: the local (offer) and
/// remote (answer) ufrag/pwd recovered from the two SDPs
/// ([`crate::stream::sdp::extract_ice_creds`]).
///
/// These key the connectivity checks: an **outbound** check we send to the camera
/// carries `USERNAME = <remoteUfrag>:<localUfrag>` and is MESSAGE-INTEGRITY-keyed
/// by the **remote** (camera) ICE password; an **inbound** check from the camera
/// is verified with the **local** password. The passwords are secrets — held only
/// for the session and redacted from `Debug`.
#[derive(Clone)]
pub struct IceCredentials {
    /// Local (our offer) ICE ufrag (`a=ice-ufrag` in our offer SDP).
    pub local_ufrag: String,
    /// Local (our offer) ICE pwd. **SECRET** — verifies inbound checks.
    pub local_pwd: String,
    /// Remote (camera answer) ICE ufrag (`a=ice-ufrag` in the answer SDP).
    pub remote_ufrag: String,
    /// Remote (camera answer) ICE pwd. **SECRET** — keys our outbound checks.
    pub remote_pwd: String,
}

impl std::fmt::Debug for IceCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IceCredentials")
            .field("local_ufrag", &self.local_ufrag)
            .field(
                "local_pwd",
                &format!("<redacted len={}>", self.local_pwd.len()),
            )
            .field("remote_ufrag", &self.remote_ufrag)
            .field(
                "remote_pwd",
                &format!("<redacted len={}>", self.remote_pwd.len()),
            )
            .finish()
    }
}

impl IceCredentials {
    /// The USERNAME for an **outbound** connectivity check we send to the camera:
    /// `<remoteUfrag>:<localUfrag>` (RFC 8445 §7.1.2; cap4-confirmed).
    #[must_use]
    pub fn outbound_username(&self) -> String {
        format!("{}:{}", self.remote_ufrag, self.local_ufrag)
    }

    /// Build an outbound ICE connectivity-check Binding Request to the camera,
    /// MESSAGE-INTEGRITY-keyed by the **remote** (camera) ICE password.
    ///
    /// `txid` is the (client-minted, random in production) transaction id;
    /// `priority` is the checked candidate's ICE priority; `role` is our ICE role
    /// with its tiebreaker; `use_candidate` nominates the pair. cap4 sends a
    /// `SOFTWARE` value of `"3.5.5"`; pass it via `software` for byte-parity, or
    /// `None` otherwise.
    ///
    /// # Errors
    /// Propagates [`Error::Transport`] from [`stun::BindingRequest::encode`].
    pub fn build_check(
        &self,
        txid: [u8; 12],
        priority: u32,
        role: IceRole,
        use_candidate: bool,
        software: Option<&str>,
    ) -> Result<Vec<u8>, Error> {
        BindingRequest {
            txid,
            username: self.outbound_username(),
            priority,
            role,
            use_candidate,
            software: software.map(str::to_string),
        }
        .encode(self.remote_pwd.as_bytes())
    }
}

/// PRIMARY (cap4-proven) media path: pick the best **host** candidate from the
/// remote (answer + trickled) candidate set and open a connected UDP transport to
/// it. cap4 reached the camera at its LAN host candidate `192.0.2.184` with NO
/// STUN/TURN, so this is the default when the client shares the camera's LAN.
///
/// "Best" = highest ICE priority among `typ host` candidates (component 1 / RTP
/// preferred). The returned [`UdpMediaTransport`] is `connect`ed to that peer; the
/// caller then (live) sends an ICE connectivity check on it
/// ([`UdpMediaTransport::send_connectivity_check`]) so the camera opens consent,
/// and finally pumps datagrams into the [`super::MediaEngine`].
///
/// LIVE: opens a socket — never exercised in the offline tests (the selection
/// logic [`select_host_candidate`] is the offline-testable part).
///
/// # Errors
/// - [`Error::Transport`] if the remote set carries no `typ host` candidate (this
///   path is host-direct only; srflx/relay need the STUN/TURN handshake).
/// - [`Error::Transport`] if binding/connecting the socket fails.
pub fn connect_host_direct(
    local: SocketAddr,
    remote_candidates: &[IceCandidate],
) -> Result<(UdpMediaTransport, IceCandidate), Error> {
    let host = select_host_candidate(remote_candidates).ok_or_else(|| {
        Error::Transport(
            "no `typ host` candidate in the remote set — host-direct needs a LAN-reachable host \
             candidate; srflx/relay require the STUN/TURN handshake (TURN is a documented stub)"
                .to_string(),
        )
    })?;
    let transport = UdpMediaTransport::connect(local, host.socket_addr())?;
    Ok((transport, host))
}

/// Select the highest-priority `typ host` candidate (component 1 preferred) from
/// a remote candidate set — the offline-testable core of [`connect_host_direct`].
#[must_use]
pub fn select_host_candidate(remote_candidates: &[IceCandidate]) -> Option<IceCandidate> {
    order_candidates(remote_candidates.to_vec())
        .into_iter()
        .filter(|c| c.kind == CandidateKind::Host)
        // Prefer the RTP component (1); `order_candidates` already sorts by
        // descending priority within a kind, so the first host of comp 1, else
        // the first host overall.
        .reduce(|best, c| {
            if best.component == 1 {
                best
            } else if c.component == 1 {
                c
            } else {
                best
            }
        })
}

/// The UDP datagram source the [`super::MediaEngine`] pulls from.
///
/// The offline pipeline tests implement this with an in-memory fake (datagrams
/// from synthetic vectors / a capture); the live path implements it with
/// [`UdpMediaTransport`].
pub trait MediaTransport {
    /// Receive the next media UDP datagram into `buf`, returning its length, or
    /// `None` if none is ready (non-blocking).
    ///
    /// # Errors
    /// [`Error::Transport`] on a receive failure.
    fn recv_datagram(&mut self, buf: &mut [u8]) -> Result<Option<usize>, Error>;
}

/// LIVE-ONLY plain-UDP media transport: binds a local socket and `connect`s it to
/// a selected peer candidate, then receives datagrams.
///
/// **Honest limitation (live-gated):** this is NOT a full ICE agent. It performs
/// no STUN binding check and no TURN allocation, so it can only reach a directly
/// routable **host** candidate; srflx/relay require the STUN/TURN handshake that
/// is a named follow-up (webrtc-rs is excluded — see module docs). It opens a
/// real socket, so it is never exercised in the offline tests.
pub struct UdpMediaTransport {
    socket: UdpSocket,
    /// The connected peer (the camera host candidate), once [`connect_peer`] runs.
    /// `None` between an early [`bind`] and the peer being known — the socket can
    /// still RECEIVE the camera's early connectivity checks in that window.
    ///
    /// [`bind`]: UdpMediaTransport::bind
    /// [`connect_peer`]: UdpMediaTransport::connect_peer
    peer: Option<SocketAddr>,
}

/// Classify a non-blocking UDP `recv`/`send` result. `WouldBlock` (nothing ready)
/// AND `ConnectionRefused` (a prior datagram drew an ICMP port-unreachable because
/// the camera has not opened its media port YET) are both **transient** during ICE
/// — map them to `Ok(None)` so the pump keeps retransmitting the connectivity
/// check instead of aborting. Any other error is a real failure.
pub(crate) fn classify_recv(res: std::io::Result<usize>) -> Result<Option<usize>, Error> {
    match res {
        Ok(n) => Ok(Some(n)),
        Err(e)
            if e.kind() == std::io::ErrorKind::WouldBlock
                || e.kind() == std::io::ErrorKind::ConnectionRefused =>
        {
            Ok(None)
        }
        Err(e) => Err(Error::Transport(format!("media UDP io: {e}"))),
    }
}

impl UdpMediaTransport {
    /// Bind a local UDP socket (ephemeral when `local` port is 0) WITHOUT yet
    /// connecting a peer, non-blocking. Use this EARLY (before signaling) so the
    /// OS-assigned source port is known and can be trickled to the camera as our
    /// host candidate; call [`connect_peer`](Self::connect_peer) once the camera's
    /// host candidate arrives.
    ///
    /// # Errors
    /// [`Error::Transport`] if binding or setting non-blocking fails.
    pub fn bind(local: SocketAddr) -> Result<Self, Error> {
        let socket = UdpSocket::bind(local)
            .map_err(|e| Error::Transport(format!("bind media UDP socket {local}: {e}")))?;
        socket
            .set_nonblocking(true)
            .map_err(|e| Error::Transport(format!("set media socket non-blocking: {e}")))?;
        Ok(Self { socket, peer: None })
    }

    /// `connect` the already-bound socket to `peer` (the selected camera host
    /// candidate's `ip:port`), so subsequent `send`/`recv` target only that peer.
    ///
    /// # Errors
    /// [`Error::Transport`] if the connect fails.
    pub fn connect_peer(&mut self, peer: SocketAddr) -> Result<(), Error> {
        self.socket
            .connect(peer)
            .map_err(|e| Error::Transport(format!("connect media UDP to {peer}: {e}")))?;
        self.peer = Some(peer);
        Ok(())
    }

    /// Bind a local UDP socket and `connect` it to `peer` in one step (the cap4
    /// host-direct path / back-compat). Equivalent to [`bind`](Self::bind) +
    /// [`connect_peer`](Self::connect_peer).
    ///
    /// # Errors
    /// [`Error::Transport`] if binding, connecting, or setting non-blocking fails.
    pub fn connect(local: SocketAddr, peer: SocketAddr) -> Result<Self, Error> {
        let mut t = Self::bind(local)?;
        t.connect_peer(peer)?;
        Ok(t)
    }

    /// The local address the socket is bound to (after an ephemeral-port bind, the
    /// OS-assigned port) — the source port the camera sees, and the port a srflx
    /// discovery on the *same* socket would map.
    ///
    /// # Errors
    /// [`Error::Transport`] if the local address cannot be read.
    pub fn local_addr(&self) -> Result<SocketAddr, Error> {
        self.socket
            .local_addr()
            .map_err(|e| Error::Transport(format!("media socket local_addr: {e}")))
    }

    /// Send a datagram to the connected peer (the camera). Used for the ICE
    /// connectivity check and any binding keepalive — the media RX itself only
    /// receives.
    ///
    /// LIVE: writes to the socket.
    ///
    /// # Errors
    /// [`Error::Transport`] on a send failure.
    pub fn send_datagram(&self, buf: &[u8]) -> Result<usize, Error> {
        self.socket
            .send(buf)
            .map_err(|e| Error::Transport(format!("media UDP send: {e}")))
    }

    /// Like [`send_datagram`](Self::send_datagram) but tolerant of the transient
    /// ICE conditions: `WouldBlock` and `ConnectionRefused` (the camera's media
    /// port not open yet) return `Ok(None)` instead of erroring, so a queued ICMP
    /// port-unreachable on a connectivity check does not abort the pump.
    ///
    /// # Errors
    /// [`Error::Transport`] on any non-transient send failure.
    pub fn try_send(&self, buf: &[u8]) -> Result<Option<usize>, Error> {
        classify_recv(self.socket.send(buf))
    }

    /// Send an ICE connectivity-check Binding Request to the connected peer.
    ///
    /// This is what makes the camera open consent and start sending media on the
    /// host-direct path. Build `req` from the session [`IceCredentials`]
    /// ([`IceCredentials::build_check`]); it is MESSAGE-INTEGRITY-keyed by the
    /// camera's ICE password.
    ///
    /// LIVE: writes to the socket.
    ///
    /// # Errors
    /// - Propagates [`Error::Transport`] from [`BindingRequest::encode`].
    /// - [`Error::Transport`] on a send failure.
    pub fn send_connectivity_check(
        &self,
        req: &BindingRequest,
        integrity_key: &[u8],
    ) -> Result<(), Error> {
        let bytes = req.encode(integrity_key)?;
        self.send_datagram(&bytes)?;
        Ok(())
    }
}

/// LIVE: discover this socket's **server-reflexive (srflx)** candidate by a STUN
/// Binding round-trip to `stun_server`, returning the XOR-MAPPED-ADDRESS the
/// server reflects back (our public `ip:port` as seen through the NAT).
///
/// This is the srflx half of ICE (AC#1) for the remote/NAT case. It must run on a
/// socket that is **not** yet `connect`ed to the camera (a connected UDP socket
/// can only talk to its peer), and the SAME socket should then be used for media
/// so the mapping holds. The request is an unauthenticated server query
/// ([`stun::encode_server_query`]); the response parse + XOR-MAPPED-ADDRESS decode
/// are the offline-tested [`stun::StunMessage`] path.
///
/// `txid` is the (random in production) transaction id — the response must echo
/// it. cap4 did not need this (LAN host-direct), so it is offline-validated via a
/// loopback responder (`#[ignore]`d test), not against the camera.
///
/// # Errors
/// - [`Error::Transport`] on any socket I/O failure or a receive timeout.
/// - [`Error::Transport`] if the response is not a Binding Success for `txid`, or
///   carries no XOR-MAPPED-ADDRESS.
pub fn discover_srflx(
    socket: &UdpSocket,
    stun_server: SocketAddr,
    txid: [u8; 12],
    timeout: Duration,
) -> Result<SocketAddr, Error> {
    let query = stun::encode_server_query(txid, Some("babymonitor-rs"));
    socket
        .send_to(&query, stun_server)
        .map_err(|e| Error::Transport(format!("STUN send_to {stun_server}: {e}")))?;
    socket
        .set_read_timeout(Some(timeout))
        .map_err(|e| Error::Transport(format!("STUN set_read_timeout: {e}")))?;
    let mut buf = [0u8; 1500];
    loop {
        let n = socket
            .recv(&mut buf)
            .map_err(|e| Error::Transport(format!("STUN recv (srflx): {e}")))?;
        let msg = stun::StunMessage::decode(&buf[..n])?;
        // Ignore anything that is not the success response to *our* transaction
        // (a concurrent media/STUN packet could arrive on the same socket).
        if msg.txid != txid || !msg.is_binding_success() {
            continue;
        }
        return msg.xor_mapped_address()?.ok_or_else(|| {
            Error::Transport("STUN Binding Success carried no XOR-MAPPED-ADDRESS".to_string())
        });
    }
}

/// TURN relay (RFC 5766) — **documented stub** (AC#2, intentionally not blocking).
///
/// cap4 reached the camera via a LAN host candidate with no relay, so TURN is only
/// needed for the remote/NAT-traversed case where neither host nor srflx checks
/// succeed. A full TURN client (Allocate → CreatePermission → ChannelBind /
/// Send-indication, with the long-term-credential REALM/NONCE/MESSAGE-INTEGRITY
/// handshake) is a larger surface than this minimal layer, and there is no relay
/// path to validate it against statically. The SDP `turn:` server + the ephemeral
/// `username`/`credential`/`ttl` are already parsed
/// ([`crate::stream::signaling::IceServer`]); wiring them into an allocation is the
/// follow-up. We return a loud, typed error rather than a fake relay.
///
/// # Errors
/// Always [`Error::Transport`] — the honest "TURN relay not implemented" state.
pub fn allocate_turn_relay(_server: SocketAddr) -> Result<SocketAddr, Error> {
    Err(Error::Transport(
        "TURN relay allocation is a documented stub (not needed for cap4's LAN host-direct path; \
         required only for remote/NAT access — see transport::allocate_turn_relay docs)"
            .to_string(),
    ))
}

impl MediaTransport for UdpMediaTransport {
    fn recv_datagram(&mut self, buf: &mut [u8]) -> Result<Option<usize>, Error> {
        // ECONNREFUSED here means a prior check hit the camera's not-yet-open media
        // port (ICMP port-unreachable); it is transient during ICE — keep polling.
        classify_recv(self.socket.recv(buf))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // classify_recv: WouldBlock + ConnectionRefused (transient during ICE — the
    // camera's media port not open yet) map to Ok(None); a real error is Err.
    #[test]
    fn classify_recv_tolerates_wouldblock_and_connrefused() {
        use std::io::{Error as IoErr, ErrorKind};
        assert_eq!(classify_recv(Ok(42)).unwrap(), Some(42));
        assert_eq!(
            classify_recv(Err(IoErr::from(ErrorKind::WouldBlock))).unwrap(),
            None
        );
        assert_eq!(
            classify_recv(Err(IoErr::from(ErrorKind::ConnectionRefused))).unwrap(),
            None
        );
        assert!(matches!(
            classify_recv(Err(IoErr::from(ErrorKind::BrokenPipe))),
            Err(Error::Transport(_))
        ));
    }

    // cap3 candidate shapes (IPs are synthetic/local; the cap3 values are not
    // committed — these reproduce the STRUCTURE: host/srflx/relay).
    const HOST: &str = "a=candidate:1058984092 1 UDP 2130706431 10.0.2.15 58363 typ host";
    const SRFLX: &str = "candidate:1685826163 1 UDP 1694498815 192.0.2.7 60862 typ srflx";
    const RELAY: &str = "a=candidate:1447897382 1 UDP 16777215 198.51.100.9 62697 typ relay\r\n";

    #[test]
    fn parses_host_candidate() {
        let c = parse_candidate(HOST).unwrap();
        assert_eq!(c.kind, CandidateKind::Host);
        assert_eq!(c.component, 1);
        assert_eq!(c.transport, "UDP");
        assert_eq!(c.priority, 2_130_706_431);
        assert_eq!(c.port, 58363);
        assert_eq!(c.socket_addr().to_string(), "10.0.2.15:58363");
    }

    #[test]
    fn parses_srflx_and_relay() {
        assert_eq!(parse_candidate(SRFLX).unwrap().kind, CandidateKind::Srflx);
        let r = parse_candidate(RELAY).unwrap(); // trailing CRLF tolerated
        assert_eq!(r.kind, CandidateKind::Relay);
        assert_eq!(r.port, 62697);
    }

    #[test]
    fn orders_host_before_srflx_before_relay() {
        let cands = vec![
            parse_candidate(RELAY).unwrap(),
            parse_candidate(SRFLX).unwrap(),
            parse_candidate(HOST).unwrap(),
        ];
        let ordered = order_candidates(cands);
        let kinds: Vec<_> = ordered.iter().map(|c| c.kind).collect();
        assert_eq!(
            kinds,
            vec![
                CandidateKind::Host,
                CandidateKind::Srflx,
                CandidateKind::Relay
            ]
        );
    }

    #[test]
    fn orders_same_kind_by_descending_priority() {
        let lo = "candidate:1 1 UDP 100 10.0.0.1 5000 typ host";
        let hi = "candidate:2 1 UDP 900 10.0.0.2 5001 typ host";
        let ordered = order_candidates(vec![
            parse_candidate(lo).unwrap(),
            parse_candidate(hi).unwrap(),
        ]);
        assert_eq!(ordered[0].priority, 900, "higher priority tried first");
    }

    #[test]
    fn parses_candidates_from_sdp_block() {
        // `parse_candidates_from_sdp` selects `a=candidate:` lines; SRFLX above is
        // a bare `candidate:` (no `a=`), so prefix it here to put it in the SDP.
        let sdp =
            format!("v=0\r\nm=application 9 tuya 6001\r\n{HOST}\r\na={SRFLX}\r\na=mid:imm0\r\n");
        let cands = parse_candidates_from_sdp(&sdp).unwrap();
        assert_eq!(cands.len(), 2);
        assert_eq!(cands[0].kind, CandidateKind::Host);
        assert_eq!(cands[1].kind, CandidateKind::Srflx);
    }

    // NEGATIVE: a non-candidate line is rejected.
    #[test]
    fn rejects_non_candidate_line() {
        assert!(matches!(
            parse_candidate("a=ice-ufrag:abcd"),
            Err(Error::Transport(_))
        ));
    }

    // NEGATIVE: a malformed candidate (missing `typ`) is rejected.
    #[test]
    fn rejects_malformed_candidate() {
        assert!(matches!(
            parse_candidate("candidate:1 1 UDP 100 10.0.0.1 5000 host"),
            Err(Error::Transport(_))
        ));
    }

    // NEGATIVE: a bad IP is rejected.
    #[test]
    fn rejects_bad_ip() {
        assert!(matches!(
            parse_candidate("candidate:1 1 UDP 100 999.999.0.1 5000 typ host"),
            Err(Error::Transport(_))
        ));
    }

    // ── Host-direct selection (cap4 primary path) ──────────────────────────

    #[test]
    fn selects_highest_priority_host() {
        let cands = vec![
            parse_candidate(RELAY).unwrap(),
            parse_candidate(SRFLX).unwrap(),
            parse_candidate("candidate:1 1 UDP 100 10.0.0.1 5000 typ host").unwrap(),
            parse_candidate("candidate:2 1 UDP 900 10.0.0.2 5001 typ host").unwrap(),
        ];
        let host = select_host_candidate(&cands).unwrap();
        assert_eq!(host.kind, CandidateKind::Host);
        assert_eq!(host.priority, 900, "highest-priority host is selected");
        assert_eq!(host.socket_addr().to_string(), "10.0.0.2:5001");
    }

    #[test]
    fn select_host_prefers_rtp_component() {
        // A lower-priority component-1 (RTP) host beats a higher-priority comp-2.
        let cands = vec![
            parse_candidate("candidate:1 2 UDP 900 10.0.0.9 6000 typ host").unwrap(),
            parse_candidate("candidate:2 1 UDP 100 10.0.0.1 5000 typ host").unwrap(),
        ];
        let host = select_host_candidate(&cands).unwrap();
        assert_eq!(host.component, 1, "RTP component (1) preferred");
    }

    // NEGATIVE: no host candidate → None (host-direct cannot proceed).
    #[test]
    fn select_host_none_when_only_srflx_relay() {
        let cands = vec![
            parse_candidate(SRFLX).unwrap(),
            parse_candidate(RELAY).unwrap(),
        ];
        assert!(select_host_candidate(&cands).is_none());
    }

    // ── ICE credentials → connectivity-check USERNAME + key ────────────────

    fn synth_creds() -> IceCredentials {
        IceCredentials {
            local_ufrag: "LOCL".into(),
            local_pwd: "SyntheticLocalPwd0123456".into(), // secret-scan:allow
            remote_ufrag: "RMTE".into(),
            remote_pwd: "SyntheticRemotePwd012345".into(), // secret-scan:allow
        }
    }

    #[test]
    fn outbound_username_is_remote_colon_local() {
        assert_eq!(synth_creds().outbound_username(), "RMTE:LOCL");
    }

    #[test]
    fn build_check_is_keyed_by_remote_pwd() {
        let creds = synth_creds();
        let bytes = creds
            .build_check(
                *b"txid01234567",
                0x6eff_ffff,
                IceRole::Controlling(0x0102_0304_0506_0708),
                false,
                Some("3.5.5"),
            )
            .unwrap();
        // The check verifies under the REMOTE pwd (camera checks with its own pwd).
        assert!(stun::verify_message_integrity(&bytes, creds.remote_pwd.as_bytes()).unwrap());
        // And NOT under the local pwd.
        assert!(!stun::verify_message_integrity(&bytes, creds.local_pwd.as_bytes()).unwrap());
        let msg = stun::StunMessage::decode(&bytes).unwrap();
        assert_eq!(
            msg.attr(stun::ATTR_USERNAME).unwrap(),
            b"RMTE:LOCL".as_slice()
        );
    }

    // The secret passwords must not leak via Debug.
    #[test]
    fn ice_credentials_debug_redacts_passwords() {
        let dbg = format!("{:?}", synth_creds());
        assert!(dbg.contains("redacted"));
        assert!(!dbg.contains("SyntheticLocalPwd0123456"));
        assert!(!dbg.contains("SyntheticRemotePwd012345"));
        // Non-secret ufrags are fine to show.
        assert!(dbg.contains("LOCL") && dbg.contains("RMTE"));
    }

    // TURN relay is an honest stub (loud typed error, never a fake relay).
    #[test]
    fn turn_relay_is_a_documented_stub() {
        let err = allocate_turn_relay("198.51.100.1:3478".parse().unwrap()).unwrap_err();
        assert!(matches!(err, Error::Transport(_)));
        assert!(err.to_string().contains("TURN"));
    }

    // ── LIVE loopback proof of the srflx + check path (#[ignore]d) ─────────
    // Not in the offline gate (opens real sockets), but runnable on demand:
    //   cargo test -p babymonitor-core srflx_loopback -- --ignored --nocapture
    // A localhost "STUN server" thread answers our query with a Binding Success
    // carrying an XOR-MAPPED-ADDRESS; we assert discover_srflx returns it. This
    // exercises encode_server_query → send → recv → decode → XOR-MAPPED-ADDRESS
    // end-to-end through a real UDP round-trip with no camera/broker.
    #[test]
    #[ignore = "opens real loopback UDP sockets; run with --ignored"]
    fn srflx_loopback_round_trip() {
        use std::thread;

        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server_addr = server.local_addr().unwrap();
        let reflected: SocketAddr = "203.0.113.7:51234".parse().unwrap();

        let handle = thread::spawn(move || {
            let mut buf = [0u8; 1500];
            let (n, from) = server.recv_from(&mut buf).unwrap();
            let req = stun::StunMessage::decode(&buf[..n]).unwrap();
            // Echo a Binding Success with XOR-MAPPED-ADDRESS = `reflected`.
            let resp = build_test_binding_success(req.txid, reflected);
            server.send_to(&resp, from).unwrap();
        });

        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        let got = discover_srflx(
            &client,
            server_addr,
            *b"srflxtxid123",
            Duration::from_secs(2),
        )
        .unwrap();
        assert_eq!(got, reflected);
        handle.join().unwrap();
    }

    // Test-only Binding Success builder (mirrors the camera/STUN server).
    #[cfg(test)]
    fn build_test_binding_success(txid: [u8; 12], addr: SocketAddr) -> Vec<u8> {
        let cookie = stun::MAGIC_COOKIE.to_be_bytes();
        let mut value = vec![0x00, 0x01];
        let xport = addr.port() ^ ((stun::MAGIC_COOKIE >> 16) as u16);
        value.extend_from_slice(&xport.to_be_bytes());
        if let IpAddr::V4(ip) = addr.ip() {
            for (i, o) in ip.octets().iter().enumerate() {
                value.push(o ^ cookie[i]);
            }
        }
        let mut msg = Vec::new();
        msg.extend_from_slice(&stun::BINDING_SUCCESS.to_be_bytes());
        msg.extend_from_slice(&0u16.to_be_bytes());
        msg.extend_from_slice(&stun::MAGIC_COOKIE.to_be_bytes());
        msg.extend_from_slice(&txid);
        msg.extend_from_slice(&stun::ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        msg.extend_from_slice(&(value.len() as u16).to_be_bytes());
        msg.extend_from_slice(&value);
        let len_after = (msg.len() - 20) as u16;
        msg[2..4].copy_from_slice(&len_after.to_be_bytes());
        msg
    }
}
