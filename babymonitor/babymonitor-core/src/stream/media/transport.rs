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
}

impl UdpMediaTransport {
    /// Bind a local UDP socket and `connect` it to `peer` (a selected candidate's
    /// `ip:port`), so only that peer's datagrams are received. Non-blocking.
    ///
    /// LIVE-ONLY: opens a socket. The caller picks `peer` via [`order_candidates`]
    /// (and, for srflx/relay, must have completed the STUN/TURN handshake that is
    /// out of scope here).
    ///
    /// # Errors
    /// [`Error::Transport`] if binding, connecting, or setting non-blocking fails.
    pub fn connect(local: SocketAddr, peer: SocketAddr) -> Result<Self, Error> {
        let socket = UdpSocket::bind(local)
            .map_err(|e| Error::Transport(format!("bind media UDP socket {local}: {e}")))?;
        socket
            .connect(peer)
            .map_err(|e| Error::Transport(format!("connect media UDP to {peer}: {e}")))?;
        socket
            .set_nonblocking(true)
            .map_err(|e| Error::Transport(format!("set media socket non-blocking: {e}")))?;
        Ok(Self { socket })
    }
}

impl MediaTransport for UdpMediaTransport {
    fn recv_datagram(&mut self, buf: &mut [u8]) -> Result<Option<usize>, Error> {
        match self.socket.recv(buf) {
            Ok(n) => Ok(Some(n)),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(Error::Transport(format!("media UDP recv: {e}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
