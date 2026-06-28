//! `rumqttc`-backed [`MqttTransport`] adapter for the Tuya 302 signaling channel.
//!
//! This binds the [`MqttTransport`] seam (defined in [`super::session`]) to
//! `rumqttc`'s **synchronous** `Client`/`Connection` (no async runtime spun by
//! us). The broker endpoint + credentials are **injected** as a [`BrokerConfig`]
//! so nothing is hardcoded and the offline tests never touch a live broker.
//!
//! # What is real vs live-gated here
//!
//! - **Real, offline-buildable:** the rumqttc binding — [`BrokerConfig`] →
//!   `MqttOptions`, `Client::publish` on the Tuya 302 topic, `Connection`
//!   polling that filters inbound `Publish` packets on the 302 topic. This is
//!   exercised by a unit test that asserts the seam shape WITHOUT a broker.
//! - **Live-gated (follow-up):**
//!   1. **TLS.** The real Tuya broker is TLS (8883). The default build keeps
//!      rumqttc `default-features = false` (no rustls/ring) to protect the
//!      offline gate; the `live-tls` cargo feature wires rumqttc's rustls
//!      transport in [`BrokerConfig::to_mqtt_options`] for the live path.
//!   2. **The CONNECT creds.** The broker password is native-derived
//!      (`doCommandNative(2, ecode)`), so it cannot be reproduced statically —
//!      it (and the username/clientId, which depend on per-login `ecode`/`token`/
//!      `uid`) must come from a live login or a captured CONNECT. This is the
//!      live block (`re/mqtt_signaling.md`); [`BrokerConfig`] injects them.
//!   3. **The Tuya topic.** The exact 302 topic string is injected config; the
//!      localKey-AES binary message-2.2 framing is implemented in
//!      [`super::mqtt_crypto::build_302_frame`] (cap5-pinned, byte-validated).
//!
//! So this module is the honest rumqttc wiring: a buildable, seam-conformant
//! adapter whose live use is gated exactly like the rest of the stream.

use std::time::Duration;

use rumqttc::{Client, Connection, Event, MqttOptions, Packet, QoS, RecvTimeoutError};

use crate::stream::mqtt_auth::MqttCredentials;
use crate::stream::session::{
    Inbound302, MqttSignalingSession, MqttTransport, NegotiationOutcome, SignalingFlow,
};
use crate::stream::signaling::OfferEnvelopeArgs;
use crate::Error;

/// Env var that arms the **wildcard 302 subscribe diagnostic** (TASK-0080 AC#1).
///
/// The live test #1 saw the camera never answer, and the inbound 302 topic
/// (`smart/mb/in/<devId>`) is derived from the decompiled MQTT publish path but
/// NOT yet wire-confirmed (the broker is TLS:8883 and no capture carries the MQTT
/// frame). Set this var (to any non-empty value) on the owner's live run and
/// [`RumqttcTransport::connect`] ALSO subscribes to the inbound wildcard
/// (`smart/mb/in/#`) and [`RumqttcTransport::try_recv_302`] logs the exact topic +
/// payload length of EVERY inbound publish — so we observe IF and WHERE the camera
/// answers, and (in diag mode) still deliver an answer that arrives on a sibling
/// `smart/mb/in/*` topic. With the var unset, behaviour is byte-identical to
/// before (strict `== subscribe_topic` match, no extra subscribe, no logging).
pub const WILDCARD_DIAG_ENV: &str = "BM_302_WILDCARD_DIAG";

/// Whether the TASK-0080 302 topic diagnostic is armed (env [`WILDCARD_DIAG_ENV`]
/// set to a non-empty value). The `stream --diag-topics` CLI flag sets this var.
///
/// Read in BOTH [`RumqttcTransport::connect`] (extra candidate subscribes) and
/// [`super::session::MqttSignalingSession::poll_inbound`] (topic + `header.type`
/// logging) so the two layers stay consistent without threading a flag through.
#[must_use]
pub fn diag_enabled() -> bool {
    std::env::var_os(WILDCARD_DIAG_ENV).is_some_and(|v| !v.is_empty())
}

/// The wildcard topic for the inbound prefix of `topic`: everything up to and
/// including the last `/`, with `#` appended. For `smart/mb/in/<devId>` this is
/// `smart/mb/in/#`. A topic with no `/` yields `#` (subscribe-all) — the
/// maximally-permissive diagnostic fallback.
#[must_use]
pub fn inbound_wildcard(topic: &str) -> String {
    match topic.rfind('/') {
        Some(i) => format!("{}#", &topic[..=i]),
        None => "#".to_string(),
    }
}

/// The inbound prefix of `topic` (everything up to and including the last `/`),
/// used to recognise sibling inbound topics in diagnostic mode. For
/// `smart/mb/in/<devId>` this is `smart/mb/in/`. Empty if `topic` has no `/`.
#[must_use]
fn inbound_prefix(topic: &str) -> String {
    match topic.rfind('/') {
        Some(i) => topic[..=i].to_string(),
        None => String::new(),
    }
}

/// Whether an inbound publish on `topic` should be delivered as a 302 message.
///
/// Pure decision (offline-testable). Strict by default — exact match on the
/// derived `subscribe_topic`. In `diag` mode it widens to ALSO accept (so the
/// camera answer is decoded + its topic+type logged wherever it lands, TASK-0080
/// AC#3):
/// - any sibling inbound topic sharing `inbound_prefix` (another `smart/mb/in/*`), and
/// - any explicit `candidates` topic (e.g. `smart/mb/in/<uid>` or the user
///   personal `smart/mb/<uid>` — which is OUTSIDE the inbound prefix).
///
/// An empty `inbound_prefix` (degenerate topic) never widens by prefix.
#[must_use]
fn accepts_topic(
    topic: &str,
    subscribe_topic: &str,
    inbound_prefix: &str,
    candidates: &[String],
    diag: bool,
) -> bool {
    topic == subscribe_topic
        || (diag
            && ((!inbound_prefix.is_empty() && topic.starts_with(inbound_prefix))
                || candidates.iter().any(|c| c == topic)))
}

/// Injected MQTT broker configuration. NONE of these are hardcoded — the live
/// values come from the device/account at runtime (`re/webrtc_session.md` §2a;
/// `re/mqtt_signaling.md`).
///
/// # How the CONNECT creds are derived (recovered, but live-gated)
/// From `decompiled/.../com/thingclips/sdk/mqtt/qpqbppd.java` (`SdkMqttCertificationInfo`)
/// + `bqbppdq.java:1900-1929`:
/// - `host`: `ssl://<getMobileMqttsUrl()>:8883` — a region domain from the login
///   `baseConfig` (e.g. an `*.tuyaeu.com` MQTT endpoint).
/// - `client_id`: `<partnerIdentity>/mb/<uid>`.
/// - `username`: `<partnerIdentity>_v1_<mAppId>_<chKey>_mb_<token><md5tail>`.
/// - `password`: middle-16 chars of `ThingNetworkSecurity.doCommandNative(2,
///   ecode)` — derived per-session from `ecode`. The cmd2 native transform is
///   **recovered and ported** in [`super::mqtt_auth`]
///   (`md5_hex_lower(md5_hex_lower(G) ++ ecode)`, then middle-16); use
///   [`BrokerConfig::from_credentials`] to populate this from a live session.
///
/// Build these three with [`super::mqtt_auth::derive_credentials`] and inject them
/// via [`BrokerConfig::from_credentials`].
///
/// `password` (the device/account MQTT credential) is **secret** and redacted in
/// `Debug`.
#[derive(Clone)]
pub struct BrokerConfig {
    /// Broker host (the Tuya MQTT endpoint for the account's region).
    pub host: String,
    /// Broker port (1883 plain / 8883 TLS — the live Tuya broker is 8883/TLS).
    pub port: u16,
    /// Whether to connect over TLS (true for the live 8883 broker). Honored only
    /// when built with the `live-tls` feature; otherwise the connection is plain
    /// TCP (offline-build default — see module docs).
    pub tls: bool,
    /// MQTT client id (`<partnerIdentity>/mb/<uid>`).
    pub client_id: String,
    /// MQTT username (the long signed `_v1_…_mb_…` string; Tuya derives it per
    /// device/account).
    pub username: String,
    /// MQTT password — middle-16 of `doCommandNative(2, ecode)`. **SECRET** +
    /// native-derived (the live block; `re/mqtt_signaling.md`).
    pub password: String,
    /// The 302 publish topic for this device (injected — the exact Tuya topic
    /// template is a live-gated follow-up, see module docs).
    pub publish_topic: String,
    /// The 302 subscribe topic for inbound signaling.
    pub subscribe_topic: String,
    /// TASK-0080 `--diag-topics`: EXTRA candidate inbound topics to also subscribe
    /// and accept when [`diag_enabled`] (e.g. `smart/mb/in/<uid>`, `smart/mb/<uid>`);
    /// empty on the normal path (no extra subscribes / no behaviour change).
    pub diag_extra_topics: Vec<String>,
}

impl std::fmt::Debug for BrokerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BrokerConfig")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("client_id", &self.client_id)
            .field("username", &self.username)
            .field(
                "password",
                &format!("<redacted len={}>", self.password.len()),
            )
            .field("publish_topic", &self.publish_topic)
            .field("subscribe_topic", &self.subscribe_topic)
            .field("diag_extra_topics", &self.diag_extra_topics)
            .finish()
    }
}

impl BrokerConfig {
    /// Build a [`BrokerConfig`] from session-derived [`MqttCredentials`] plus the
    /// injected broker endpoint + 302 topics.
    ///
    /// This is the wiring seam for the live path: the caller derives the three
    /// CONNECT credentials with [`super::mqtt_auth::derive_credentials`] (the
    /// ported cmd2 password + clientId/username) and supplies the broker host
    /// (`ssl://<getMobileMqttsUrl()>:8883`, from the login `baseConfig`) and the
    /// device 302 topics. Nothing is hardcoded.
    #[must_use]
    pub fn from_credentials(
        credentials: MqttCredentials,
        host: impl Into<String>,
        port: u16,
        tls: bool,
        publish_topic: impl Into<String>,
        subscribe_topic: impl Into<String>,
    ) -> Self {
        Self {
            host: host.into(),
            port,
            tls,
            client_id: credentials.client_id,
            username: credentials.username,
            password: credentials.password,
            publish_topic: publish_topic.into(),
            subscribe_topic: subscribe_topic.into(),
            diag_extra_topics: Vec::new(),
        }
    }

    /// Set the TASK-0080 extra candidate inbound topics (consumed only when
    /// [`diag_enabled`]). Returns `self` for builder-style chaining.
    #[must_use]
    pub fn with_diag_topics(mut self, topics: Vec<String>) -> Self {
        self.diag_extra_topics = topics;
        self
    }

    /// Build the rumqttc `MqttOptions` from this config.
    ///
    /// Kept separate (and `pub`) so it is unit-testable WITHOUT opening a socket:
    /// a test asserts the options carry the injected host/port/credentials.
    ///
    /// TLS (port 8883) is wired only under the `live-tls` feature — it sets
    /// rumqttc's rustls transport with the platform root store. Without the
    /// feature the options are plain-TCP (the offline-build default); the live
    /// path must build with `--features live-tls`.
    #[must_use]
    pub fn to_mqtt_options(&self) -> MqttOptions {
        let mut opts = MqttOptions::new(&self.client_id, &self.host, self.port);
        opts.set_credentials(&self.username, &self.password);
        #[cfg(feature = "live-tls")]
        if self.tls {
            // Default rustls config with the OS/webpki root store — the Tuya
            // broker presents a public CA cert on 8883.
            opts.set_transport(rumqttc::Transport::tls_with_default_config());
        }
        opts
    }
}

/// A live rumqttc-backed transport over the Tuya 302 channel.
///
/// Holds the sync `Client` (for publishing) and the `Connection` (for driving
/// the eventloop + reading inbound publishes). Construct via
/// [`RumqttcTransport::connect`] — which opens a socket, so it is only used on
/// the live (#[ignore]d) path.
pub struct RumqttcTransport {
    client: Client,
    connection: Connection,
    publish_topic: String,
    subscribe_topic: String,
    /// TASK-0080: wildcard 302 diagnostic armed (env [`WILDCARD_DIAG_ENV`] set).
    /// When `true`, an extra inbound-wildcard subscribe is issued and every
    /// inbound publish is logged + accepted if it shares the inbound prefix.
    diag: bool,
    /// The inbound prefix (`smart/mb/in/`) used to recognise sibling topics in
    /// diagnostic mode. Derived once from `subscribe_topic`.
    inbound_prefix: String,
    /// TASK-0080 extra candidate inbound topics (e.g. `smart/mb/in/<uid>`,
    /// `smart/mb/<uid>`) the diagnostic subscribes + accepts. Empty off-diag.
    diag_extra_topics: Vec<String>,
    /// How long each [`try_recv_302`](MqttTransport::try_recv_302) blocks driving
    /// the sync eventloop. rumqttc's `Connection::recv_timeout` actually advances
    /// the network future; `try_recv` (`now_or_never`) only polls it ONCE and drops
    /// it, so a multi-step TLS/CONNECT/PUBLISH handshake never completes and the
    /// camera never receives the offer. This must be a blocking drive.
    drive: Duration,
}

/// The blocking drive window per poll once the connection is established — long
/// enough to flush a queued publish + read an answer, short enough to stay
/// responsive to the negotiation's poll budget.
const EVENTLOOP_DRIVE: Duration = Duration::from_millis(100);

/// The budget to complete the initial TLS + CONNECT handshake (one `recv_timeout`
/// must drive it to the CONNACK in a single `block_on`, else the future is dropped).
const CONNECT_DRIVE: Duration = Duration::from_secs(8);

impl RumqttcTransport {
    /// Connect to the broker and subscribe to the inbound 302 topic.
    ///
    /// LIVE-ONLY: this opens a TCP socket. Over the real (TLS) Tuya broker it
    /// additionally needs the `use-rustls` rumqttc feature (the offline build
    /// omits TLS — see module docs); so this currently connects plain-TCP only.
    ///
    /// If [`WILDCARD_DIAG_ENV`] is set (TASK-0080 AC#1) it ALSO subscribes to the
    /// inbound wildcard ([`inbound_wildcard`], e.g. `smart/mb/in/#`) so the
    /// camera's answer is observed even if it lands on a topic other than the
    /// derived `smart/mb/in/<devId>`.
    ///
    /// # Errors
    /// [`Error::Transport`] if the initial subscribe fails. (The actual network
    /// connect is lazy in rumqttc — driven by polling the connection.)
    pub fn connect(config: &BrokerConfig) -> Result<Self, Error> {
        let opts = config.to_mqtt_options();
        let (client, connection) = Client::new(opts, 10);
        client
            .subscribe(&config.subscribe_topic, QoS::AtLeastOnce)
            .map_err(|e| Error::Transport(format!("subscribe to 302 topic: {e}")))?;
        let diag = diag_enabled();
        if diag {
            // Subscribe to the inbound wildcard (covers EVERY `smart/mb/in/*`,
            // e.g. both `<devId>` and `<uid>`) AND each explicit extra candidate
            // (e.g. the user personal `smart/mb/<uid>`, which is OUTSIDE the
            // inbound prefix) so the camera's answer is observed wherever it lands.
            let wildcard = inbound_wildcard(&config.subscribe_topic);
            client
                .subscribe(&wildcard, QoS::AtLeastOnce)
                .map_err(|e| Error::Transport(format!("wildcard-diag subscribe: {e}")))?;
            for cand in &config.diag_extra_topics {
                client
                    .subscribe(cand, QoS::AtLeastOnce)
                    .map_err(|e| Error::Transport(format!("diag candidate subscribe: {e}")))?;
            }
            eprintln!(
                "302 topic-diag ({WILDCARD_DIAG_ENV} set): subscribed to '{}', wildcard '{}', and \
                 candidates {:?}; every inbound topic+len is logged and each accepted 302 logs its \
                 topic + header.type (bodies withheld)",
                config.subscribe_topic, wildcard, config.diag_extra_topics
            );
        }
        let mut transport = Self {
            client,
            connection,
            publish_topic: config.publish_topic.clone(),
            inbound_prefix: inbound_prefix(&config.subscribe_topic),
            subscribe_topic: config.subscribe_topic.clone(),
            diag_extra_topics: config.diag_extra_topics.clone(),
            diag,
            drive: EVENTLOOP_DRIVE,
        };
        // Drive the eventloop until the broker CONNACKs so the network is durably
        // established BEFORE the negotiation loop. Without this, the first poll's
        // connect future would be repeatedly started+cancelled by short drive
        // windows and never complete (the queued subscribe/publish never flush).
        transport.establish()?;
        Ok(transport)
    }

    /// Block (bounded) driving the eventloop until the initial CONNACK, so the TLS
    /// handshake + CONNECT complete in one `block_on` and `self.network` is set.
    ///
    /// # Errors
    /// [`Error::Transport`] if the broker errors or does not CONNACK in time.
    fn establish(&mut self) -> Result<(), Error> {
        // A handful of CONNECT_DRIVE windows: the first block_on drives the whole
        // TLS+CONNECT to the CONNACK; the extras absorb a slow first RTT.
        for _ in 0..4 {
            match self.connection.recv_timeout(CONNECT_DRIVE) {
                Ok(Ok(Event::Incoming(Packet::ConnAck(_)))) => {
                    if self.diag {
                        eprintln!("302 mqtt-diag: <- CONNACK (broker accepted CONNECT)");
                    }
                    return Ok(());
                }
                // Outgoing CONNECT / other pre-CONNACK events — keep driving.
                Ok(Ok(_)) => continue,
                Ok(Err(e)) => return Err(Error::Transport(format!("mqtt connect failed: {e}"))),
                Err(RecvTimeoutError::Timeout) => continue,
                Err(RecvTimeoutError::Disconnected) => {
                    return Err(Error::Transport(
                        "mqtt connection closed before CONNACK".to_string(),
                    ))
                }
            }
        }
        Err(Error::Transport(
            "broker did not CONNACK within the connect budget".to_string(),
        ))
    }

    /// The inbound 302 topic this transport filters on.
    #[must_use]
    pub fn subscribe_topic(&self) -> &str {
        &self.subscribe_topic
    }

    /// Whether an inbound publish should be delivered as a 302 message.
    ///
    /// Strict by default (exact `subscribe_topic` match). In diagnostic mode, a
    /// publish on ANY sibling inbound topic (`smart/mb/in/*`) is also accepted, so
    /// an answer addressed on a topic other than the derived `smart/mb/in/<devId>`
    /// still drives the negotiation (and is logged so we learn the real topic).
    fn accepts(&self, topic: &str) -> bool {
        accepts_topic(
            topic,
            &self.subscribe_topic,
            &self.inbound_prefix,
            &self.diag_extra_topics,
            self.diag,
        )
    }
}

impl MqttTransport for RumqttcTransport {
    fn publish_302(&mut self, _dev_id: &str, _pv: &str, payload: &[u8]) -> Result<(), Error> {
        // NB: `payload` is the ALREADY-localKey-AES-encrypted+Tuya-framed 302
        // payload (the crypto/framing is the caller's concern — currently
        // pending). We publish it verbatim on the device's 302 topic.
        self.client
            .publish(
                &self.publish_topic,
                QoS::AtLeastOnce,
                false,
                payload.to_vec(),
            )
            .map_err(|e| Error::Transport(format!("publish 302: {e}")))
    }

    fn try_recv_302(&mut self) -> Result<Option<Inbound302>, Error> {
        // Drive the eventloop for one `drive` window (BLOCKING). This actually
        // advances the network future — flushing queued subscribes/publishes and
        // reading inbound packets. `try_recv` (now_or_never) does NOT: it polls the
        // future once and drops it, so the handshake/publish never complete. A
        // `Publish` on our 302 topic yields the (encrypted) payload; a Timeout (no
        // event this window) is the normal idle case → `Ok(None)`.
        match self.connection.recv_timeout(self.drive) {
            Ok(Ok(Event::Incoming(Packet::Publish(p)))) => {
                if self.diag {
                    // AC#3: log the EXACT topic + payload length of every inbound
                    // publish (payload is encrypted — length only, never bytes).
                    // The decoded header.type of accepted frames is logged one
                    // layer up in `MqttSignalingSession::poll_inbound`.
                    eprintln!(
                        "302 topic-diag: inbound publish topic='{}' payload_len={} accepted={}",
                        p.topic,
                        p.payload.len(),
                        self.accepts(&p.topic)
                    );
                }
                if self.accepts(&p.topic) {
                    Ok(Some(Inbound302 {
                        topic: Some(p.topic.clone()),
                        payload: p.payload.to_vec(),
                    }))
                } else {
                    Ok(None)
                }
            }
            // Other events (acks, pings, connect). In diag mode, log the broker's
            // SUBACK/PUBACK/CONNACK so a "camera silent" run can tell whether the
            // broker actually accepted our subscribe + publish (delivery proof),
            // not just whether the camera answered.
            Ok(Ok(ev)) => {
                if self.diag {
                    match &ev {
                        Event::Incoming(Packet::SubAck(_)) => {
                            eprintln!("302 mqtt-diag: <- SUBACK (subscribe accepted by broker)");
                        }
                        Event::Incoming(Packet::PubAck(_)) => {
                            eprintln!("302 mqtt-diag: <- PUBACK (publish accepted by broker)");
                        }
                        Event::Incoming(Packet::ConnAck(_)) => {
                            eprintln!("302 mqtt-diag: <- CONNACK (broker accepted CONNECT)");
                        }
                        Event::Outgoing(o) => {
                            eprintln!("302 mqtt-diag: -> outgoing {o:?}");
                        }
                        _ => {}
                    }
                }
                Ok(None)
            }
            // A connection error surfaces loud rather than being swallowed.
            Ok(Err(e)) => Err(Error::Transport(format!("mqtt connection error: {e}"))),
            // No event within this drive window — the normal idle case.
            Err(RecvTimeoutError::Timeout) => Ok(None),
            // The broker dropped the connection.
            Err(RecvTimeoutError::Disconnected) => {
                Err(Error::Transport("mqtt connection closed".to_string()))
            }
        }
    }
}

/// The inputs to one live 302 signaling exchange (bundled to keep
/// [`connect_and_negotiate`] under clippy's argument limit). The `flow` carries
/// the routing ids; the borrowed fields are the device framing material + the
/// offer/candidate payloads to send.
pub struct LiveSignalingParams<'a> {
    /// The signaling [`SignalingFlow`] (routing ids + lifecycle).
    pub flow: SignalingFlow,
    /// The device `localKey` bytes (16) — the 302-frame AES key.
    pub local_key: &'a [u8],
    /// The device id (`gwId` + publish target).
    pub dev_id: &'a str,
    /// The device protocol version (`pv`).
    pub pv: &'a str,
    /// The offer envelope args (SDP + ICE/relay descriptors).
    pub offer_args: &'a OfferEnvelopeArgs,
    /// The local ICE candidate lines to trickle (the end-of-candidates sentinel
    /// is appended automatically by [`MqttSignalingSession::negotiate_with_trickle`]).
    pub local_candidates: &'a [String],
    /// Bounded receive budget for the camera answer (phase 1).
    pub max_polls: usize,
    /// Extra polls AFTER the answer to collect the camera's trickled candidates
    /// (phase 2). The answer SDP carries none — cap3/cap4 — so this window is where
    /// the host candidate actually arrives.
    pub trickle_polls: usize,
    /// Sleep between empty non-blocking polls — paces the live `rumqttc` eventloop
    /// so it does not busy-spin (offline callers use [`Duration::ZERO`]).
    pub poll_interval: Duration,
}

/// LIVE-ONLY: connect to the Tuya broker, subscribe to the device 302 topic, run
/// the full WebRTC-over-MQTT offer/answer exchange, and collect the camera's
/// trickled ICE candidates ([`NegotiationOutcome`] = the parsed answer + the
/// remote candidate set).
///
/// Composes the live wiring end-to-end:
/// [`RumqttcTransport::connect`] (opens the socket + subscribes to the 302 topic)
/// → [`MqttSignalingSession::negotiate_with_trickle`] (publish the offer + local
/// candidates over `mqtt`+`lan`, receive + parse the answer, then keep collecting
/// the camera's trickled `candidate` messages). The trickle phase is required: the
/// camera's answer SDP carries no `a=candidate:` lines (cap3/cap4), so its host
/// candidate only arrives as separate 302 `candidate` messages after the answer.
/// Build `config` from session-derived creds with [`BrokerConfig::from_credentials`].
///
/// This opens a real socket, so it is **never** exercised in the offline tests —
/// the mock-transport tests in [`super::session`] cover the publish/poll/answer +
/// trickle wiring with no broker. The TLS upgrade for the 8883 broker is wired only
/// under the `live-tls` feature (see [`BrokerConfig::to_mqtt_options`]); without it
/// this connects plain-TCP (the offline-build default), so a real run needs
/// `--features live-tls`.
///
/// # Errors
/// Propagates connect/subscribe/publish/parse errors; [`Error::Transport`] if the
/// camera does not answer within `params.max_polls`.
pub fn connect_and_negotiate(
    config: &BrokerConfig,
    params: LiveSignalingParams<'_>,
) -> Result<NegotiationOutcome, Error> {
    let mut transport = RumqttcTransport::connect(config)?;
    let mut session = MqttSignalingSession::new(
        &mut transport,
        params.flow,
        params.local_key.to_vec(),
        params.dev_id,
        params.pv,
    );
    session.negotiate_with_trickle(
        params.offer_args,
        params.local_candidates,
        params.max_polls,
        params.trickle_polls,
        params.poll_interval,
        // Stop the trickle window the instant the camera's `typ host` candidate is
        // in hand, so the media path opens promptly (TASK-0083 time-to-first-frame).
        crate::stream::session::has_usable_host_candidate,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synth_config() -> BrokerConfig {
        // SYNTHETIC values only — never a real broker/credential (CLAUDE.md).
        BrokerConfig {
            host: "broker.invalid".into(),
            port: 1883,
            tls: false,
            client_id: "SYNTH_CLIENT".into(),
            username: "SYNTH_USER".into(),
            password: "SYNTH_PASS_0000".into(),
            publish_topic: "tuya/dev/SYNTH/p2p/pub".into(),
            subscribe_topic: "tuya/dev/SYNTH/p2p/sub".into(),
            diag_extra_topics: Vec::new(),
        }
    }

    // TASK-0080 AC#1: the wildcard-diag helpers derive the right inbound topic
    // family from a `smart/mb/in/<devId>` subscribe topic (SYNTHETIC devId).
    #[test]
    fn inbound_wildcard_and_prefix_for_device_topic() {
        let sub = "smart/mb/in/synthdev0001ufmo";
        assert_eq!(inbound_wildcard(sub), "smart/mb/in/#");
        assert_eq!(inbound_prefix(sub), "smart/mb/in/");
    }

    // Degenerate topics: no `/` => subscribe-all wildcard, empty prefix.
    #[test]
    fn inbound_wildcard_and_prefix_for_bare_topic() {
        assert_eq!(inbound_wildcard("flat"), "#");
        assert_eq!(inbound_prefix("flat"), "");
    }

    // The pure accept decision: strict by default, prefix-widened only in diag.
    #[test]
    fn accepts_topic_strict_vs_diag() {
        let sub = "smart/mb/in/synthdev0001ufmo";
        let pre = inbound_prefix(sub);
        let sibling = "smart/mb/in/synthOTHERdevice";
        let foreign = "smart/mb/out/synthdev0001ufmo";
        // The user personal topic — OUTSIDE the inbound prefix; only accepted in
        // diag when listed as an explicit candidate.
        let personal = "smart/mb/eu0000000000000synth".to_string();
        let cands = vec![personal.clone()];
        let none: &[String] = &[];

        // Strict mode: only the exact subscribe topic is accepted (candidates ignored).
        assert!(accepts_topic(sub, sub, &pre, &cands, false));
        assert!(!accepts_topic(sibling, sub, &pre, &cands, false));
        assert!(!accepts_topic(foreign, sub, &pre, &cands, false));
        assert!(!accepts_topic(&personal, sub, &pre, &cands, false));

        // Diag mode: the exact topic, any sibling inbound topic, AND each explicit
        // candidate are accepted, but a non-inbound (out/) topic is still rejected.
        assert!(accepts_topic(sub, sub, &pre, none, true));
        assert!(accepts_topic(sibling, sub, &pre, none, true));
        assert!(!accepts_topic(foreign, sub, &pre, none, true));
        // The personal topic is accepted ONLY when listed as a candidate.
        assert!(!accepts_topic(&personal, sub, &pre, none, true));
        assert!(accepts_topic(&personal, sub, &pre, &cands, true));

        // An empty prefix (degenerate sub topic) never widens by prefix, even in diag.
        assert!(!accepts_topic("anything", "exact", "", none, true));
        assert!(accepts_topic("exact", "exact", "", none, true));
    }

    // The rumqttc options binding is testable WITHOUT a socket: assert the
    // injected host/port/keepalive land in MqttOptions. (Credentials are not
    // readable back out of MqttOptions, so we assert what the API exposes.)
    #[test]
    fn broker_config_builds_mqtt_options() {
        let cfg = synth_config();
        let opts = cfg.to_mqtt_options();
        assert_eq!(opts.broker_address(), ("broker.invalid".to_string(), 1883));
        assert_eq!(opts.client_id(), "SYNTH_CLIENT");
    }

    // BrokerConfig must redact the password in Debug — never leak it via {:?}.
    #[test]
    fn broker_config_redacts_password() {
        let cfg = synth_config();
        let dbg = format!("{cfg:?}");
        assert!(dbg.contains("redacted"));
        assert!(!dbg.contains("SYNTH_PASS_0000"));
        // Non-secret fields are fine to show.
        assert!(dbg.contains("broker.invalid"));
    }

    // Derived MQTT credentials flow cleanly into a BrokerConfig via the wiring
    // constructor (the live path's seam) and the password stays redacted.
    #[test]
    fn broker_config_from_credentials_wires_seam() {
        use crate::stream::mqtt_auth::MqttCredentials;
        let creds = MqttCredentials {
            client_id: "PARTNERX/mb/SYNTH_UID".into(),
            username: "PARTNERX_v1_APP_chk_mb_TOKtail".into(),
            password: "0123456789abcdef".into(), // SYNTHETIC middle-16
        };
        let cfg = BrokerConfig::from_credentials(
            creds,
            "broker.invalid",
            8883,
            true,
            "tuya/dev/SYNTH/p2p/pub",
            "tuya/dev/SYNTH/p2p/sub",
        );
        assert_eq!(cfg.client_id, "PARTNERX/mb/SYNTH_UID");
        assert_eq!(cfg.username, "PARTNERX_v1_APP_chk_mb_TOKtail");
        assert_eq!(cfg.port, 8883);
        assert!(cfg.tls);
        // The MqttOptions binding carries the injected client id + endpoint.
        let opts = cfg.to_mqtt_options();
        assert_eq!(opts.broker_address(), ("broker.invalid".to_string(), 8883));
        assert_eq!(opts.client_id(), "PARTNERX/mb/SYNTH_UID");
        // Password is still redacted in Debug (never leaked via {:?}).
        assert!(format!("{cfg:?}").contains("redacted"));
        assert!(!format!("{cfg:?}").contains("0123456789abcdef"));
    }

    // The LIVE connect is honestly NOT exercised offline (it opens a socket).
    // This test documents the gating: we assert the config shape is ready, but
    // we do NOT call connect() here (that is the #[ignore]d live test's job).
    #[test]
    fn connect_is_not_exercised_offline() {
        let cfg = synth_config();
        // Build options (no socket) — proves the path up to connect is wired.
        let _opts = cfg.to_mqtt_options();
        // We intentionally do not call RumqttcTransport::connect(&cfg) here: it
        // would attempt a real TCP connection. The live path is gated in the
        // #[ignore]d integration test (tests/live_e2e.rs).
    }
}
