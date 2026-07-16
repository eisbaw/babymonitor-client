//! RE-derived Tuya live A/V protocol implementation.
//!
//! Signaling uses the shared `{header,msg}` offer/answer/candidate codec in
//! [`signaling`] over exactly one selected carrier:
//!
//! - cloud MQTT uses [`mqtt_crypto`] message-2.2 framing and the live
//!   [`transport`] adapter;
//! - local mode uses Tuya 3.3/3.4/3.5 `IPC_LAN_302` frame type 32 in
//!   [`tuya_lan`] and [`lan_transport`], with [`lan_discovery`] resolving a
//!   DHCP-assigned endpoint by matching the camera's cached device id.
//!
//! [`session`] owns the transport-neutral negotiation and strict trace/session
//! correlation. [`sdp`] carries the ICE credentials and media AES key. The media
//! path is Tuya's custom host-direct UDP + ICE/STUN + KCP + authenticated
//! AES-CBC/GCM framing, implemented by [`media`]; it is not DTLS-SRTP and does
//! not require webrtc-rs.
//!
//! The production CLI wires signaling through media and output under its `live`
//! feature. Cloud mode needs an authorized session/runtime record; LAN mode needs
//! an already paired camera's owner-provisioned IP, device ID, sender ID,
//! localKey, and Hgw version. Offline tests exercise both carrier state machines
//! and the media codecs without fabricating an owner-camera result. TASK-0126
//! live-proved a frame-32 -> ICE/KCP stream with every client WAN destination
//! denied and only the camera's private address allowed.

pub mod connect;
pub mod frame;
pub mod lan_config;
pub mod lan_discovery;
pub mod lan_transport;
pub mod media;
pub mod mqtt_auth;
pub mod mqtt_crypto;
pub mod rtc_config;
pub mod sdp;
pub mod session;
pub mod signaling;
pub mod topics;
pub mod transport;
pub mod tuya_lan;

use crate::Error;
use zeroize::Zeroize;

/// Render an `Option<String>`-shaped secret for `Debug` without leaking its
/// value. Mirrors the redaction helpers in `sign.rs` / `device.rs`.
fn dbg_secret(s: &str) -> String {
    format!("<redacted len={}>", s.len())
}

/// Carrier-neutral credential container injected into offer/media assembly.
///
/// Cloud mode populates the full record from the owner's authorized device and
/// `rtc.config` responses. LAN mode populates the shared device/sender/localKey
/// and optional media-password fields from its secure pre-provisioned cache;
/// cloud-only token/relay/session fields are empty and never validated or used.
/// Secret-bearing fields are redacted from `Debug` and zeroized on drop.
///
/// Tests construct this with SYNTHETIC values only (CLAUDE.md).
#[derive(Clone)]
pub struct StreamCredentials {
    /// Cloud-only per-session signaling token. Empty and unused in LAN mode.
    /// **SECRET** when present.
    pub token: String,
    /// Sender/account routing ID used as `header.from` and SDP cname. In cloud
    /// mode the runtime assembler supplies the account UID; LAN mode loads the
    /// same pre-provisioned value from its secure cache. Sensitive.
    pub p2p_id: String,
    /// Tuya device ID: signaling `header.to` on both carriers and the MQTT
    /// publish target in cloud mode. Account-linked PII.
    pub dev_id: String,
    /// Cloud capability JSON. LAN offer assembly uses `{}` and does not consume
    /// cloud capability/session control.
    pub skill: String,
    /// Cloud `P2pConfig.p2pKey`. Empty and unused in LAN mode. **SECRET**.
    pub p2p_key: String,
    /// Cloud STUN/TURN server JSON. LAN credentials keep this empty;
    /// `negotiate_lan` injects an ephemeral LAN-local STUN entry directly.
    pub ices: String,
    /// Cloud session descriptor. Empty/unused in LAN mode. **SECRET**.
    pub session: String,
    /// Cloud `P2pConfig.tcpRelay` as a compact JSON string — echoed (with a re-minted
    /// `sessionId`) as the offer `msg.tcp_token` (cap3). `""` if the cloud returned
    /// none, in which case the offer omits it. **SECRET-adjacent** (relay HMAC).
    pub tcp_relay: String,
    /// Cloud `P2pConfig.log` as a compact JSON string — passed through verbatim as the
    /// offer `msg.log` (cap3). `""` if absent. **SECRET-adjacent** (log auth key).
    pub log: String,
    /// Device `localKey`: MQTT inner-payload AES key in cloud mode and the root
    /// authentication/session key for Tuya LAN 3.4/3.5. **SECRET**.
    pub local_key: String,
    /// Carrier protocol label: cloud `DeviceBean.pv` for MQTT; LAN retains the
    /// Hgw version here for diagnostics while `Lan302ConnectConfig` carries the
    /// parsed version used on the wire.
    pub pv: String,
    /// Camera-info password used to derive the conv=0 media-start AUTH value.
    /// Cloud mode receives it from `rtc.config`; LAN may use a cached
    /// owner-provisioned value whose reset/refresh stability is unproven. Empty
    /// means no AUTH PDU. **SECRET** — never logged.
    pub media_auth_password: String,
}

impl StreamCredentials {
    /// Validate cloud-mode load-bearing handles. A cloud live session with an
    /// empty `token`/`p2p_id`/`dev_id`/`local_key` cannot succeed, so we reject
    /// it loudly up front rather than emitting a malformed `connect_v2` / a
    /// broken AES key.
    ///
    /// # Errors
    /// [`Error::StreamConfig`] naming the first empty required field.
    pub fn validate(&self) -> Result<(), Error> {
        for (name, val) in [
            ("token", &self.token),
            ("p2p_id", &self.p2p_id),
            ("dev_id", &self.dev_id),
            ("local_key", &self.local_key),
        ] {
            if val.is_empty() {
                return Err(Error::StreamConfig(format!(
                    "required stream credential `{name}` is empty"
                )));
            }
        }
        Ok(())
    }
}

impl Drop for StreamCredentials {
    fn drop(&mut self) {
        // The struct is shared by cloud and LAN setup, so clear every owned
        // account/device/session string rather than trying to maintain a second,
        // inevitably drifting list of which fields are sensitive.
        self.token.zeroize();
        self.p2p_id.zeroize();
        self.dev_id.zeroize();
        self.skill.zeroize();
        self.p2p_key.zeroize();
        self.ices.zeroize();
        self.session.zeroize();
        self.tcp_relay.zeroize();
        self.log.zeroize();
        self.local_key.zeroize();
        self.pv.zeroize();
        self.media_auth_password.zeroize();
    }
}

impl std::fmt::Debug for StreamCredentials {
    /// Redacts every secret-bearing field; never leaks values via `{:?}`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamCredentials")
            .field("token", &dbg_secret(&self.token))
            .field("p2p_id", &dbg_secret(&self.p2p_id))
            .field("dev_id", &dbg_secret(&self.dev_id))
            .field("skill", &self.skill) // capability JSON, not a secret
            .field("p2p_key", &dbg_secret(&self.p2p_key))
            .field("ices", &dbg_secret(&self.ices))
            .field("session", &dbg_secret(&self.session))
            .field("tcp_relay", &dbg_secret(&self.tcp_relay))
            .field("log", &dbg_secret(&self.log))
            .field("local_key", &dbg_secret(&self.local_key))
            .field("pv", &self.pv)
            .field(
                "media_auth_password",
                &dbg_secret(&self.media_auth_password),
            )
            .finish()
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::StreamCredentials;

    /// SYNTHETIC credentials for tests — never a real value (CLAUDE.md).
    #[must_use]
    pub fn synth_credentials() -> StreamCredentials {
        StreamCredentials {
            token: "SYNTH_TOKEN_0000".into(),
            p2p_id: "SYNTH_P2PID_0000".into(),
            dev_id: "SYNTH_DEVID_0000".into(),
            skill: "{}".into(),
            p2p_key: "SYNTH_P2PKEY_0000".into(),
            ices: "[]".into(),
            session: "{}".into(),
            tcp_relay: String::new(),
            log: String::new(),
            // 16 bytes of synthetic key material (AES-128 sized).
            local_key: "0123456789abcdef".into(), // secret-scan:allow (synthetic test value)
            pv: "2.2".into(),
            media_auth_password: "SynthAuthPwd".into(), // secret-scan:allow (synthetic test pwd)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_accepts_full_credentials() {
        let creds = test_support::synth_credentials();
        assert!(creds.validate().is_ok());
    }

    // NEGATIVE: an empty required handle must be rejected loudly (prove the
    // check bites; a green check that can't go red is not grounding).
    #[test]
    fn validate_rejects_empty_required_field() {
        let mut creds = test_support::synth_credentials();
        creds.token = String::new();
        assert!(matches!(creds.validate(), Err(Error::StreamConfig(_))));

        let mut creds = test_support::synth_credentials();
        creds.local_key = String::new();
        assert!(matches!(creds.validate(), Err(Error::StreamConfig(_))));
    }

    #[test]
    fn debug_redacts_secrets() {
        let creds = test_support::synth_credentials();
        let dbg = format!("{creds:?}");
        assert!(dbg.contains("redacted"));
        // None of the secret VALUES may appear.
        assert!(!dbg.contains("SYNTH_TOKEN_0000"));
        assert!(!dbg.contains("SYNTH_P2PKEY_0000"));
        assert!(!dbg.contains("0123456789abcdef"));
        assert!(
            !dbg.contains("SynthAuthPwd"),
            "auth password must be redacted"
        );
        // Non-secret fields (skill JSON, pv) are fine to show.
        assert!(dbg.contains("pv"));
    }
}
