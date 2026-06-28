//! The Tuya mobile MQTT **302 publish / subscribe topic** derivation (TASK-0078).
//!
//! These were the project's #1 signaling unknown — the live `stream` path used to
//! carry them as injected strings in `secrets/stream_runtime.json`. They are now
//! **derived** from the decompiled MQTT publish path, so `stream --live` needs only
//! the camera `devId`.
//!
//! # Derivation (confidence: confirmed — two independent Java sources)
//!
//! The IPC 302 signaling rides the **standard mobile device-control MQTT channel**
//! (not a dedicated WebRTC topic). Tracing the publish:
//!
//! 1. `P2PMQTTServiceManager.send302MessageThroughMqtt` →
//!    `homeCamera.publish(devId, pv, localKey, json, 302, cb)`
//!    (`com/thingclips/smart/p2p/utils/P2PMQTTServiceManager.java:1550`).
//! 2. `homeCamera.publish(str, …)` builds the control with the topic id = its first
//!    arg: `new MqttControlBuilder()…​.r(str)…`, and `str` is the `devId`
//!    (`com/thingclips/smart/p2p/qqpddqd.java:1130-1137`). `MqttControlBuilder.r()`
//!    sets field `g` (`…/interior/mqtt/MqttControlBuilder.java:861,920`), which
//!    `MqttControlBuilder.i()` returns (`:258`).
//! 3. `MqttServerManager.publishDevice` then uses that id `i`
//!    (`com/thingclips/sdk/mqtt/bqbppdq.java:3660-3678`):
//!    - **subscribe** to `"smart/mb/in/" + i`  (line 3661) — inbound (device → app),
//!    - **publish**  to  `"smart/mb/out/" + i` — the actual 302 send is
//!      `send302Message(bArr, "smart/mb/out/" + pdqppqb, …)` (line 1503/1515),
//!      where the `"smart/mb/out/"` constant is `bqbppdq.qqpddqd` (`:61`).
//!
//! So with `i == devId`:
//! - **publish topic** (app → camera, offer + ICE candidates): [`publish_topic`] =
//!   `smart/mb/out/<devId>`.
//! - **subscribe topic** (camera → app, answer + ICE candidates): [`subscribe_topic`]
//!   = `smart/mb/in/<devId>`.
//!
//! # Capture status (honest)
//!
//! The literal topic strings are **NOT byte-confirmed by capture**: the broker is
//! TLS:8883 and the cap0–cap3 mitmproxy is HTTP-only, and cap4 is the media UDP
//! pcap — so no captured MQTT frame carries the topic. What IS validated against
//! the captures is the **input** `devId`: the same `devId` from `rtc.config.get`
//! appears as the cap3 302 `header.to` / `gwId` (`tests/rtc_config_cap.rs`). The
//! template itself is the two-source Java derivation above, to be wire-confirmed on
//! the owner's live run (a broker subscribe/publish trace).

/// The mobile-app MQTT topic-id prefix for **outbound** (app → device) messages,
/// including the 302 offer + trickled ICE candidates. `bqbppdq.qqpddqd` (`:61`).
const PUBLISH_PREFIX: &str = "smart/mb/out/";

/// The mobile-app MQTT topic-id prefix for **inbound** (device → app) messages,
/// including the 302 answer + the camera's trickled ICE candidates. `bqbppdq:3661`.
const SUBSCRIBE_PREFIX: &str = "smart/mb/in/";

/// The mobile-app MQTT prefix for **user-level** personal pushes (`smart/mb/<uid>`),
/// distinct from the device inbound `smart/mb/in/<devId>`. From the dp-router
/// topic-suffix set `["smart/mb/in/", "m/dg/", "smart/mb/<uid>"]`
/// (`com/thingclips/.../qqpqqpq.getTopicSuffix():345`). The 302 answer is NOT
/// believed to ride this topic (the RE pins `smart/mb/in/<devId>`), but the cap3
/// answer header `to` is the account **uid**, so it is a candidate the TASK-0080
/// `--diag-topics` diagnostic probes to rule it in or out live.
const PERSONAL_PREFIX: &str = "smart/mb/";

/// The 302 **publish** topic for a camera: `smart/mb/out/<devId>`.
///
/// This is where the client publishes its offer and trickled ICE candidates.
#[must_use]
pub fn publish_topic(dev_id: &str) -> String {
    format!("{PUBLISH_PREFIX}{dev_id}")
}

/// The 302 **subscribe** topic for a camera: `smart/mb/in/<devId>`.
///
/// This is where the client receives the camera's answer + trickled candidates.
#[must_use]
pub fn subscribe_topic(dev_id: &str) -> String {
    format!("{SUBSCRIBE_PREFIX}{dev_id}")
}

/// The user **personal** topic `smart/mb/<uid>` (a TASK-0080 diagnostic candidate,
/// NOT the strict 302 channel — see [`PERSONAL_PREFIX`]).
#[must_use]
pub fn personal_topic(uid: &str) -> String {
    format!("{PERSONAL_PREFIX}{uid}")
}

/// The EXTRA inbound-topic candidates the `--diag-topics` run subscribes + accepts
/// **in addition to** the strict `smart/mb/in/<devId>` (TASK-0080 AC#3): the uid
/// inbound `smart/mb/in/<uid>` (the disproven-but-probed "app subscribes on its own
/// id" hypothesis) and the user personal `smart/mb/<uid>`. The strict device topic
/// is already subscribed separately, so it is intentionally excluded here.
/// De-duplicated and never empty-id-bearing.
#[must_use]
pub fn diag_extra_topics(dev_id: &str, uid: &str) -> Vec<String> {
    let mut out = Vec::new();
    if !uid.is_empty() {
        let uid_inbound = subscribe_topic(uid);
        // Skip if it collides with the device inbound (uid == devId is unexpected).
        if uid_inbound != subscribe_topic(dev_id) {
            out.push(uid_inbound);
        }
        out.push(personal_topic(uid));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // A synthetic devId (no real account device id).
    const DEV: &str = "synthdev0001ufmo";

    #[test]
    fn topics_use_the_devid() {
        assert_eq!(publish_topic(DEV), "smart/mb/out/synthdev0001ufmo");
        assert_eq!(subscribe_topic(DEV), "smart/mb/in/synthdev0001ufmo");
    }

    #[test]
    fn publish_and_subscribe_differ_only_in_direction_segment() {
        // The two topics share the devId and differ only in out/ vs in/ — the
        // exact app behaviour (publishDevice subscribes in/<id>, publishes out/<id>).
        let p = publish_topic(DEV);
        let s = subscribe_topic(DEV);
        assert_eq!(p.replace("/out/", "/DIR/"), s.replace("/in/", "/DIR/"));
        assert_ne!(p, s);
    }

    // A synthetic uid (no real account uid).
    const UID: &str = "eu0000000000000synth";

    #[test]
    fn personal_topic_uses_the_uid() {
        assert_eq!(personal_topic(UID), "smart/mb/eu0000000000000synth");
        // The personal topic is OUTSIDE the device inbound prefix.
        assert!(!personal_topic(UID).starts_with("smart/mb/in/"));
    }

    #[test]
    fn diag_extra_topics_are_the_uid_inbound_plus_personal() {
        let extra = diag_extra_topics(DEV, UID);
        assert_eq!(
            extra,
            vec![
                "smart/mb/in/eu0000000000000synth".to_string(),
                "smart/mb/eu0000000000000synth".to_string(),
            ]
        );
        // The strict device inbound is NOT included (subscribed separately).
        assert!(!extra.contains(&subscribe_topic(DEV)));
    }

    #[test]
    fn diag_extra_topics_skip_uid_devid_collision() {
        // Degenerate: uid == devId — the uid-inbound collides with the device
        // inbound and is dropped; only the personal topic remains.
        let extra = diag_extra_topics(DEV, DEV);
        assert_eq!(extra, vec![personal_topic(DEV)]);
    }

    #[test]
    fn diag_extra_topics_empty_uid_yields_none() {
        assert!(diag_extra_topics(DEV, "").is_empty());
    }

    #[test]
    fn empty_devid_yields_bare_prefix() {
        // A defensive shape check — the caller validates a non-empty devId
        // upstream (StreamCredentials.validate), but the pure function is total.
        assert_eq!(publish_topic(""), "smart/mb/out/");
        assert_eq!(subscribe_topic(""), "smart/mb/in/");
    }
}
