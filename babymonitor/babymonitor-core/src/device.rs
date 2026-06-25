//! Tuya device-list / device-binding typed models + a list service.
//!
//! These are the typed serde models the Rust client uses to discover the
//! SCD921 camera under the user's Tuya account and to surface its P2P/WebRTC
//! credential handles. The shapes are recovered **statically** from the
//! decompiled Tuya beans and the documented wire payload in
//! `re/tuya_cloud_auth.md` §5; the P2P-transport selection from
//! `re/streaming_mode.md`.
//!
//! # Grounding (symbol-anchored — line hints are approximate, jadx-run-dependent)
//!
//! - The device-list container is `HomeBean.deviceList : List<DeviceBean>`
//!   (`com/thingclips/smart/home/sdk/bean/HomeBean.java`).
//! - [`DeviceBean`] fields: `devId`/`localKey`/`secKey`/`uuid`/`pv`/`productId`/
//!   `category`/`isOnline`/`skills` (`com/thingclips/smart/sdk/bean/DeviceBean.java`).
//! - [`CameraInfoBean`] + nested [`P2pConfig`]
//!   (`com/thingclips/smart/camera/ipccamerasdk/bean/CameraInfoBean.java`;
//!   `P2pConfig` declares `ices`/`initStr`/`p2pKey`/`session`/`tcpRelay`/`udpRelay`).
//! - `p2pType` is present on the **wire** (the embedded sample payload in
//!   `com/thingclips/smart/camera/middleware/pqpbpqd.java` carries `"p2pType":4`),
//!   even though it is not a *declared* Java field of `CameraInfoBean` — FastJSON
//!   tolerates unmapped JSON keys. We model it explicitly because it is the
//!   transport selector. The enum mapping is authoritative:
//!   `ThingCameraConstants.P2PType { P2P_TYPE_PPCS(2), P2P_TYPE_THING(4) }`
//!   (`com/thingclips/smart/camera/api/ThingCameraConstants.java`), confirmed in
//!   `re/streaming_mode.md` (`p2pType` 2=PPCS / 4=THING-WebRTC). See
//!   [`P2pTransport`].
//!
//! # Required vs optional invariants (NOT a permissive serde sponge)
//!
//! Most cloud fields are genuinely-optional (the real atop API omits fields per
//! account/firmware), so they are `Option<T>` / `#[serde(default)]`. But the
//! camera's **load-bearing identity/credential handles are REQUIRED** so a
//! malformed record is REJECTED with a typed serde error rather than silently
//! parsed into a half-empty struct:
//! - [`DeviceBean::dev_id`] — required (the P2P/MQTT addressing key);
//! - [`CameraInfoBean::p2p_id`] — required (the P2P device handle / IOTC UID);
//! - [`CameraInfoBean::p2p_type`] — required (the transport selector).
//!
//! A negative test (`device::tests::malformed_*`) proves each of these bites.
//!
//! # Secrets (CLAUDE.md: never leak a secret through any channel)
//!
//! The following fields are **secret** and are REDACTED from the custom `Debug`
//! impls (a test proves they never appear in `{:?}`):
//! `DeviceBean.local_key`, `DeviceBean.sec_key`, `CameraInfoBean.password`,
//! `CameraInfoBean.session_tid`, `P2pConfig.p2p_key`, `P2pConfig.init_str`.
//! `dev_id`/`uuid`/`p2p_id` are not crypto secrets but are account-linked PII —
//! callers must not print them by default (feed-forward to the CLI, TASK-0014).
//!
//! # Offline-first core
//!
//! [`parse_device_list`] takes a response **body** (injected bytes) so it is
//! fully testable offline. A real HTTP fetch is intentionally NOT implemented in
//! this core crate: the device list rides an authenticated session produced by the
//! live auth path or injected into the CLI store. [`list_devices`] threads signer
//! and session inputs through the API and returns [`Error::BmpTokenPending`] when
//! callers still supply the pending signer. Either way it never makes a live call
//! and never fabricates a response.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::sign::{BmpTokenProvider, SigningKeyMaterial};
use crate::Error;

// ─────────────────────────────────────────────────────────────────────────────
// P2P transport selection (p2pType -> which transport)
// ─────────────────────────────────────────────────────────────────────────────

/// The wire `p2pType` integer for the THING/WebRTC transport
/// (`ThingCameraConstants.P2PType.P2P_TYPE_THING(4)`).
pub const P2P_TYPE_THING_WEBRTC: i32 = 4;

/// The wire `p2pType` integer for the legacy PPCS/IOTC transport
/// (`ThingCameraConstants.P2PType.P2P_TYPE_PPCS(2)`).
pub const P2P_TYPE_PPCS: i32 = 2;

/// Which streaming transport the camera advertises, decoded from the cloud
/// `p2pType` integer (`re/streaming_mode.md`; enum
/// `ThingCameraConstants.P2PType`).
///
/// The choice is **data-driven per device** — the cloud sets `p2pType`, the
/// client does not. `4` (THING/WebRTC-over-MQTT) is preferred on the SCD921;
/// `2` (PPCS) is the legacy fallback. Any other integer is surfaced as
/// [`P2pTransport::Other`] rather than silently coerced, so an unexpected value
/// fails loud at the call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum P2pTransport {
    /// Legacy TUTK/IOTC PPCS (`p2pType == 2`).
    Ppcs,
    /// Tuya's own RTC, WebRTC-over-MQTT (`p2pType == 4`) — preferred here.
    ThingWebRtc,
    /// An unrecognized `p2pType` value, carried verbatim for honest reporting.
    Other(i32),
}

impl P2pTransport {
    /// Decode a raw `p2pType` integer into a [`P2pTransport`].
    #[must_use]
    pub fn from_p2p_type(p2p_type: i32) -> Self {
        match p2p_type {
            P2P_TYPE_PPCS => Self::Ppcs,
            P2P_TYPE_THING_WEBRTC => Self::ThingWebRtc,
            other => Self::Other(other),
        }
    }

    /// The raw `p2pType` integer this transport corresponds to.
    #[must_use]
    pub fn as_p2p_type(self) -> i32 {
        match self {
            Self::Ppcs => P2P_TYPE_PPCS,
            Self::ThingWebRtc => P2P_TYPE_THING_WEBRTC,
            Self::Other(v) => v,
        }
    }

    /// Whether this is the WebRTC-over-MQTT path (the Wave-2 preferred transport).
    #[must_use]
    pub fn is_webrtc(self) -> bool {
        matches!(self, Self::ThingWebRtc)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Debug redaction helper (consistent with sign.rs / session.rs)
// ─────────────────────────────────────────────────────────────────────────────

/// Render an `Option<String>` secret for `Debug` without leaking its value:
/// `Some(len=N)` redacted, or `None`. Mirrors the redaction style in
/// `sign::SigningKeyMaterial` / `session::Session`.
fn dbg_opt_secret(v: &Option<String>) -> String {
    match v {
        Some(s) => format!("<redacted len={}>", s.len()),
        None => "None".to_string(),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Device-list container + DeviceBean
// ─────────────────────────────────────────────────────────────────────────────

/// The parsed device list: the `deviceList` (+ `sharedDeviceList`) carried by a
/// Tuya `HomeBean` home-detail response (`re/tuya_cloud_auth.md` §5a,
/// `HomeBean.deviceList`/`getSharedDeviceList`).
///
/// We model the container directly as the two lists the home-detail returns;
/// the caller selects the camera via [`DeviceList::find_camera`]. Both lists
/// default to empty so a home with no shared devices parses cleanly.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DeviceList {
    /// Devices owned in this home (`HomeBean.deviceList`).
    #[serde(rename = "deviceList", default)]
    pub device_list: Vec<DeviceBean>,
    /// Devices shared INTO this home (`HomeBean.sharedDeviceList`).
    #[serde(rename = "sharedDeviceList", default)]
    pub shared_device_list: Vec<DeviceBean>,
}

impl DeviceList {
    /// Iterate over owned + shared devices (a single source of truth — no
    /// duplicated/merged stored vec; the view is computed on demand).
    pub fn all_devices(&self) -> impl Iterator<Item = &DeviceBean> {
        self.device_list
            .iter()
            .chain(self.shared_device_list.iter())
    }

    /// Find the first camera (`sp`/ipc family) device and return a typed
    /// [`CameraView`] over it paired with its [`CameraInfoBean`] P2P record.
    ///
    /// The per-camera P2P record (`CameraInfoBean`) is fetched SEPARATELY from
    /// the device list (`re/tuya_cloud_auth.md` §5c), so the caller must supply
    /// the parsed [`CameraInfoBean`] for the matched `devId`. This keeps the two
    /// concerns composable: list parsing here, the per-device config fetch at
    /// the integration site.
    ///
    /// Returns `None` if no camera-category device is present.
    #[must_use]
    pub fn find_camera_device(&self) -> Option<&DeviceBean> {
        self.all_devices().find(|d| d.is_camera())
    }
}

/// A single device record from the device list (`re/tuya_cloud_auth.md` §5b,
/// `DeviceBean`). Field names follow the atop camelCase wire shape.
///
/// `dev_id` is REQUIRED (non-Option): it is the P2P/MQTT addressing key and the
/// join key to the per-camera [`CameraInfoBean`]; a record without it is
/// meaningless and is rejected. All other fields are optional because the real
/// atop API omits many per account/firmware.
#[derive(Clone, Deserialize, Serialize)]
pub struct DeviceBean {
    /// Device id — the P2P/MQTT addressing key (`DeviceBean.devId`). REQUIRED.
    /// Not a crypto secret, but a real value is account-linked PII (anonymize).
    #[serde(rename = "devId")]
    pub dev_id: String,
    /// Display name (`DeviceBean.name`). May be PII.
    #[serde(default)]
    pub name: Option<String>,
    /// Per-device AES local key (`DeviceBean.localKey`). **SECRET** (LAN proto /
    /// DP decrypt). Redacted in `Debug`.
    #[serde(rename = "localKey", default)]
    pub local_key: Option<String>,
    /// Secondary key material (`DeviceBean.secKey`). **SECRET**. Redacted.
    #[serde(rename = "secKey", default)]
    pub sec_key: Option<String>,
    /// Device uuid (`DeviceBean.uuid`). Anonymize (not a crypto secret).
    #[serde(default)]
    pub uuid: Option<String>,
    /// Protocol version (`DeviceBean.pv`).
    #[serde(default)]
    pub pv: Option<String>,
    /// Product/profile id (`DeviceBean.productId`).
    #[serde(rename = "productId", default)]
    pub product_id: Option<String>,
    /// Device category — camera is the `sp`/ipc family (`DeviceBean.category`).
    ///
    /// The wire carries this as `category` AND a sibling `categoryCode`
    /// (`re/tuya_cloud_auth.md` §5b lists `category`/`categoryCode` together as
    /// the device-category field). We accept either key into this one field via
    /// the serde alias so a record that populates only `categoryCode` does not
    /// silently miss [`is_camera`](DeviceBean::is_camera). Which key the real atop
    /// response populates is `needs-live` (not observed against a real capture);
    /// accepting both is the safe static choice.
    #[serde(default, alias = "categoryCode")]
    pub category: Option<String>,
    /// Cloud online state (`DeviceBean.isOnline`).
    #[serde(rename = "isOnline", default)]
    pub is_online: Option<bool>,
    /// LAN online state (`DeviceBean.isLocalOnline`).
    #[serde(rename = "isLocalOnline", default)]
    pub is_local_online: Option<bool>,
    /// Device capability skill map (`DeviceBean.skills`). Opaque JSON values.
    #[serde(default)]
    pub skills: BTreeMap<String, Value>,
}

impl DeviceBean {
    /// Tuya category code for the IPC/camera family (`sp`).
    /// (`re/tuya_cloud_auth.md` §5b: "camera = `sp`/ipc family".)
    pub const CATEGORY_CAMERA: &'static str = "sp";

    /// Whether this device is a camera. A device with no category is
    /// conservatively NOT treated as a camera.
    ///
    /// `sp` is the grounded camera category (`re/tuya_cloud_auth.md` §5b). The
    /// `"ipc"` arm is **(inferred)** — it is the common Tuya IPC-family shorthand
    /// but is NOT grounded by a citation here; it is kept as a lenient extra match
    /// so a future capture using it still resolves, and should be confirmed (or
    /// dropped) against a real device-list capture (needs-live).
    #[must_use]
    pub fn is_camera(&self) -> bool {
        matches!(self.category.as_deref(), Some(c) if c == Self::CATEGORY_CAMERA || c == "ipc")
    }

    /// Online if either the cloud or LAN online flag is set true.
    #[must_use]
    pub fn online(&self) -> bool {
        self.is_online.unwrap_or(false) || self.is_local_online.unwrap_or(false)
    }
}

impl std::fmt::Debug for DeviceBean {
    /// Redacts `local_key`/`sec_key`; never leaks them via `{:?}`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceBean")
            .field("dev_id", &self.dev_id)
            .field("name", &self.name)
            .field("local_key", &dbg_opt_secret(&self.local_key))
            .field("sec_key", &dbg_opt_secret(&self.sec_key))
            .field("uuid", &self.uuid)
            .field("pv", &self.pv)
            .field("product_id", &self.product_id)
            .field("category", &self.category)
            .field("is_online", &self.is_online)
            .field("is_local_online", &self.is_local_online)
            .field("skills", &self.skills)
            .finish()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CameraInfoBean + nested P2pConfig (the per-camera P2P/WebRTC record)
// ─────────────────────────────────────────────────────────────────────────────

/// The per-camera P2P/WebRTC config record (`re/tuya_cloud_auth.md` §5c,
/// `CameraInfoBean`), fetched per `devId` separately from the device list.
///
/// `p2p_id` and `p2p_type` are REQUIRED (non-Option): `p2p_id` is the P2P device
/// handle (IOTC UID) — the load-bearing credential handle — and `p2p_type` is
/// the transport selector. A record missing either is rejected, so this is not a
/// permissive sponge.
#[derive(Clone, Deserialize, Serialize)]
pub struct CameraInfoBean {
    /// Camera/session id (`CameraInfoBean.id`). Anonymize.
    #[serde(default)]
    pub id: Option<String>,
    /// The P2P device handle / IOTC UID (`CameraInfoBean.p2pId`). REQUIRED —
    /// the load-bearing P2P credential handle. Per-device sensitive.
    #[serde(rename = "p2pId")]
    pub p2p_id: String,
    /// P2P transport type (`p2pType`, on the wire — see module docs). REQUIRED
    /// transport selector. Decode with [`P2pTransport::from_p2p_type`] via
    /// [`CameraInfoBean::transport`].
    #[serde(rename = "p2pType")]
    pub p2p_type: i32,
    /// Specified P2P type (`CameraInfoBean.p2pSpecifiedType`).
    #[serde(rename = "p2pSpecifiedType", default)]
    pub p2p_specified_type: Option<i32>,
    /// P2P policy selector (`CameraInfoBean.p2pPolicy`).
    #[serde(rename = "p2pPolicy", default)]
    pub p2p_policy: Option<i32>,
    /// P2P session password (`CameraInfoBean.password`). **SECRET**. Redacted.
    #[serde(default)]
    pub password: Option<String>,
    /// Session ticket id (`CameraInfoBean.sessionTid`). **SECRET**. Redacted.
    #[serde(rename = "sessionTid", default)]
    pub session_tid: Option<String>,
    /// Capability manifest as a raw JSON string (`CameraInfoBean.skill`):
    /// `videos[]`/`audios[]`/`p2p`/`webrtc`/`localStorage`/`sdk_version`/… We
    /// keep it as the raw string the wire carries (Tuya double-encodes it as a
    /// JSON string); parsing it is a later concern, kept out of this model.
    #[serde(default)]
    pub skill: Option<String>,
    /// Negotiated media skill (`CameraInfoBean.mediaConsumerSkill`).
    #[serde(rename = "mediaConsumerSkill", default)]
    pub media_consumer_skill: Option<String>,
    /// Nested WebRTC/P2P credential handles (`CameraInfoBean.p2pConfig`).
    #[serde(rename = "p2pConfig", default)]
    pub p2p_config: Option<P2pConfig>,
}

impl CameraInfoBean {
    /// Decode the transport selector from `p2p_type`.
    #[must_use]
    pub fn transport(&self) -> P2pTransport {
        P2pTransport::from_p2p_type(self.p2p_type)
    }
}

impl std::fmt::Debug for CameraInfoBean {
    /// Redacts `password`/`session_tid`; never leaks them via `{:?}`. The nested
    /// `P2pConfig` redacts its own secrets.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CameraInfoBean")
            .field("id", &self.id)
            .field("p2p_id", &self.p2p_id)
            .field("p2p_type", &self.p2p_type)
            .field("p2p_specified_type", &self.p2p_specified_type)
            .field("p2p_policy", &self.p2p_policy)
            .field("password", &dbg_opt_secret(&self.password))
            .field("session_tid", &dbg_opt_secret(&self.session_tid))
            .field("skill", &self.skill)
            .field("media_consumer_skill", &self.media_consumer_skill)
            .field("p2p_config", &self.p2p_config)
            .finish()
    }
}

/// The nested WebRTC/P2P credential handles
/// (`re/tuya_cloud_auth.md` §5c, `CameraInfoBean.P2pConfig`).
///
/// All fields are optional because the cloud populates them per transport (a
/// PPCS device may omit the WebRTC `ices`/`session`; a WebRTC device may omit
/// relay descriptors). `p2p_key`/`init_str`/`session` are **secret** and
/// redacted in `Debug`. The relay/ICE descriptors are kept as raw JSON
/// ([`serde_json::Value`]) because their inner shape is not yet recovered
/// statically (honest: see module docs).
#[derive(Clone, Deserialize, Serialize, Default)]
pub struct P2pConfig {
    /// P2P session key (`P2pConfig.p2pKey`). **SECRET**. Redacted.
    #[serde(rename = "p2pKey", default)]
    pub p2p_key: Option<String>,
    /// P2P init string (`P2pConfig.initStr`; consumed as `lnInitStr + "/" +
    /// lnKeyStr`). **SECRET**. Redacted.
    #[serde(rename = "initStr", default)]
    pub init_str: Option<String>,
    /// ICE server list (`P2pConfig.ices`) — WebRTC. Raw JSON; endpoints are
    /// sensitive (inner shape not yet recovered statically).
    #[serde(default)]
    pub ices: Option<Value>,
    /// Session descriptor (`P2pConfig.session`). **SECRET** (the session
    /// JSONObject read by `ThingSmartCameraP2PSync`). Raw JSON, redacted.
    #[serde(default)]
    pub session: Option<Value>,
    /// TCP TURN/relay descriptor (`P2pConfig.tcpRelay`). Sensitive endpoints.
    #[serde(rename = "tcpRelay", default)]
    pub tcp_relay: Option<Value>,
    /// UDP TURN/relay descriptor (`P2pConfig.udpRelay`). Sensitive endpoints.
    #[serde(rename = "udpRelay", default)]
    pub udp_relay: Option<Value>,
}

impl std::fmt::Debug for P2pConfig {
    /// Redacts `p2p_key`/`init_str`/`session`; never leaks them via `{:?}`. The
    /// `ices`/`tcpRelay`/`udpRelay` descriptors carry endpoints (sensitive) so
    /// we report only their presence, not their contents.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fn present(v: &Option<Value>) -> &'static str {
            if v.is_some() {
                "<present, redacted>"
            } else {
                "None"
            }
        }
        f.debug_struct("P2pConfig")
            .field("p2p_key", &dbg_opt_secret(&self.p2p_key))
            .field("init_str", &dbg_opt_secret(&self.init_str))
            .field("ices", &present(&self.ices))
            .field("session", &present(&self.session))
            .field("tcp_relay", &present(&self.tcp_relay))
            .field("udp_relay", &present(&self.udp_relay))
            .finish()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Typed accessor: a camera view over (DeviceBean, CameraInfoBean)
// ─────────────────────────────────────────────────────────────────────────────

/// A read-only view that pairs a camera [`DeviceBean`] (from the device list)
/// with its [`CameraInfoBean`] (the per-device P2P record) and exposes exactly
/// the handles a transport needs to connect: `dev_id`, online state, the
/// selected [`P2pTransport`], and the P2P/WebRTC credential handles.
///
/// This is the composition seam: the device list and the per-camera config are
/// fetched separately, and the caller pairs them here. Borrowing (no owned copy)
/// keeps the secrets' lifetime owned by the caller — consistent with the
/// signer's injected-borrow design.
#[derive(Debug, Clone, Copy)]
pub struct CameraView<'a> {
    /// The camera device record.
    pub device: &'a DeviceBean,
    /// The per-camera P2P/WebRTC config record.
    pub info: &'a CameraInfoBean,
}

impl<'a> CameraView<'a> {
    /// Pair a [`DeviceBean`] with its [`CameraInfoBean`].
    ///
    /// This validates ONLY that `device` is a camera-category device
    /// ([`DeviceBean::is_camera`]); it does not (and cannot, statically) confirm
    /// that `info` actually belongs to `device`. Whether
    /// [`CameraInfoBean::id`] equals [`DeviceBean::dev_id`] for the same camera is
    /// **unconfirmed** (needs-live: the per-camera config fetch is keyed by
    /// `devId`, but the response `id` field's relationship to it has not been
    /// observed against a real device). The caller is responsible for fetching
    /// `info` for the matched `devId`.
    ///
    /// # Errors
    /// [`Error::DeviceMismatch`] if `device` is not a camera-category device — we
    /// fail loud rather than build a camera view over a non-camera record.
    pub fn pair(device: &'a DeviceBean, info: &'a CameraInfoBean) -> Result<Self, Error> {
        if !device.is_camera() {
            return Err(Error::DeviceMismatch(format!(
                "device {} is not a camera (category={:?})",
                device.dev_id, device.category
            )));
        }
        Ok(Self { device, info })
    }

    /// The device id (the P2P/MQTT addressing key). PII — do not print by default.
    #[must_use]
    pub fn dev_id(&self) -> &str {
        &self.device.dev_id
    }

    /// Whether the camera is online (cloud or LAN).
    #[must_use]
    pub fn online(&self) -> bool {
        self.device.online()
    }

    /// The selected transport (decoded from `p2pType`).
    #[must_use]
    pub fn transport(&self) -> P2pTransport {
        self.info.transport()
    }

    /// The P2P device handle (IOTC UID). Sensitive — do not print by default.
    #[must_use]
    pub fn p2p_id(&self) -> &str {
        &self.info.p2p_id
    }

    /// The nested WebRTC/P2P credential handles, if present.
    #[must_use]
    pub fn p2p_config(&self) -> Option<&P2pConfig> {
        self.info.p2p_config.as_ref()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// List service (offline-injectable parse + token-pending fetch shape)
// ─────────────────────────────────────────────────────────────────────────────

/// Parse a device-list response **body** into the typed [`DeviceList`].
///
/// This is the offline-injectable seam: hand it the bytes of a home-detail
/// response and it deserializes + enforces the required invariants (a record
/// missing `devId` is rejected by serde). No network is touched.
///
/// # Errors
/// [`Error::DeviceParse`] if the body is not valid JSON or does not match the
/// [`DeviceList`] shape (e.g. a device record missing the required `devId`).
pub fn parse_device_list(body: &[u8]) -> Result<DeviceList, Error> {
    serde_json::from_slice(body).map_err(|e| Error::DeviceParse(e.to_string()))
}

/// Parse a per-camera [`CameraInfoBean`] response **body**.
///
/// # Errors
/// [`Error::DeviceParse`] if the body is not valid JSON or is missing a required
/// invariant (`p2pId` / `p2pType`).
pub fn parse_camera_info(body: &[u8]) -> Result<CameraInfoBean, Error> {
    serde_json::from_slice(body).map_err(|e| Error::DeviceParse(e.to_string()))
}

/// The shape a real `list_devices` fetch would take: given injected signing key
/// material, a token provider, a session, and a home id, it would build a signed
/// home-detail request, POST it, and [`parse_device_list`] the response.
///
/// **No live call is made in this core crate.** The home-detail call needs an
/// authenticated session and a live HTTP transport, both supplied by the CLI live
/// layer. This function threads signer and session inputs through and returns
/// [`Error::BmpTokenPending`] when callers still supply the pending signer —
/// exactly the TASK-0012 discipline. Either way the request-decoration wiring
/// stays real and reviewable without fabricating a response or hitting the
/// network. The real HTTP path runs in the CLI live layer when an authenticated
/// session is injected or created by a validated live login.
///
/// `_material`/`_token_provider`/`_session_sid`/`_home_id` are accepted now so
/// the call signature is stable for callers (the CLI, TASK-0014) — they are
/// borrowed, never re-read from `secrets/` per call.
///
/// # Errors
/// [`Error::BmpTokenPending`] while signing is unavailable (the current state).
pub fn list_devices<P: BmpTokenProvider>(
    _material: &SigningKeyMaterial,
    token_provider: &P,
    _session_sid: &str,
    _home_id: &str,
) -> Result<DeviceList, Error> {
    // The core crate has no live HTTP transport. On top of that, a caller using
    // the pending signer cannot produce a signature: probe that dependency here,
    // and if it is pending we cannot sign, so we cannot make the request. Surface
    // that honestly rather than touching the network or returning an empty list.
    token_provider.bmp_token()?;
    // Even if a token became available, the core crate still has no live HTTP path
    // or session source. Those live concerns are owned by the CLI `live` feature.
    Err(Error::NotImplemented(
        "list_devices live HTTP fetch (signer unblocked but fetch not wired \
         yet — follow-up task)",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign::{PendingBmpToken, StaticBmpToken};

    // ── Transport mapping ──────────────────────────────────────────────────
    #[test]
    fn transport_maps_known_p2p_types() {
        assert_eq!(P2pTransport::from_p2p_type(2), P2pTransport::Ppcs);
        assert_eq!(P2pTransport::from_p2p_type(4), P2pTransport::ThingWebRtc);
        assert!(P2pTransport::from_p2p_type(4).is_webrtc());
        assert!(!P2pTransport::from_p2p_type(2).is_webrtc());
        // Round-trips back to the integer.
        assert_eq!(P2pTransport::Ppcs.as_p2p_type(), 2);
        assert_eq!(P2pTransport::ThingWebRtc.as_p2p_type(), 4);
    }

    // NEGATIVE: an unknown p2pType is surfaced, not silently coerced to a known
    // transport (prove the Other arm bites).
    #[test]
    fn transport_surfaces_unknown_p2p_type() {
        let t = P2pTransport::from_p2p_type(99);
        assert_eq!(t, P2pTransport::Other(99));
        assert!(!t.is_webrtc());
        assert_eq!(t.as_p2p_type(), 99);
    }

    // ── category / categoryCode alias ──────────────────────────────────────
    //
    // The wire may populate `categoryCode` instead of `category` (§5b). The serde
    // alias must route either into `category` so find_camera_device cannot
    // silently miss the camera. Prove the alias path bites.
    #[test]
    fn category_code_alias_populates_camera_category() {
        let body = br#"{"deviceList":[{"devId":"d1","categoryCode":"sp"}]}"#;
        let list = parse_device_list(body).unwrap();
        let cam = list
            .find_camera_device()
            .expect("a categoryCode=sp device must be found as a camera");
        assert_eq!(cam.dev_id, "d1");
        assert!(cam.is_camera());
        assert_eq!(cam.category.as_deref(), Some("sp"));
    }

    // NEGATIVE: a non-camera categoryCode is not mistaken for a camera (prove the
    // alias does not over-match).
    #[test]
    fn category_code_alias_non_camera_is_not_camera() {
        let body = br#"{"deviceList":[{"devId":"d1","categoryCode":"cz"}]}"#;
        let list = parse_device_list(body).unwrap();
        assert!(list.find_camera_device().is_none());
    }

    // ── list_devices service: TOKEN-PENDING discipline ─────────────────────
    fn synth_material() -> SigningKeyMaterial {
        // SYNTHETIC values only — never a real secret.
        SigningKeyMaterial {
            app_key: "SYNTH_APPKEY_000000".into(),
            app_secret: "SYNTH_APPSECRET_0000000000000000".into(),
            app_cert_sha256_hex: "00".repeat(32),
            ttid: "SYNTH_TTID".into(),
        }
    }

    // With the default pending token provider, list_devices must NOT touch the
    // network and must surface the honest pending state — the same discipline as
    // the signer. (The deeper reason the fetch is unreachable is the absent
    // authenticated session / identity gate, TASK-0050/0051; the concrete variant
    // here is BmpTokenPending because the signer's un-validated 6th ingredient,
    // the bmp_token — TASK-0032 — is its first stop.)
    #[test]
    fn list_devices_is_token_pending_without_token() {
        let material = synth_material();
        let result = list_devices(&material, &PendingBmpToken, "SYNTH_SID", "SYNTH_HOME");
        assert!(
            matches!(result, Err(Error::BmpTokenPending)),
            "without a bmp_token list_devices MUST report pending, not fetch"
        );
    }

    // Even with a (synthetic) token available, the LIVE HTTP fetch is not wired
    // in this task — that is honestly surfaced as NotImplemented, never a
    // fabricated/empty list. This proves we did not silently stub the happy path.
    #[test]
    fn list_devices_fetch_not_wired_even_with_token() {
        let material = synth_material();
        let token = StaticBmpToken::new("SYNTH_PLACEHOLDER_TOKEN");
        let result = list_devices(&material, &token, "SYNTH_SID", "SYNTH_HOME");
        assert!(
            matches!(result, Err(Error::NotImplemented(_))),
            "live fetch is not wired yet; must surface NotImplemented, not Ok"
        );
    }
}
