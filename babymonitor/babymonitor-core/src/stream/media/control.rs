//! The **conv=0 imm control channel**: the client-initiated KCP control PDUs that
//! make the SCD921 begin streaming after ICE validates (`re/media_start_handshake.md`,
//! TASK-0083).
//!
//! # Why this exists
//! After ICE validates (the camera answers our plain connectivity check), the
//! camera still does **not** stream until the *client* sends KCP control packets
//! first. cap4's working flow proves it: the app sends three conv=0 KCP PUSH
//! segments (capture frames 253–255), each carrying a 28-byte `imm` control PDU,
//! and the camera begins streaming ~37 ms later (frame 256, then conv=1 video at
//! 259). Our client did ICE then only *received* → camera-silent media. Replaying
//! these PDUs is the fix.
//!
//! # The `imm` control PDU (`SendCommand`)
//! Little-endian, decrypted from cap4 (key#0, HMAC-confirmed —
//! `re/media_start_handshake.md` §"The 28-byte imm control PDU"). Each conv=0
//! control PDU is a `ThingNetProtocolManager::SendCommand(reqId, high_cmd,
//! low_cmd, payload)` struct: a 20-byte header (`@0..@0x14`) followed by the
//! payload. Field layout, **corrected** against the decompile
//! (`decompiled/ghidra_camera/funcs/funcs/002c5e54_SendCommand.c:44-52`):
//!
//! ```text
//! @0    u32   magic     = 0x12345678         (constant imm marker; line 45)
//! @4    u32   reqId     = param_1            (request id; line 46 — see note)
//! @8    u32   direction                      (0 = app→camera command,
//!                                             1 = camera→app response — the low
//!                                             word of the @0xe0 store; 0 here)
//! @0xc  u32   command   = (low_cmd<<16)|high_cmd   (the real command id; line 52)
//! @0x10 u32   payload length                 (= 8 for the three 28-byte PDUs; line 51)
//! @0x14 u8[]  payload                         (`payload length` bytes)
//! ```
//!
//! So the three 28-byte cap4 PDUs are the commands `command = 9` (hi9,lo0),
//! `6` (hi6,lo0, "open video"), and `0x00040006` (hi6,lo4) — each with an
//! 8-byte payload — and the 24-byte [`MEDIA_START_VERSION_PDU`] is
//! `command = 0x0A` (hi10,lo0) with a 4-byte payload.
//!
//! **Confidence on `@4`: MEDIUM.** `SendCommand` (line 46) writes the monotonic
//! `m_nCommandReqId++` counter here, so `@4` is the per-command request id — NOT
//! the "type" the earlier doc called it (which also wrongly split the `@0xc`
//! command into two unrelated `@12`/`@24` fields). Caveat we do not fully explain:
//! the captured `@4` values are `0x00010004 / 0x00010003 / 0x00010005` — a constant
//! high word `0x0001` with low words `4, 3, 5` in send order f253→f254→f255, i.e.
//! **not** monotonically increasing (the counter base is `0x00010000`, but the 3→4→5
//! ordering vs the 4,3,5 captured values is unexplained — possibly a separate
//! response/request pairing the camera does not validate). We replay the captured
//! values verbatim; the camera streamed video regardless (live-validated), so `@4`
//! is not gating. The wire bytes below are the ground truth, not this field label.
//!
//! These are **protocol constants / small codes — NO session tokens, no creds**
//! (`re/media_start_handshake.md` §"The 28-byte imm control PDU"), so they are
//! replayable verbatim in a fresh session (the AES/HMAC that seal them on the wire
//! use the new session's `a=aes-key`; the *plaintext* PDU is the same). They are
//! reproduced here as exact byte templates — the literals are the ground truth; the
//! [`build_media_start_pdu`] builder only documents the field structure and is
//! cross-checked against the literals in tests.

/// The conv (KCP channel id) the media-start control PDUs ride on (cap4: the app's
/// conv=0 send stream). Demuxed away from the video (`1`) / audio (`2`) media convs.
pub const MEDIA_START_CONV: u32 = 0;

/// The constant `imm` control marker at PDU offset 0 (little-endian `u32`).
pub const MEDIA_START_MAGIC: u32 = 0x1234_5678;

/// Length of one `imm` control PDU, in bytes.
pub const MEDIA_START_PDU_LEN: usize = 28;

/// PDU **A** — cap4 frame 253 (`78563412 04000100 00000000 09000000 08000000
/// 00000000 04000000`), the verbatim decrypted plaintext.
pub const PDU_F253: [u8; MEDIA_START_PDU_LEN] = [
    0x78, 0x56, 0x34, 0x12, // @0    magic 0x12345678
    0x04, 0x00, 0x01, 0x00, // @4    reqId 0x00010004
    0x00, 0x00, 0x00, 0x00, // @8    direction 0
    0x09, 0x00, 0x00, 0x00, // @0xc  command 9
    0x08, 0x00, 0x00, 0x00, // @0x10 payload len 8
    0x00, 0x00, 0x00, 0x00, // @0x14 payload[0..4]
    0x04, 0x00, 0x00, 0x00, // @0x18 payload[4..8]
];

/// PDU **B** — cap4 frame 254 (`78563412 03000100 00000000 06000000 08000000
/// 00000000 00000000`), the verbatim decrypted plaintext.
pub const PDU_F254: [u8; MEDIA_START_PDU_LEN] = [
    0x78, 0x56, 0x34, 0x12, // @0    magic 0x12345678
    0x03, 0x00, 0x01, 0x00, // @4    reqId 0x00010003
    0x00, 0x00, 0x00, 0x00, // @8    direction 0
    0x06, 0x00, 0x00, 0x00, // @0xc  command 6 ("open video")
    0x08, 0x00, 0x00, 0x00, // @0x10 payload len 8
    0x00, 0x00, 0x00, 0x00, // @0x14 payload[0..4]
    0x00, 0x00, 0x00, 0x00, // @0x18 payload[4..8]
];

/// PDU **C** — cap4 frame 255 (`78563412 05000100 00000000 06000400 08000000
/// 00000000 04000000`), the verbatim decrypted plaintext.
pub const PDU_F255: [u8; MEDIA_START_PDU_LEN] = [
    0x78, 0x56, 0x34, 0x12, // @0    magic 0x12345678
    0x05, 0x00, 0x01, 0x00, // @4    reqId 0x00010005
    0x00, 0x00, 0x00, 0x00, // @8    direction 0
    0x06, 0x00, 0x04, 0x00, // @0xc  command 0x00040006 (hi6,lo4)
    0x08, 0x00, 0x00, 0x00, // @0x10 payload len 8
    0x00, 0x00, 0x00, 0x00, // @0x14 payload[0..4]
    0x04, 0x00, 0x00, 0x00, // @0x18 payload[4..8]
];

/// The three media-start control PDUs, in the exact send order the cap4 app used
/// (frames 253 → 254 → 255). Replayed verbatim as KCP PUSH payloads on
/// [`MEDIA_START_CONV`]. **Ground truth** (`re/media_start_handshake.md`).
pub const MEDIA_START_PDUS: [[u8; MEDIA_START_PDU_LEN]; 3] = [PDU_F253, PDU_F254, PDU_F255];

/// The conv=0 **VERSION** control PDU — a 24-byte `SendCommand(reqId=0,
/// high_cmd=10, low_cmd=0, payload=0x00010000)` the app emits at KCP **sn=1**,
/// directly after the AUTH PDU. It is the tail of `SendAuthorizationInfo`, which
/// allocates a 4-byte `0x00010000` payload vector and frames it as a command:
/// `SendCommand(this,0,10,0,{0x00010000})`
/// (`decompiled/ghidra_camera/funcs/funcs/002c8028_SendAuthorizationInfo.c:83-89`
/// builds the payload; `…/002c5e54_SendCommand.c:44-52` builds the struct). A
/// 20-byte header — magic / reqId=0 / direction=0 / command=0x0A=(low0<<16)|high10
/// / payload-len=4 — plus the 4-byte little-endian payload `0x00010000`. Replayable
/// verbatim (protocol constants only — NO session tokens, no creds).
pub const MEDIA_START_VERSION_PDU: [u8; 24] = [
    0x78, 0x56, 0x34, 0x12, // @0    magic 0x12345678
    0x00, 0x00, 0x00, 0x00, // @4    reqId = 0
    0x00, 0x00, 0x00, 0x00, // @8    direction = 0 (app→camera command)
    0x0A, 0x00, 0x00, 0x00, // @0xc  command = 0x0A = (low0<<16)|high10
    0x04, 0x00, 0x00, 0x00, // @0x10 payload length = 4
    0x00, 0x00, 0x01, 0x00, // @0x14 payload = 0x00010000 (LE)
];

// ── The conv=0 media-start AUTH PDU (`SendAuthorizationInfo`, sn=0) ──────────
//
// The 104-byte `imm` authorization control message the app sends FIRST on conv=0
// (KCP sn=0), before the three [`MEDIA_START_PDUS`] continuation PDUs. Ground
// truth: `ThingSmartP2PSDK::SendAuthorizationInfo`
// (`decompiled/ghidra_p2p/funcs/00147608_SendAuthorizationInfo.c`) builds a
// 0x68 (=104)-byte little-endian struct and hands it to `imm_p2p_rtc_send_data`:
//
// ```text
// @0    u32  magic    = 0x12345678   (local_c0)
// @4    i32  code     = param_3      (iStack_bc; 0 on the media-start path)
// @8    char[31]      = username     (strncpy(local_b8, param_4, 0x1f), NUL-padded)
// @0x27 u8            = 0            (the NUL separator after the 31-byte username)
// @0x28 char[63]      = password     (strncpy(local_b8+0x20, param_5, 0x3f), NUL-padded)
// ```
//
// (`re/media_start_handshake.md`; smali `pbbppqb.j()` → `getString("password")`.)
// `username` is the hardcoded constant `"admin"`; `password` is the camera-info
// `password` field (`rtc.config result.password`). It is sealed identically to the
// 28-byte PDUs (PKCS#7-pad 104→112 → AES-128-CBC seal → conv=0 KCP PUSH + HMAC).

/// The constant `imm` marker at AUTH PDU offset 0 (little-endian `u32`; same value
/// as the 28-byte control PDUs' [`MEDIA_START_MAGIC`]).
pub const MEDIA_START_AUTH_MAGIC: u32 = 0x1234_5678;

/// The `code` field (@4) of the AUTH PDU on the media-start path. `SendAuthorizationInfo`'s
/// `param_3`; `0` for the media-start authorization.
pub const MEDIA_START_AUTH_CODE: i32 = 0;

/// The hardcoded `username` (@8) of the AUTH PDU (`SendAuthorizationInfo` `param_4`).
pub const MEDIA_START_AUTH_USERNAME: &str = "admin";

/// Length of the AUTH PDU, in bytes (`0x68` — the `imm_p2p_rtc_send_data` length arg).
pub const MEDIA_START_AUTH_PDU_LEN: usize = 104;

/// Byte offset of the `username` field within the AUTH PDU.
const AUTH_USERNAME_OFF: usize = 8;
/// Max `username` length (the `strncpy(.., 0x1f)` cap; one byte short of the
/// 32-byte slot so the @0x27 NUL separator is always present).
const AUTH_USERNAME_MAX: usize = 0x1f;
/// Byte offset of the `password` field within the AUTH PDU (`local_b8 + 0x20`).
const AUTH_PASSWORD_OFF: usize = 0x28;
/// Max `password` length (the `strncpy(.., 0x3f)` cap).
const AUTH_PASSWORD_MAX: usize = 0x3f;

/// Build the 104-byte conv=0 media-start AUTH PDU (`SendAuthorizationInfo`).
///
/// Zero-fills the 104-byte buffer (so every unused byte — including the @0x27
/// username/password separator and all NUL padding — is `0`, matching the native
/// `local_b8[..] = '\0'` clears), then writes: the `0x12345678` magic LE @0, `code`
/// LE @4, up to 31 `username` bytes @8 (`strncpy(.., 0x1f)`), and up to 63
/// `password` bytes @0x28 (`strncpy(.., 0x3f)`). `username`/`password` longer than
/// their slots are truncated exactly as `strncpy` truncates (no NUL terminator is
/// then written, but the next field's offset is fixed, so this matches the native
/// struct layout).
#[must_use]
pub fn build_auth_pdu(code: i32, username: &str, password: &str) -> [u8; MEDIA_START_AUTH_PDU_LEN] {
    let mut p = [0u8; MEDIA_START_AUTH_PDU_LEN];
    p[0..4].copy_from_slice(&MEDIA_START_AUTH_MAGIC.to_le_bytes());
    p[4..8].copy_from_slice(&code.to_le_bytes());

    let u = username.as_bytes();
    let un = u.len().min(AUTH_USERNAME_MAX);
    p[AUTH_USERNAME_OFF..AUTH_USERNAME_OFF + un].copy_from_slice(&u[..un]);

    let pw = password.as_bytes();
    let pn = pw.len().min(AUTH_PASSWORD_MAX);
    p[AUTH_PASSWORD_OFF..AUTH_PASSWORD_OFF + pn].copy_from_slice(&pw[..pn]);
    p
}

/// Derive the conv=0 media-start AUTH **password** from the camera-info `password`
/// and the device `localKey`.
///
/// The raw 8-char `rtc.config result.password` is **not** what the app puts in the
/// AUTH PDU. The real client salts it with the device `localKey` and MD5-hashes the
/// pair before connecting. jadx ground truth
/// (`decompiled/jadx/sources/com/thingclips/smart/camera/ipccamerasdk/IPCThingP2PCamera.java`):
///
/// ```text
/// 6874: String password = this.mBean.getPassword();   // 8-char rtc.config password
/// 6875: this.mLocalkey = this.mBean.getLocalKey();     // device localKey
/// 6881: this.mPwd = MD5Utils.b(password + com.thingclips.sdk.mqtt.pbbppqb.pbpdbqp + this.mLocalkey);
/// 6975: this.thingCamera.connect("admin", this.mPwd, ...);   // username "admin", password = mPwd
/// ```
///
/// - The separator constant `pbbppqb.pbpdbqp = "||"`
///   (`com/thingclips/sdk/mqtt/pbbppqb.java:26`).
/// - `MD5Utils` is `com.thingclips.smart.camera.utils.chaos.MD5Utils`:
///   `b(s) = HexUtil.a(MD5(s.getBytes()))` → a **lowercase** 32-char hex string
///   (Tuya's `HexUtil` emits lowercase across their SDKs).
///
/// So the wire password is:
///
/// ```text
/// auth_password = md5_hex_lower( utf8(password) ++ "||" ++ utf8(localKey) )   // 32 ASCII hex chars
/// ```
///
/// and the username stays the constant [`MEDIA_START_AUTH_USERNAME`] (`"admin"`).
/// The resulting 32-char hex fits the C++ `password@0x28` slot (max `0x3f`) in
/// [`build_auth_pdu`] without truncation.
///
/// # Confidence
/// **HIGH** on the structure (the `password ++ "||" ++ localKey` MD5 is read directly
/// from the decompiled `IPCThingP2PCamera.connect` path). The one residual assumption
/// is hex **case**: `chaos::HexUtil.a()` was NOT byte-verified from the decompile (its
/// body did not survive jadx/apktool — only the class shell remains), so lowercase is
/// *inferred* from Tuya's conventional `HexUtil` output. It is not independently
/// corroborated by [`crate::sign::md5_hex_lower`] (that is our own reimplementation,
/// not a decompile of `HexUtil.a()`). The decisive evidence is the **live test**: this
/// derivation made the SCD921 accept the conv=0 AUTH and push video end-to-end, which
/// it would not have done with the wrong case.
#[must_use]
pub fn derive_media_auth_password(password: &str, local_key: &str) -> String {
    crate::sign::md5_hex_lower(format!("{password}||{local_key}").as_bytes())
}

/// Build one 28-byte `imm` control PDU from its three per-message fields: `f4` =
/// `@4` reqId, `f12` = `@0xc` command id, and `f24` = the **second** word of the
/// 8-byte payload (`@0x18`). The constants are `@0` magic, `@0x10` payload-len = 8,
/// and `@8` (direction) = `@0x14` (first payload word) = 0 — the `SendCommand`
/// layout documented in the module header. This only **documents** the structure
/// — [`MEDIA_START_PDUS`] is the on-wire ground truth; the builder is cross-checked
/// against the literals in tests.
#[must_use]
pub fn build_media_start_pdu(f4: u32, f12: u32, f24: u32) -> [u8; MEDIA_START_PDU_LEN] {
    let mut p = [0u8; MEDIA_START_PDU_LEN];
    p[0..4].copy_from_slice(&MEDIA_START_MAGIC.to_le_bytes());
    p[4..8].copy_from_slice(&f4.to_le_bytes());
    // @8 stays 0.
    p[12..16].copy_from_slice(&f12.to_le_bytes());
    p[16..20].copy_from_slice(&8u32.to_le_bytes());
    // @20 stays 0.
    p[24..28].copy_from_slice(&f24.to_le_bytes());
    p
}

/// Read the little-endian `u32` at offset 0 of a PDU (the `imm` magic marker).
#[must_use]
pub fn pdu_magic(pdu: &[u8; MEDIA_START_PDU_LEN]) -> u32 {
    u32::from_le_bytes([pdu[0], pdu[1], pdu[2], pdu[3]])
}

#[cfg(test)]
mod tests {
    use super::*;

    // The first PDU must be the verbatim f253 literal, 28 bytes, magic 0x12345678
    // (the task's required assertion). The literal is re-stated inline so the test
    // is a real cross-check, not a tautology against the same constant.
    #[test]
    fn pdu0_is_the_f253_literal_with_imm_magic() {
        let f253: [u8; 28] = [
            0x78, 0x56, 0x34, 0x12, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x00,
            0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
        ];
        assert_eq!(MEDIA_START_PDUS[0].len(), MEDIA_START_PDU_LEN);
        assert_eq!(MEDIA_START_PDU_LEN, 28);
        assert_eq!(
            MEDIA_START_PDUS[0], f253,
            "PDU[0] must equal the f253 literal"
        );
        assert_eq!(pdu_magic(&MEDIA_START_PDUS[0]), 0x1234_5678);
        assert_eq!(pdu_magic(&MEDIA_START_PDUS[0]), MEDIA_START_MAGIC);
    }

    // Every PDU is 28 bytes and carries the imm magic at @0.
    #[test]
    fn all_pdus_are_28b_with_magic() {
        for pdu in &MEDIA_START_PDUS {
            assert_eq!(pdu.len(), 28);
            assert_eq!(pdu_magic(pdu), MEDIA_START_MAGIC);
        }
    }

    // The 24-byte VERSION PDU (SendCommand(0,10,0,{0x00010000})), sent at sn=1 after
    // the AUTH PDU: 24 bytes, imm magic @0, command 0x0A @0xc, payload 0x00010000.
    // Ground truth: ghidra_camera 002c8028:83-89 (payload) + 002c5e54 (struct).
    #[test]
    fn version_pdu_is_24b_sendcommand_0x0a() {
        let v = MEDIA_START_VERSION_PDU;
        assert_eq!(v.len(), 24, "20B SendCommand header + 4B payload");
        assert_eq!(
            u32::from_le_bytes([v[0], v[1], v[2], v[3]]),
            0x1234_5678,
            "@0 imm magic"
        );
        // @0xc command = (low_cmd<<16)|high_cmd = 0x0A (high=10, low=0).
        assert_eq!(
            u32::from_le_bytes([v[0xc], v[0xd], v[0xe], v[0xf]]),
            0x0A,
            "@0xc command id is 0x0A"
        );
        // @0x10 payload length = 4; @0x14 payload = 0x00010000 (little-endian).
        assert_eq!(
            u32::from_le_bytes([v[0x10], v[0x11], v[0x12], v[0x13]]),
            4,
            "@0x10 payload length = 4"
        );
        assert_eq!(
            u32::from_le_bytes([v[0x14], v[0x15], v[0x16], v[0x17]]),
            0x0001_0000,
            "@0x14 payload = 0x00010000"
        );
    }

    // The builder reproduces each literal from its three per-message fields — this
    // documents the @4 / @0xc / payload field semantics AND guards a typo in the
    // literals.
    #[test]
    fn builder_reproduces_the_literals() {
        assert_eq!(build_media_start_pdu(0x0001_0004, 9, 4), PDU_F253);
        assert_eq!(build_media_start_pdu(0x0001_0003, 6, 0), PDU_F254);
        assert_eq!(build_media_start_pdu(0x0001_0005, 0x0004_0006, 4), PDU_F255);
    }

    // ── The conv=0 media-start AUTH PDU (SendAuthorizationInfo) ──────────────
    // The 104-byte struct: magic@0, code@4, username@8 (NUL-padded, NUL sep @0x27),
    // password@0x28 (NUL-padded). Ground truth: ghidra_p2p/funcs/00147608.
    #[test]
    fn auth_pdu_has_magic_len_and_fields_at_the_right_offsets() {
        // SYNTHETIC username/password (never a real credential — CLAUDE.md).
        let pwd = "SynthAuthPwd"; // secret-scan:allow (synthetic test password)
        let pdu = build_auth_pdu(MEDIA_START_AUTH_CODE, MEDIA_START_AUTH_USERNAME, pwd);

        // Length is exactly 0x68 (the imm_p2p_rtc_send_data length arg).
        assert_eq!(pdu.len(), MEDIA_START_AUTH_PDU_LEN);
        assert_eq!(MEDIA_START_AUTH_PDU_LEN, 104);

        // @0 magic 0x12345678 (little-endian).
        assert_eq!(
            u32::from_le_bytes([pdu[0], pdu[1], pdu[2], pdu[3]]),
            MEDIA_START_AUTH_MAGIC
        );
        assert_eq!(MEDIA_START_AUTH_MAGIC, 0x1234_5678);

        // @4 code (little-endian i32).
        assert_eq!(
            i32::from_le_bytes([pdu[4], pdu[5], pdu[6], pdu[7]]),
            MEDIA_START_AUTH_CODE
        );

        // @8 username round-trips (NUL-terminated within its 31-byte slot), and the
        // @0x27 separator is the NUL that bounds it.
        assert_eq!(&pdu[8..8 + MEDIA_START_AUTH_USERNAME.len()], b"admin");
        assert_eq!(pdu[8 + MEDIA_START_AUTH_USERNAME.len()], 0);
        assert_eq!(pdu[0x27], 0, "the username/password separator is NUL");

        // @0x28 password round-trips.
        assert_eq!(&pdu[0x28..0x28 + pwd.len()], pwd.as_bytes());
        assert_eq!(pdu[0x28 + pwd.len()], 0, "password is NUL-padded");

        // Every byte not covered by a written field is zero (the native clears).
        for (i, &b) in pdu.iter().enumerate() {
            let in_magic = i < 4;
            let in_code = (4..8).contains(&i);
            let in_user = (8..8 + MEDIA_START_AUTH_USERNAME.len()).contains(&i);
            let in_pass = (0x28..0x28 + pwd.len()).contains(&i);
            if !(in_magic || in_code || in_user || in_pass) {
                assert_eq!(b, 0, "byte @{i:#x} must be zero-filled");
            }
        }
    }

    // strncpy truncation: an over-long username (>31) / password (>63) is cut to its
    // slot, never overrunning into the next field or past the 104-byte struct.
    #[test]
    fn auth_pdu_truncates_overlong_fields_to_their_slots() {
        let long_user = "u".repeat(40); // > 0x1f
        let long_pass = "p".repeat(80); // > 0x3f  // secret-scan:allow (synthetic)
        let pdu = build_auth_pdu(0, &long_user, &long_pass);
        // Username is capped at its 31-byte slot (offsets 8..8+0x1f); the @0x27
        // separator and the password field (0x28..0x28+0x3f) are never overrun.
        assert_eq!(&pdu[8..8 + 0x1f], &b"u".repeat(0x1f)[..]);
        assert_eq!(pdu[0x27], 0, "username truncation leaves the NUL separator");
        assert_eq!(&pdu[0x28..0x28 + 0x3f], &b"p".repeat(0x3f)[..]);
        // The struct is still exactly 104 bytes (no overrun).
        assert_eq!(pdu.len(), 104);
    }

    // KAT for the conv=0 AUTH password derivation
    // (md5_hex_lower(password ++ "||" ++ localKey); jadx IPCThingP2PCamera:6881).
    // SYNTHETIC inputs (never a real credential — CLAUDE.md). The expected digest
    // was computed independently:
    //   python3 -c 'import hashlib;print(hashlib.md5(b"pw123456||0123456789abcdef").hexdigest())'
    //   => cad489ac966634d654f21abd0f868e3c
    #[test]
    fn derive_media_auth_password_matches_independent_md5_kat() {
        // SYNTHETIC password / localKey — not a real value.
        let pw = "pw123456"; // secret-scan:allow (synthetic test password)
        let lk = "0123456789abcdef"; // secret-scan:allow (synthetic test localKey)
        let derived = derive_media_auth_password(pw, lk);

        // Exact independently-computed MD5 hex of `pw ++ "||" ++ lk`.
        assert_eq!(derived, "cad489ac966634d654f21abd0f868e3c");

        // Shape invariants: 32 chars, all ascii lowercase hex.
        assert_eq!(derived.len(), 32, "MD5 hex is always 32 chars");
        assert!(
            derived
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "HexUtil emits lowercase hex only"
        );

        // The 32-char hex fits the AUTH PDU password slot (max 0x3f) untruncated.
        assert!(derived.len() <= AUTH_PASSWORD_MAX);
    }
}
