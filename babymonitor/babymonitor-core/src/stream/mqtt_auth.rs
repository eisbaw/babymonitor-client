//! Tuya MQTT broker **CONNECT credential** derivation (clientId / username /
//! password) for the device-IPC 302 signaling channel.
//!
//! This module ports the native `doCommandNative(cmd=2, ecode)` transform — the
//! source of the broker **password** — and assembles the `clientId`/`username`
//! exactly as `SdkMqttCertificationInfo` (`qpqbppd.java`) builds them, so the
//! live [`super::transport::BrokerConfig`] can be populated from a real session
//! without any hardcoded credential.
//!
//! # The recovered derivation (was previously thought "not statically recoverable")
//!
//! `re/mqtt_signaling.md` §4 originally flagged the password as a hard live block
//! because it runs through native `doCommandNative(2)`. That routine is now
//! recovered: it is **not** an opaque transform — it is a nested MD5 over the
//! cached master key **G** and the per-session `ecode`. So the password is now
//! derivable from `G` + `ecode` (both of which we have for a live session); the
//! only residual provenance caveat is the same one that gates the signer (the
//! `bmp_token` value that folds into `G`, `re/master_secret_g.md`).
//!
//! ## cmd2 = `doCommandNative(app, 2, ecode.getBytes(), null, mD)`
//!
//! Decompiled chain (`re/ghidra/doCommandNative.c:315-376` cmd2 branch →
//! `re/ghidra/md5_key_builder.c` `FUN_00113474` →
//! `decompiled/ghidra_security/funcs/00113318_FUN_00113318.c` +
//! `001135d8_FUN_001135d8.c`):
//!
//! - `FUN_001135d8(out, a, b)` is a raw **string concatenation** `out = a ++ b`.
//! - `FUN_00113318(in, out)` hashes `in` with the lib's 128-bit digest
//!   (`FUN_00118928`/`00118944`/`001194b0` — finalize writes exactly **16 bytes**,
//!   i.e. **MD5**) and writes the **lowercase-hex** of that digest to `out`. This
//!   is the SAME primitive `computeDigest` (`re/ghidra/computeDigest.c:109`) uses,
//!   and `master_secret_g.md`/`sign.rs` already pin `computeDigest` as "MD5 →
//!   32-hex" — so `FUN_00113318(x) == sign::md5_hex_lower(x)` (two-source).
//! - `FUN_00113474(ecode, out)` therefore computes:
//!
//!   ```text
//!   out = md5_hex_lower( md5_hex_lower(G) ++ ecode )      // 32 lowercase-hex chars
//!   ```
//!
//!   (first `FUN_00113318` hashes the cached G → `hex(MD5(G))`; `FUN_001135d8`
//!   appends `ecode`; second `FUN_00113318` hashes the concatenation.)
//!
//! The **password** is then the **middle 16 chars** of that 32-char string
//! (`qpqbppd.java:132-133`: `length = str.length() >> 1; str.substring(length-8,
//! length+8)` → `[8..24]`).
//!
//! ## clientId / username (`qpqbppd.java:28-33` / `:142-152`)
//!
//! - `clientId = <partnerIdentity> + "/mb/" + <uid>`.
//! - `username = <partnerIdentity> + "_v1_" + <mAppId> + <SEP> + <chKey> + "_mb_"
//!   + <token> + <md5tail>` where:
//!   - `SEP = ddbdpdp.bdpdqbp = "_"`
//!     (`com/thingclips/sdk/device/ddbdpdp.java:12`, `ThingDeviceServiceManager.kt`);
//!   - `chKey = getChKey(app, mAppId.getBytes())` — the capture-verified
//!     [`crate::sign::ch_key`] (`mAppId == appKey`, `re/chkey_static.md`);
//!   - `md5tail = md5AsBase64( md5AsBase64(mAppId) + ecode ).substring(length-16,
//!     length)` = the **last 16 chars** of `md5_hex_lower( md5_hex_lower(mAppId) ++
//!     ecode )` — `MD5Util.md5AsBase64` is lowercase-32-hex MD5, NOT base64
//!     (`MD5Util.java:576-577` → `HexUtil.bytesToHexString`).
//!
//! # What is offline-validated vs live-gated
//!
//! - **Offline-validated:** the cmd2 ALGORITHM is bit-exact against an INDEPENDENT
//!   MD5 reference (Python `hashlib` gold vectors in the tests) and structurally
//!   against the decompiled `FUN_00113474`; the clientId/username string assembly
//!   is asserted against exact synthetic strings. NO secret value is committed.
//! - **Live-gated / no captured ground truth:** there is NO packet capture of the
//!   real MQTT CONNECT (the broker is TLS:8883, cap3's mitmproxy is HTTP-only —
//!   `re/mqtt_signaling.md` §4), so the *output* credentials have no wire vector to
//!   diff against. End-to-end correctness (AC#3) needs the owner's live broker
//!   connect. We never fabricate a value.

use crate::sign::md5_hex_lower;
use crate::Error;

/// The username segment separator `ddbdpdp.bdpdqbp` (`= "_"`,
/// `com/thingclips/sdk/device/ddbdpdp.java:12`).
const USERNAME_SEP: &str = "_";

/// Inputs needed to derive the three MQTT CONNECT credentials.
///
/// A mix of **static** material (`app_id`, `ch_key`, `master_key_g`) and
/// **per-session** material (`partner_identity`, `uid`, `token`, `ecode`) that
/// only exists after a successful cloud login + mqtt-config fetch. All fields are
/// borrowed; the secret ones (`token`, `ecode`, `master_key_g`) are never logged
/// by this module.
pub struct MqttAuthInputs<'a> {
    /// `MqttConnectConfig.getPartnerIdentity()` — the OEM/partner channel id.
    pub partner_identity: &'a str,
    /// `MqttConnectConfig.getUid()` — account user id. SECRET (account PII).
    pub uid: &'a str,
    /// `MqttConnectConfig.getToken()` — the per-session MQTT token. SECRET.
    pub token: &'a str,
    /// `MqttConnectConfig.getEcode()` — the per-session ecode. SECRET; the cmd2
    /// password input + the username `md5tail` salt.
    pub ecode: &'a str,
    /// `ThingSmartNetWork.mAppId` — the Tuya appKey string (`== appKey`).
    pub app_id: &'a str,
    /// `getChKey(app, mAppId.getBytes())` — precomputed via [`crate::sign::ch_key`]
    /// (`ch_key(appKey, package, cert_digest)`).
    pub ch_key: &'a str,
    /// The native master key **G** raw bytes ([`crate::sign::assemble_master_key_g`]).
    pub master_key_g: &'a [u8],
}

/// The three derived MQTT CONNECT parameters. `password` is **SECRET** and redacted
/// in [`Debug`].
#[derive(Clone)]
pub struct MqttCredentials {
    /// `<partnerIdentity>/mb/<uid>`.
    pub client_id: String,
    /// `<partnerIdentity>_v1_<mAppId>_<chKey>_mb_<token><md5tail>`.
    pub username: String,
    /// Middle-16 of `doCommandNative(2, ecode)`. SECRET.
    pub password: String,
}

impl std::fmt::Debug for MqttCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MqttCredentials")
            .field("client_id", &self.client_id)
            .field("username", &self.username)
            .field(
                "password",
                &format!("<redacted len={}>", self.password.len()),
            )
            .finish()
    }
}

/// Port of native `doCommandNative(app, 2, ecode.getBytes(), null, mD)`.
///
/// Returns the **full 32-char lowercase-hex** string (the password is the middle
/// 16 of this — see [`mqtt_password`]). Faithful to `FUN_00113474`
/// (`re/ghidra/md5_key_builder.c`):
///
/// ```text
/// md5_hex_lower( md5_hex_lower(G) ++ ecode )
/// ```
///
/// `master_key_g` is the raw G bytes (it is NOT UTF-8 — one part is binary, so it
/// is taken as `&[u8]`). `ecode` is appended as its UTF-8 bytes (Java
/// `String.getBytes()`).
#[must_use]
pub fn do_command_native_cmd2(master_key_g: &[u8], ecode: &str) -> String {
    // FUN_00113318(&G, out): out = hex(MD5(G))   — 32 ASCII hex chars.
    let inner = md5_hex_lower(master_key_g);
    // FUN_001135d8(local_68, out, ecode): local_68 = out ++ ecode.
    let mut combined = inner.into_bytes();
    combined.extend_from_slice(ecode.as_bytes());
    // FUN_00113318(local_80, out): out = hex(MD5(local_68)).
    md5_hex_lower(&combined)
}

/// The MQTT broker **password** = middle-16 chars of [`do_command_native_cmd2`].
///
/// Mirrors `qpqbppd.bppdpdq()` (`qpqbppd.java:132-133`):
/// `length = str.length() >> 1; str.substring(length - 8, length + 8)`. For the
/// 32-char cmd2 output that is `str[8..24]`.
///
/// # Errors
/// [`Error::StreamConfig`] if the cmd2 output is shorter than 16 chars (it never
/// is — MD5 hex is always 32 — but the slice is bounds-checked rather than able to
/// panic, matching the honest-failure rule).
pub fn mqtt_password(master_key_g: &[u8], ecode: &str) -> Result<String, Error> {
    middle_16(&do_command_native_cmd2(master_key_g, ecode))
}

/// `str[len/2 - 8 .. len/2 + 8]` — the Java `substring(length-8, length+8)` slice.
fn middle_16(s: &str) -> Result<String, Error> {
    let mid = s.len() / 2;
    if mid < 8 || mid + 8 > s.len() {
        return Err(Error::StreamConfig(format!(
            "cmd2 output too short for middle-16 (len={})",
            s.len()
        )));
    }
    Ok(s[mid - 8..mid + 8].to_string())
}

/// `clientId = <partnerIdentity>/mb/<uid>` (`qpqbppd.bdpdqbp()`,
/// `qpqbppd.java:28-33`).
#[must_use]
pub fn mqtt_client_id(partner_identity: &str, uid: &str) -> String {
    format!("{partner_identity}/mb/{uid}")
}

/// The username `md5tail` = last-16 of `md5_hex_lower( md5_hex_lower(mAppId) ++
/// ecode )` (`qpqbppd.java:149-151`).
#[must_use]
pub fn username_md5_tail(app_id: &str, ecode: &str) -> String {
    let inner = md5_hex_lower(app_id.as_bytes());
    let mut combined = inner.into_bytes();
    combined.extend_from_slice(ecode.as_bytes());
    let full = md5_hex_lower(&combined);
    // substring(length - 16, length): the LAST 16 chars (vs the password's MIDDLE
    // 16 — the two slices differ, do not conflate them).
    full[full.len() - 16..].to_string()
}

/// `username = <partnerIdentity>_v1_<mAppId>_<chKey>_mb_<token><md5tail>`
/// (`qpqbppd.qddqppb()`, `qpqbppd.java:142-152`).
#[must_use]
pub fn mqtt_username(
    partner_identity: &str,
    app_id: &str,
    ch_key: &str,
    token: &str,
    ecode: &str,
) -> String {
    let tail = username_md5_tail(app_id, ecode);
    let mut s = String::new();
    s.push_str(partner_identity);
    s.push_str("_v1_");
    s.push_str(app_id);
    s.push_str(USERNAME_SEP); // ddbdpdp.bdpdqbp = "_"
    s.push_str(ch_key);
    s.push_str("_mb_");
    s.push_str(token);
    s.push_str(&tail);
    s
}

/// Derive all three CONNECT credentials from a live session.
///
/// # Errors
/// Propagates [`mqtt_password`]'s bounds error (in practice infallible for a
/// real 32-char cmd2 output).
pub fn derive_credentials(inputs: &MqttAuthInputs) -> Result<MqttCredentials, Error> {
    Ok(MqttCredentials {
        client_id: mqtt_client_id(inputs.partner_identity, inputs.uid),
        username: mqtt_username(
            inputs.partner_identity,
            inputs.app_id,
            inputs.ch_key,
            inputs.token,
            inputs.ecode,
        ),
        password: mqtt_password(inputs.master_key_g, inputs.ecode)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Independent MD5 gold vectors ────────────────────────────────────────
    // Computed OUT-OF-BAND with Python `hashlib` (a DIFFERENT MD5 implementation
    // from the Rust `md5` crate), so these assert cross-implementation parity of
    // the cmd2 algorithm — not just that our code equals itself. Reproduce:
    //
    //   python3 - <<'PY'
    //   import hashlib
    //   h=lambda b: hashlib.md5(b).hexdigest()
    //   G=b'SYNTH_MASTER_KEY_G_0123456789'; ecode='SYNTH_ECODE_ABC'
    //   cmd2=h(h(G).encode()+ecode.encode())
    //   print(cmd2, cmd2[len(cmd2)//2-8:len(cmd2)//2+8])
    //   PY
    //
    // All values here are SYNTHETIC (CLAUDE.md) — never a real G/ecode/password.
    const SYNTH_G: &[u8] = b"SYNTH_MASTER_KEY_G_0123456789";
    const SYNTH_ECODE: &str = "SYNTH_ECODE_ABC";
    const GOLD_CMD2: &str = "b55acd76e9c82619e3079fe244cb4851";
    const GOLD_PASSWORD: &str = "e9c82619e3079fe2";

    #[test]
    fn cmd2_matches_independent_python_md5_gold() {
        // Bit-exact vs an independent MD5 implementation (Python hashlib).
        assert_eq!(do_command_native_cmd2(SYNTH_G, SYNTH_ECODE), GOLD_CMD2);
    }

    #[test]
    fn cmd2_output_is_32_lowercase_hex() {
        let out = do_command_native_cmd2(SYNTH_G, SYNTH_ECODE);
        assert_eq!(out.len(), 32);
        assert!(out
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn cmd2_structure_matches_decompiled_fun_00113474() {
        // Independently reconstruct FUN_00113474's nested-MD5 structure and assert
        // our implementation equals it (decompile-semantics check):
        //   out = md5_hex_lower( md5_hex_lower(G) ++ ecode )
        let inner = md5_hex_lower(SYNTH_G); // FUN_00113318(&G, out)
        let concatenated = format!("{inner}{SYNTH_ECODE}"); // FUN_001135d8
        let expected = md5_hex_lower(concatenated.as_bytes()); // FUN_00113318(local_80, out)
        assert_eq!(do_command_native_cmd2(SYNTH_G, SYNTH_ECODE), expected);
    }

    #[test]
    fn password_is_middle_16_of_cmd2() {
        let pw = mqtt_password(SYNTH_G, SYNTH_ECODE).expect("password derivable");
        assert_eq!(pw, GOLD_PASSWORD);
        assert_eq!(pw.len(), 16);
        // It is exactly the MIDDLE slice [8..24] of the 32-char cmd2 string
        // (qpqbppd.java:132-133: length = 32>>1 = 16; substring(8, 24)).
        let cmd2 = do_command_native_cmd2(SYNTH_G, SYNTH_ECODE);
        assert_eq!(&cmd2[8..24], pw);
    }

    #[test]
    fn middle_16_rejects_too_short() {
        // A <16-char string cannot yield a middle-16 window → typed error, no panic.
        assert!(middle_16("short").is_err());
        assert!(middle_16("0123456789abcde").is_err()); // 15 chars
        assert!(middle_16("0123456789abcdef").is_ok()); // 16 chars → mid=8, [0..16]
    }

    #[test]
    fn client_id_format() {
        assert_eq!(
            mqtt_client_id("PARTNERX", "SYNTH_UID_0001"),
            "PARTNERX/mb/SYNTH_UID_0001"
        );
    }

    #[test]
    fn username_md5_tail_matches_independent_python_gold() {
        // python: h(h(b'SYNTH_APPKEY_0001').encode()+b'SYNTH_ECODE_ABC')[-16:]
        assert_eq!(
            username_md5_tail("SYNTH_APPKEY_0001", SYNTH_ECODE),
            "d5b94857b87fc8f6"
        );
    }

    #[test]
    fn username_full_assembly() {
        // <partner>_v1_<appId>_<chKey>_mb_<token><md5tail>
        let u = mqtt_username(
            "PARTNERX",
            "SYNTH_APPKEY_0001",
            "0a1b2c3d", // synthetic 8-char chKey (sign::ch_key shape)
            "SYNTH_TOKEN_Z",
            SYNTH_ECODE,
        );
        assert_eq!(
            u,
            "PARTNERX_v1_SYNTH_APPKEY_0001_0a1b2c3d_mb_SYNTH_TOKEN_Zd5b94857b87fc8f6"
        );
    }

    #[test]
    fn derive_credentials_wires_all_three() {
        let inputs = MqttAuthInputs {
            partner_identity: "PARTNERX",
            uid: "SYNTH_UID_0001",
            token: "SYNTH_TOKEN_Z",
            ecode: SYNTH_ECODE,
            app_id: "SYNTH_APPKEY_0001",
            ch_key: "0a1b2c3d",
            master_key_g: SYNTH_G,
        };
        let creds = derive_credentials(&inputs).expect("derivable");
        assert_eq!(creds.client_id, "PARTNERX/mb/SYNTH_UID_0001");
        assert_eq!(
            creds.username,
            "PARTNERX_v1_SYNTH_APPKEY_0001_0a1b2c3d_mb_SYNTH_TOKEN_Zd5b94857b87fc8f6"
        );
        assert_eq!(creds.password, GOLD_PASSWORD);
    }

    #[test]
    fn credentials_redact_password_in_debug() {
        let creds = MqttCredentials {
            client_id: "PARTNERX/mb/UID".into(),
            username: "u".into(),
            password: GOLD_PASSWORD.into(),
        };
        let dbg = format!("{creds:?}");
        assert!(dbg.contains("redacted"));
        assert!(!dbg.contains(GOLD_PASSWORD));
        assert!(dbg.contains("PARTNERX/mb/UID")); // non-secret fields shown
    }
}
