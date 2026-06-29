//! Minimal STUN (RFC 5389 / 8489) codec used as the ICE connectivity-check and
//! server-reflexive-discovery primitive for the media path (TASK-0075).
//!
//! # Why this exists (and what it is NOT)
//!
//! cap4 proved the camera is reached over a **LAN host candidate** with no relay
//! (`emulator_captures/cap4/TRAFFIC.md`), so the default media path is host-direct
//! UDP ([`super::transport::connect_host_direct`]). But even the host-direct path
//! needs the ICE *connectivity check* — an authenticated STUN Binding Request the
//! offerer sends to the peer's candidate so the camera opens consent and starts
//! sending media. cap4 contains ~559 real STUN packets, 541 of which are ICE
//! connectivity-check Binding Requests app→camera. This module encodes/decodes
//! exactly those, plus the Binding Success → XOR-MAPPED-ADDRESS that yields a
//! **srflx** candidate for the remote/NAT case.
//!
//! This is a *minimal* STUN: Binding only (no TURN allocation — TURN is a
//! documented stub in [`super::transport`]), short-term-credential
//! MESSAGE-INTEGRITY (the ICE password keys the HMAC-SHA1), and FINGERPRINT.
//!
//! # cap4-pinned (KAT)
//!
//! [`message_integrity`] + [`fingerprint`] reproduce a **real** cap4 Binding
//! Request's MESSAGE-INTEGRITY (HMAC-SHA1, key = the camera/answer ICE pwd) and
//! FINGERPRINT (CRC-32 ^ `0x5354554e`) bytes EXACTLY, and [`BindingRequest::encode`]
//! reproduces the whole 100-byte packet byte-for-byte. See
//! `babymonitor-core/tests/cap4_stun_kat.rs` (`#[ignore]`d, reads the gitignored
//! cap4 capture + the runtime-recovered ICE pwd — never an inlined secret).
//!
//! [`StunMessage::xor_mapped_address`] decodes a Binding Success response's
//! XOR-MAPPED-ADDRESS to a **srflx** candidate; the real cap4 srflx is recovered
//! at runtime from the gitignored capture and is never inlined here.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use hmac::{Hmac, Mac};
use sha1::Sha1;

use crate::Error;

/// The STUN magic cookie (`bytes[4..8]` of every STUN message; RFC 5389 §6).
pub const MAGIC_COOKIE: u32 = 0x2112_a442;
/// The FINGERPRINT XOR constant (RFC 5389 §15.5): `CRC-32(msg) ^ 0x5354554e`.
pub const FINGERPRINT_XOR: u32 = 0x5354_554e;

/// STUN message type: Binding **Request** (class request, method binding).
pub const BINDING_REQUEST: u16 = 0x0001;
/// STUN message type: Binding **Success Response**.
pub const BINDING_SUCCESS: u16 = 0x0101;
/// STUN message type: Binding **Error Response**.
pub const BINDING_ERROR: u16 = 0x0111;

/// Attribute type: MAPPED-ADDRESS (legacy, non-XOR).
pub const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
/// Attribute type: USERNAME (`<remoteUfrag>:<localUfrag>` for an ICE check).
pub const ATTR_USERNAME: u16 = 0x0006;
/// Attribute type: MESSAGE-INTEGRITY (20-byte HMAC-SHA1).
pub const ATTR_MESSAGE_INTEGRITY: u16 = 0x0008;
/// Attribute type: ERROR-CODE.
pub const ATTR_ERROR_CODE: u16 = 0x0009;
/// Attribute type: XOR-MAPPED-ADDRESS (the srflx the server reflects back).
pub const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
/// Attribute type: PRIORITY (ICE candidate priority, RFC 8445 §7.1.1).
pub const ATTR_PRIORITY: u16 = 0x0024;
/// Attribute type: USE-CANDIDATE (nomination flag, empty value).
pub const ATTR_USE_CANDIDATE: u16 = 0x0025;
/// Attribute type: SOFTWARE (agent name/version; cap4 = `"3.5.5"`).
pub const ATTR_SOFTWARE: u16 = 0x8022;
/// Attribute type: FINGERPRINT (CRC-32 ^ `0x5354554e`).
pub const ATTR_FINGERPRINT: u16 = 0x8028;
/// Attribute type: ICE-CONTROLLING (8-byte tiebreaker).
pub const ATTR_ICE_CONTROLLING: u16 = 0x8029;
/// Attribute type: ICE-CONTROLLED (8-byte tiebreaker).
pub const ATTR_ICE_CONTROLLED: u16 = 0x802a;

/// The fixed STUN header length (type + length + cookie + 96-bit transaction id).
pub const HEADER_LEN: usize = 20;
/// The MESSAGE-INTEGRITY value length (HMAC-SHA1 = 20 bytes).
pub const MESSAGE_INTEGRITY_LEN: usize = 20;

/// One decoded STUN attribute: its type plus the raw (un-padded) value bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StunAttr {
    /// The attribute type (e.g. [`ATTR_USERNAME`]).
    pub typ: u16,
    /// The attribute value (length as declared, before 4-byte padding).
    pub value: Vec<u8>,
}

/// A decoded STUN message: type + 96-bit transaction id + the attribute list, in
/// wire order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StunMessage {
    /// The STUN message type (class+method), e.g. [`BINDING_REQUEST`].
    pub msg_type: u16,
    /// The 96-bit transaction id (`bytes[8..20]`).
    pub txid: [u8; 12],
    /// The attributes, in the order they appear on the wire.
    pub attributes: Vec<StunAttr>,
}

impl StunMessage {
    /// Decode a STUN message from a UDP payload.
    ///
    /// Validates the 20-byte header, the [`MAGIC_COOKIE`], and that the declared
    /// message length fits in `buf`, then walks the TLV attributes (each value
    /// padded to a 4-byte boundary). Trailing bytes past the declared length are
    /// ignored. This is a *parser only* — it does not verify MESSAGE-INTEGRITY or
    /// FINGERPRINT (the caller checks those when it has the key).
    ///
    /// # Errors
    /// [`Error::Transport`] if the buffer is shorter than the header, the cookie
    /// is wrong, the declared length overruns the buffer, or an attribute length
    /// overruns the message.
    pub fn decode(buf: &[u8]) -> Result<Self, Error> {
        if buf.len() < HEADER_LEN {
            return Err(Error::Transport(format!(
                "STUN message is {} bytes; shorter than the 20-byte header",
                buf.len()
            )));
        }
        let cookie = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        if cookie != MAGIC_COOKIE {
            return Err(Error::Transport(format!(
                "not a STUN message: magic cookie {cookie:#010x} != {MAGIC_COOKIE:#010x}"
            )));
        }
        let msg_type = u16::from_be_bytes([buf[0], buf[1]]);
        let length = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        let end = HEADER_LEN
            .checked_add(length)
            .filter(|&e| e <= buf.len())
            .ok_or_else(|| {
                Error::Transport(format!(
                    "STUN declared length {length} overruns the {}-byte buffer",
                    buf.len()
                ))
            })?;
        let mut txid = [0u8; 12];
        txid.copy_from_slice(&buf[8..20]);

        let mut attributes = Vec::new();
        let mut off = HEADER_LEN;
        while off + 4 <= end {
            let typ = u16::from_be_bytes([buf[off], buf[off + 1]]);
            let alen = u16::from_be_bytes([buf[off + 2], buf[off + 3]]) as usize;
            let vstart = off + 4;
            let vend = vstart
                .checked_add(alen)
                .filter(|&v| v <= end)
                .ok_or_else(|| {
                    Error::Transport(format!(
                        "STUN attribute {typ:#06x} length {alen} overruns the message"
                    ))
                })?;
            attributes.push(StunAttr {
                typ,
                value: buf[vstart..vend].to_vec(),
            });
            // Advance past the value and its 4-byte padding.
            off = (vend + 3) & !3;
        }
        Ok(Self {
            msg_type,
            txid,
            attributes,
        })
    }

    /// The first attribute value of type `typ`, if present.
    #[must_use]
    pub fn attr(&self, typ: u16) -> Option<&[u8]> {
        self.attributes
            .iter()
            .find(|a| a.typ == typ)
            .map(|a| a.value.as_slice())
    }

    /// Whether this is a Binding **Success** Response.
    #[must_use]
    pub fn is_binding_success(&self) -> bool {
        self.msg_type == BINDING_SUCCESS
    }

    /// Decode the XOR-MAPPED-ADDRESS attribute (the server-reflexive address) to a
    /// [`SocketAddr`], if present. This is the **srflx** candidate.
    ///
    /// The address is XOR-folded against the magic cookie (IPv4) or the cookie +
    /// transaction id (IPv6), per RFC 5389 §15.2.
    ///
    /// # Errors
    /// [`Error::Transport`] if the attribute is present but malformed (bad length
    /// or an unknown address family). Returns `Ok(None)` if absent.
    pub fn xor_mapped_address(&self) -> Result<Option<SocketAddr>, Error> {
        let Some(value) = self.attr(ATTR_XOR_MAPPED_ADDRESS) else {
            return Ok(None);
        };
        decode_xor_mapped_address(value, &self.txid).map(Some)
    }
}

/// Decode an XOR-MAPPED-ADDRESS attribute value (`[reserved, family, xport(2),
/// xaddr(..)]`) into a [`SocketAddr`].
fn decode_xor_mapped_address(value: &[u8], txid: &[u8; 12]) -> Result<SocketAddr, Error> {
    if value.len() < 4 {
        return Err(Error::Transport(format!(
            "XOR-MAPPED-ADDRESS is {} bytes; need at least 4",
            value.len()
        )));
    }
    let family = value[1];
    let port = u16::from_be_bytes([value[2], value[3]]) ^ ((MAGIC_COOKIE >> 16) as u16);
    let cookie = MAGIC_COOKIE.to_be_bytes();
    match family {
        0x01 => {
            // IPv4: XOR the 4 address bytes with the magic cookie.
            if value.len() < 8 {
                return Err(Error::Transport(
                    "XOR-MAPPED-ADDRESS (IPv4) is shorter than 8 bytes".to_string(),
                ));
            }
            let mut a = [0u8; 4];
            for i in 0..4 {
                a[i] = value[4 + i] ^ cookie[i];
            }
            Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(a)), port))
        }
        0x02 => {
            // IPv6: XOR with the cookie (first 4 bytes) followed by the txid.
            if value.len() < 20 {
                return Err(Error::Transport(
                    "XOR-MAPPED-ADDRESS (IPv6) is shorter than 20 bytes".to_string(),
                ));
            }
            let mut key = [0u8; 16];
            key[..4].copy_from_slice(&cookie);
            key[4..].copy_from_slice(txid);
            let mut a = [0u8; 16];
            for i in 0..16 {
                a[i] = value[4 + i] ^ key[i];
            }
            Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(a)), port))
        }
        other => Err(Error::Transport(format!(
            "XOR-MAPPED-ADDRESS unknown address family {other:#04x} (expected 0x01/0x02)"
        ))),
    }
}

/// The ICE role attribute carried on a connectivity check, with its 8-byte
/// tiebreaker (RFC 8445 §7.1.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IceRole {
    /// ICE-CONTROLLING (the offerer/controlling agent).
    Controlling(u64),
    /// ICE-CONTROLLED (the controlled agent).
    Controlled(u64),
}

/// An ICE connectivity-check **Binding Request** to encode.
///
/// The attribute order matches the cap4 capture exactly — `PRIORITY`,
/// `[USE-CANDIDATE]`, `ICE-CONTROLLING`/`ICE-CONTROLLED`, `[SOFTWARE]`,
/// `USERNAME`, `MESSAGE-INTEGRITY`, `FINGERPRINT` — so [`Self::encode`] reproduces
/// a real packet byte-for-byte when fed the captured field values.
#[derive(Debug, Clone)]
pub struct BindingRequest {
    /// The 96-bit transaction id (client-minted; echoed in the response).
    pub txid: [u8; 12],
    /// USERNAME = `<remoteUfrag>:<localUfrag>` (RFC 8445 §7.1.2).
    pub username: String,
    /// PRIORITY of the local candidate being checked.
    pub priority: u32,
    /// The ICE role + tiebreaker.
    pub role: IceRole,
    /// Whether to set USE-CANDIDATE (nomination).
    pub use_candidate: bool,
    /// Optional SOFTWARE attribute (cap4 sends `"3.5.5"`).
    pub software: Option<String>,
}

impl BindingRequest {
    /// Encode this Binding Request to its on-wire bytes, appending
    /// MESSAGE-INTEGRITY (HMAC-SHA1 keyed by `integrity_key` — the **peer/remote**
    /// ICE password for an outbound check) and FINGERPRINT.
    ///
    /// # Errors
    /// [`Error::Transport`] only if HMAC-SHA1 key initialization fails (it accepts
    /// any key length, so this is effectively infallible — surfaced as a typed
    /// error rather than a panic to honor the crate's no-panic discipline).
    pub fn encode(&self, integrity_key: &[u8]) -> Result<Vec<u8>, Error> {
        let mut buf = Vec::with_capacity(128);
        // Header: type + placeholder length + cookie + txid.
        buf.extend_from_slice(&BINDING_REQUEST.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes()); // length patched at the end
        buf.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        buf.extend_from_slice(&self.txid);

        // Attributes, in the cap4-observed order.
        push_attr(&mut buf, ATTR_PRIORITY, &self.priority.to_be_bytes());
        if self.use_candidate {
            push_attr(&mut buf, ATTR_USE_CANDIDATE, &[]);
        }
        match self.role {
            IceRole::Controlling(tb) => {
                push_attr(&mut buf, ATTR_ICE_CONTROLLING, &tb.to_be_bytes());
            }
            IceRole::Controlled(tb) => {
                push_attr(&mut buf, ATTR_ICE_CONTROLLED, &tb.to_be_bytes());
            }
        }
        if let Some(sw) = &self.software {
            push_attr(&mut buf, ATTR_SOFTWARE, sw.as_bytes());
        }
        push_attr(&mut buf, ATTR_USERNAME, self.username.as_bytes());

        // MESSAGE-INTEGRITY over the message so far (header length counts through
        // the MI attribute), then FINGERPRINT over the message through the FP attr.
        let mi = message_integrity(&buf, integrity_key)?;
        push_attr(&mut buf, ATTR_MESSAGE_INTEGRITY, &mi);
        let fp = fingerprint(&buf);
        push_attr(&mut buf, ATTR_FINGERPRINT, &fp.to_be_bytes());

        // Patch the real header length (everything after the 20-byte header).
        let len_after = u16::try_from(buf.len() - HEADER_LEN).map_err(|_| {
            Error::Transport("STUN message exceeds 65535 bytes after header".to_string())
        })?;
        buf[2..4].copy_from_slice(&len_after.to_be_bytes());
        Ok(buf)
    }
}

/// Encode a *bare* Binding Request (just SOFTWARE + FINGERPRINT, no credentials) —
/// the query a client sends to a STUN **server** to learn its srflx candidate
/// (the response's XOR-MAPPED-ADDRESS). A server query is not ICE-authenticated,
/// so it carries no USERNAME/MESSAGE-INTEGRITY.
#[must_use]
pub fn encode_server_query(txid: [u8; 12], software: Option<&str>) -> Vec<u8> {
    let mut buf = Vec::with_capacity(32);
    buf.extend_from_slice(&BINDING_REQUEST.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    buf.extend_from_slice(&txid);
    if let Some(sw) = software {
        push_attr(&mut buf, ATTR_SOFTWARE, sw.as_bytes());
    }
    let fp = fingerprint(&buf);
    push_attr(&mut buf, ATTR_FINGERPRINT, &fp.to_be_bytes());
    let len_after = (buf.len() - HEADER_LEN) as u16;
    buf[2..4].copy_from_slice(&len_after.to_be_bytes());
    buf
}

/// Encode a Binding **Success** response: echo `txid`, carry XOR-MAPPED-ADDRESS =
/// `mapped` (the requester's source address as we observed it), then append
/// MESSAGE-INTEGRITY (HMAC-SHA1 keyed by `integrity_key`) and FINGERPRINT.
///
/// This is the reply an ICE agent sends to a peer's connectivity check so the
/// peer confirms consent-to-send (RFC 8445 §7.3, RFC 7675). For the babymonitor
/// host-direct path the camera (the controlled agent) periodically checks us to
/// keep ITS consent fresh; answering with this success keeps the camera streaming
/// during a sustained session. `integrity_key` is OUR **local** ICE password (the
/// short-term credential the inbound check authenticated under).
///
/// # Errors
/// [`Error::Transport`] if the message overruns 65535 bytes after the header, or
/// HMAC key init fails (see [`message_integrity`]).
pub fn encode_binding_success(
    txid: [u8; 12],
    mapped: SocketAddr,
    integrity_key: &[u8],
) -> Result<Vec<u8>, Error> {
    let mut buf = Vec::with_capacity(64);
    buf.extend_from_slice(&BINDING_SUCCESS.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes()); // length patched at the end
    buf.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    buf.extend_from_slice(&txid);

    push_attr(
        &mut buf,
        ATTR_XOR_MAPPED_ADDRESS,
        &encode_xor_mapped_address(mapped, &txid),
    );
    let mi = message_integrity(&buf, integrity_key)?;
    push_attr(&mut buf, ATTR_MESSAGE_INTEGRITY, &mi);
    let fp = fingerprint(&buf);
    push_attr(&mut buf, ATTR_FINGERPRINT, &fp.to_be_bytes());

    let len_after = u16::try_from(buf.len() - HEADER_LEN).map_err(|_| {
        Error::Transport("STUN message exceeds 65535 bytes after header".to_string())
    })?;
    buf[2..4].copy_from_slice(&len_after.to_be_bytes());
    Ok(buf)
}

/// Encode an XOR-MAPPED-ADDRESS attribute VALUE (`[reserved, family, xport(2),
/// xaddr(..)]`) for `addr` — the inverse of [`decode_xor_mapped_address`] (RFC
/// 5389 §15.2).
fn encode_xor_mapped_address(addr: SocketAddr, txid: &[u8; 12]) -> Vec<u8> {
    let cookie = MAGIC_COOKIE.to_be_bytes();
    let xport = addr.port() ^ ((MAGIC_COOKIE >> 16) as u16);
    let mut v = Vec::with_capacity(20);
    v.push(0x00); // reserved
    match addr.ip() {
        IpAddr::V4(ip) => {
            v.push(0x01);
            v.extend_from_slice(&xport.to_be_bytes());
            for (i, o) in ip.octets().iter().enumerate() {
                v.push(o ^ cookie[i]);
            }
        }
        IpAddr::V6(ip) => {
            v.push(0x02);
            v.extend_from_slice(&xport.to_be_bytes());
            let mut key = [0u8; 16];
            key[..4].copy_from_slice(&cookie);
            key[4..].copy_from_slice(txid);
            for (i, o) in ip.octets().iter().enumerate() {
                v.push(o ^ key[i]);
            }
        }
    }
    v
}

/// Append one STUN attribute `[type(2) | length(2) | value | pad-to-4]` to `buf`.
fn push_attr(buf: &mut Vec<u8>, typ: u16, value: &[u8]) {
    buf.extend_from_slice(&typ.to_be_bytes());
    buf.extend_from_slice(&(value.len() as u16).to_be_bytes());
    buf.extend_from_slice(value);
    while buf.len() % 4 != 0 {
        buf.push(0);
    }
}

/// Compute the MESSAGE-INTEGRITY (HMAC-SHA1, 20 bytes) value that should follow
/// `prefix`, where `prefix` is the full STUN message bytes from offset 0 up to —
/// but not including — the MESSAGE-INTEGRITY attribute.
///
/// Per RFC 5389 §15.4 the HMAC is taken over the message with its header **length
/// field set to cover through the MESSAGE-INTEGRITY attribute** (i.e.
/// `prefix.len() - 20 + 24`); this function patches a copy's length accordingly,
/// so the caller passes the prefix with any placeholder length. The `key` is the
/// short-term credential — for an ICE connectivity check, the **peer's** ICE
/// password (no realm).
///
/// # Errors
/// [`Error::Transport`] if `prefix` is shorter than the 20-byte header, or HMAC
/// key init fails (HMAC accepts any key length; surfaced as a typed error).
pub fn message_integrity(prefix: &[u8], key: &[u8]) -> Result<[u8; MESSAGE_INTEGRITY_LEN], Error> {
    if prefix.len() < HEADER_LEN {
        return Err(Error::Transport(
            "STUN MESSAGE-INTEGRITY prefix is shorter than the 20-byte header".to_string(),
        ));
    }
    // Length that points to the end of the (about-to-be-added) MI attribute:
    // (bytes after header in the prefix) + 4 (MI type/len) + 20 (MI value).
    let len_after = u16::try_from(prefix.len() - HEADER_LEN + 4 + MESSAGE_INTEGRITY_LEN)
        .map_err(|_| Error::Transport("STUN message too long for MESSAGE-INTEGRITY".to_string()))?;
    let mut patched = prefix.to_vec();
    patched[2..4].copy_from_slice(&len_after.to_be_bytes());

    let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(key)
        .map_err(|e| Error::Transport(format!("STUN HMAC-SHA1 key init failed: {e}")))?;
    mac.update(&patched);
    let tag = mac.finalize().into_bytes();
    let mut out = [0u8; MESSAGE_INTEGRITY_LEN];
    out.copy_from_slice(&tag);
    Ok(out)
}

/// Verify a decoded message's MESSAGE-INTEGRITY against `key`, given the full raw
/// message bytes `raw`. Returns `Ok(true)`/`Ok(false)`; `Ok(false)` also covers a
/// message with no MESSAGE-INTEGRITY attribute.
///
/// Used to authenticate an inbound Binding Request/Response (the camera's check or
/// the response to ours) under the relevant ICE password.
///
/// # Errors
/// [`Error::Transport`] if `raw` is malformed (cannot locate the MI attribute) or
/// HMAC init fails.
pub fn verify_message_integrity(raw: &[u8], key: &[u8]) -> Result<bool, Error> {
    let Some(mi_off) = find_attr_offset(raw, ATTR_MESSAGE_INTEGRITY)? else {
        return Ok(false);
    };
    let prefix = &raw[..mi_off];
    let expected = message_integrity(prefix, key)?;
    let actual = &raw[mi_off + 4..mi_off + 4 + MESSAGE_INTEGRITY_LEN];
    // Constant-time compare.
    Ok(actual.ct_eq(&expected))
}

/// Find the byte offset of the first attribute of type `typ` in a raw STUN
/// message (walking the TLVs), or `None` if absent.
fn find_attr_offset(raw: &[u8], typ: u16) -> Result<Option<usize>, Error> {
    if raw.len() < HEADER_LEN {
        return Err(Error::Transport(
            "STUN message shorter than header".to_string(),
        ));
    }
    let length = u16::from_be_bytes([raw[2], raw[3]]) as usize;
    let end = (HEADER_LEN + length).min(raw.len());
    let mut off = HEADER_LEN;
    while off + 4 <= end {
        let t = u16::from_be_bytes([raw[off], raw[off + 1]]);
        let alen = u16::from_be_bytes([raw[off + 2], raw[off + 3]]) as usize;
        if t == typ {
            return Ok(Some(off));
        }
        let vend = off + 4 + alen;
        if vend > end {
            break;
        }
        off = (vend + 3) & !3;
    }
    Ok(None)
}

/// Compute the FINGERPRINT value (`CRC-32(prefix-with-patched-length) ^
/// 0x5354554e`) that should follow `prefix`, where `prefix` is the message bytes
/// up to — but not including — the FINGERPRINT attribute (RFC 5389 §15.5). The
/// header length field is patched to cover through the FINGERPRINT attribute.
#[must_use]
pub fn fingerprint(prefix: &[u8]) -> u32 {
    debug_assert!(prefix.len() >= HEADER_LEN);
    if prefix.len() < HEADER_LEN {
        // A FINGERPRINT prefix shorter than the header is a caller bug; rather
        // than underflow, CRC the bytes as-is (no length to patch). This never
        // happens on a real STUN message (FP follows a 20-byte header + attrs).
        return crc32_ieee(prefix) ^ FINGERPRINT_XOR;
    }
    // Length that points to the end of the (about-to-be-added) FP attribute:
    // (bytes after header) + 4 (FP type/len) + 4 (FP value).
    let len_after = (prefix.len() - HEADER_LEN + 8) as u16;
    let mut patched = prefix.to_vec();
    patched[2..4].copy_from_slice(&len_after.to_be_bytes());
    crc32_ieee(&patched) ^ FINGERPRINT_XOR
}

/// Standard IEEE 802.3 / zlib CRC-32 (reflected, poly `0xEDB88320`, init/xor-out
/// `0xFFFFFFFF`). Implemented inline so the offline cargo gate needs no extra
/// crate; bit-for-bit identical to `zlib`'s `crc32`.
fn crc32_ieee(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// Constant-time byte-slice equality (avoids a timing side channel on MI compare).
trait ConstantTimeEq {
    fn ct_eq(&self, other: &[u8]) -> bool;
}
impl ConstantTimeEq for [u8] {
    fn ct_eq(&self, other: &[u8]) -> bool {
        if self.len() != other.len() {
            return false;
        }
        let mut diff = 0u8;
        for (a, b) in self.iter().zip(other.iter()) {
            diff |= a ^ b;
        }
        diff == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A synthetic ICE password — never a real device/session value (CLAUDE.md).
    const PWD: &[u8] = b"SyntheticIcePwd012345678"; // secret-scan:allow (synthetic test pwd)

    fn synth_request(use_candidate: bool) -> BindingRequest {
        BindingRequest {
            txid: *b"txid01234567",
            username: "REMOTEuf:LOCALuf".to_string(),
            priority: 0x6eff_ffff,
            role: IceRole::Controlling(0xffff_ffff_158f_0ac3),
            use_candidate,
            software: Some("3.5.5".to_string()),
        }
    }

    // ── CRC-32 sanity against known zlib vectors ───────────────────────────
    #[test]
    fn crc32_matches_known_vectors() {
        assert_eq!(crc32_ieee(b""), 0x0000_0000);
        assert_eq!(crc32_ieee(b"123456789"), 0xCBF4_3926); // canonical CRC-32 check value
        assert_eq!(
            crc32_ieee(b"The quick brown fox jumps over the lazy dog"),
            0x414F_A339
        );
    }

    // ── Encode → decode round-trip ─────────────────────────────────────────
    #[test]
    fn encode_then_decode_round_trips() {
        let req = synth_request(false);
        let bytes = req.encode(PWD).unwrap();
        // 4-byte aligned, header present, declared length consistent.
        assert_eq!(bytes.len() % 4, 0);
        let declared = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
        assert_eq!(declared, bytes.len() - HEADER_LEN);

        let msg = StunMessage::decode(&bytes).unwrap();
        assert_eq!(msg.msg_type, BINDING_REQUEST);
        assert_eq!(&msg.txid, b"txid01234567");
        assert_eq!(
            msg.attr(ATTR_USERNAME).unwrap(),
            b"REMOTEuf:LOCALuf".as_slice()
        );
        assert_eq!(
            msg.attr(ATTR_PRIORITY).unwrap(),
            &0x6eff_ffffu32.to_be_bytes()
        );
        assert!(msg.attr(ATTR_ICE_CONTROLLING).is_some());
        assert_eq!(msg.attr(ATTR_SOFTWARE).unwrap(), b"3.5.5".as_slice());
        assert!(msg.attr(ATTR_MESSAGE_INTEGRITY).is_some());
        assert!(msg.attr(ATTR_FINGERPRINT).is_some());
    }

    // ── MESSAGE-INTEGRITY verifies under the encoding key ──────────────────
    #[test]
    fn encoded_message_integrity_verifies() {
        let bytes = synth_request(true).encode(PWD).unwrap();
        assert!(verify_message_integrity(&bytes, PWD).unwrap());
        // USE-CANDIDATE present (empty value).
        let msg = StunMessage::decode(&bytes).unwrap();
        assert_eq!(msg.attr(ATTR_USE_CANDIDATE), Some(&[][..]));
    }

    // NEGATIVE: a one-bit flip in the body breaks MESSAGE-INTEGRITY.
    #[test]
    fn tampered_body_fails_message_integrity() {
        let mut bytes = synth_request(false).encode(PWD).unwrap();
        bytes[24] ^= 0x01; // flip a byte inside PRIORITY
        assert!(!verify_message_integrity(&bytes, PWD).unwrap());
    }

    // NEGATIVE: the wrong key fails MESSAGE-INTEGRITY (proves key-binding bites).
    #[test]
    fn wrong_key_fails_message_integrity() {
        let bytes = synth_request(false).encode(PWD).unwrap();
        assert!(!verify_message_integrity(&bytes, b"the-wrong-ice-password00").unwrap());
        // secret-scan:allow
    }

    // ── FINGERPRINT integrity: recompute over the prefix == embedded value ──
    #[test]
    fn fingerprint_recomputes_to_embedded_value() {
        let bytes = synth_request(false).encode(PWD).unwrap();
        let fp_off = find_attr_offset(&bytes, ATTR_FINGERPRINT).unwrap().unwrap();
        let embedded = u32::from_be_bytes([
            bytes[fp_off + 4],
            bytes[fp_off + 5],
            bytes[fp_off + 6],
            bytes[fp_off + 7],
        ]);
        assert_eq!(fingerprint(&bytes[..fp_off]), embedded);
    }

    // ── XOR-MAPPED-ADDRESS round-trip (IPv4 + IPv6) ────────────────────────
    #[test]
    fn xor_mapped_address_ipv4_round_trip() {
        // Encode a documentation srflx address (RFC 5737 TEST-NET-1) as an
        // XOR-MAPPED-ADDRESS in a Binding Success and decode it back. The real
        // cap4 srflx is runtime-resolved from the capture, never inlined.
        let txid = *b"abcdefghijkl";
        let addr: SocketAddr = "192.0.2.81:14363".parse().unwrap();
        let value = encode_xor_mapped_for_test(addr, &txid);
        let mut msg = Vec::new();
        msg.extend_from_slice(&BINDING_SUCCESS.to_be_bytes());
        msg.extend_from_slice(&0u16.to_be_bytes());
        msg.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        msg.extend_from_slice(&txid);
        push_attr(&mut msg, ATTR_XOR_MAPPED_ADDRESS, &value);
        let len_after = (msg.len() - HEADER_LEN) as u16;
        msg[2..4].copy_from_slice(&len_after.to_be_bytes());

        let decoded = StunMessage::decode(&msg).unwrap();
        assert!(decoded.is_binding_success());
        assert_eq!(decoded.xor_mapped_address().unwrap(), Some(addr));
    }

    #[test]
    fn xor_mapped_address_ipv6_round_trip() {
        let txid = *b"0123456789ab";
        let addr: SocketAddr = "[2001:db8::1]:5000".parse().unwrap();
        let value = encode_xor_mapped_for_test(addr, &txid);
        let mut msg = Vec::new();
        msg.extend_from_slice(&BINDING_SUCCESS.to_be_bytes());
        msg.extend_from_slice(&0u16.to_be_bytes());
        msg.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        msg.extend_from_slice(&txid);
        push_attr(&mut msg, ATTR_XOR_MAPPED_ADDRESS, &value);
        let len_after = (msg.len() - HEADER_LEN) as u16;
        msg[2..4].copy_from_slice(&len_after.to_be_bytes());
        let decoded = StunMessage::decode(&msg).unwrap();
        assert_eq!(decoded.xor_mapped_address().unwrap(), Some(addr));
    }

    // ── Decode negatives ───────────────────────────────────────────────────
    #[test]
    fn decode_rejects_bad_cookie() {
        let mut bytes = synth_request(false).encode(PWD).unwrap();
        bytes[4] ^= 0xff; // corrupt the magic cookie
        assert!(matches!(
            StunMessage::decode(&bytes),
            Err(Error::Transport(_))
        ));
    }

    #[test]
    fn decode_rejects_short_buffer() {
        assert!(matches!(
            StunMessage::decode(&[0u8; 8]),
            Err(Error::Transport(_))
        ));
    }

    #[test]
    fn decode_rejects_attribute_overrun() {
        let mut bytes = synth_request(false).encode(PWD).unwrap();
        // Inflate the first attribute's length so it overruns the message.
        bytes[HEADER_LEN + 2] = 0xff;
        bytes[HEADER_LEN + 3] = 0xff;
        assert!(matches!(
            StunMessage::decode(&bytes),
            Err(Error::Transport(_))
        ));
    }

    #[test]
    fn server_query_has_fingerprint_no_credentials() {
        let q = encode_server_query(*b"qqqqqqqqqqqq", Some("3.5.5"));
        let msg = StunMessage::decode(&q).unwrap();
        assert_eq!(msg.msg_type, BINDING_REQUEST);
        assert!(msg.attr(ATTR_FINGERPRINT).is_some());
        assert!(msg.attr(ATTR_USERNAME).is_none());
        assert!(msg.attr(ATTR_MESSAGE_INTEGRITY).is_none());
    }

    // ── Binding Success responder (consent reply; RFC 7675 keepalive) ──────
    // A camera connectivity check (Binding Request keyed by OUR local pwd) is
    // answered with encode_binding_success: the response must echo the txid, carry
    // XOR-MAPPED-ADDRESS = the camera's address, and verify MESSAGE-INTEGRITY +
    // FINGERPRINT under the same local pwd. This is the offline KAT for the
    // "answer the camera's checks so it keeps streaming" path.
    #[test]
    fn binding_success_response_round_trips_and_authenticates() {
        let local_pwd = b"SyntheticLocalPwd0123456"; // secret-scan:allow (synthetic test pwd)
        let camera: SocketAddr = "192.0.2.50:43210".parse().unwrap();
        let txid = *b"camcheck1234";
        let resp = encode_binding_success(txid, camera, local_pwd).unwrap();

        let msg = StunMessage::decode(&resp).unwrap();
        assert!(msg.is_binding_success());
        assert_eq!(&msg.txid, b"camcheck1234");
        // XOR-MAPPED-ADDRESS decodes back to the camera's address.
        assert_eq!(msg.xor_mapped_address().unwrap(), Some(camera));
        // MESSAGE-INTEGRITY verifies under the local pwd, and FINGERPRINT is
        // self-consistent.
        assert!(verify_message_integrity(&resp, local_pwd).unwrap());
        let fp_off = find_attr_offset(&resp, ATTR_FINGERPRINT).unwrap().unwrap();
        let embedded = u32::from_be_bytes([
            resp[fp_off + 4],
            resp[fp_off + 5],
            resp[fp_off + 6],
            resp[fp_off + 7],
        ]);
        assert_eq!(fingerprint(&resp[..fp_off]), embedded);
    }

    // The wrong key must fail the response MESSAGE-INTEGRITY (key-binding bites).
    #[test]
    fn binding_success_wrong_key_fails_integrity() {
        let resp = encode_binding_success(
            *b"abcdefghijkl",
            "198.51.100.9:5000".parse().unwrap(),
            b"SyntheticLocalPwd0123456", // secret-scan:allow
        )
        .unwrap();
        assert!(!verify_message_integrity(&resp, b"the-wrong-ice-password00").unwrap());
        // secret-scan:allow
    }

    // The private XOR-MAPPED-ADDRESS encoder is the exact inverse of the decoder
    // for both families (used by encode_binding_success).
    #[test]
    fn xor_mapped_encode_decode_inverse() {
        for s in ["203.0.113.7:51234", "[2001:db8::1]:5000"] {
            let addr: SocketAddr = s.parse().unwrap();
            let txid = *b"0123456789ab";
            let v = super::encode_xor_mapped_address(addr, &txid);
            assert_eq!(decode_xor_mapped_address(&v, &txid).unwrap(), addr);
        }
    }

    /// Test-only XOR-MAPPED-ADDRESS encoder (the inverse of the decoder).
    fn encode_xor_mapped_for_test(addr: SocketAddr, txid: &[u8; 12]) -> Vec<u8> {
        let cookie = MAGIC_COOKIE.to_be_bytes();
        let mut v = Vec::new();
        v.push(0x00); // reserved
        let xport = addr.port() ^ ((MAGIC_COOKIE >> 16) as u16);
        match addr.ip() {
            IpAddr::V4(ip) => {
                v.push(0x01);
                v.extend_from_slice(&xport.to_be_bytes());
                let o = ip.octets();
                for i in 0..4 {
                    v.push(o[i] ^ cookie[i]);
                }
            }
            IpAddr::V6(ip) => {
                v.push(0x02);
                v.extend_from_slice(&xport.to_be_bytes());
                let mut key = [0u8; 16];
                key[..4].copy_from_slice(&cookie);
                key[4..].copy_from_slice(txid);
                let o = ip.octets();
                for i in 0..16 {
                    v.push(o[i] ^ key[i]);
                }
            }
        }
        v
    }
}
