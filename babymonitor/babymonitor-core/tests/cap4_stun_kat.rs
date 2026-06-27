//! cap4 **real-STUN** known-answer test (KAT) — LOCAL-ONLY, `#[ignore]`d.
//!
//! Drives the committed STUN codec ([`babymonitor_core::stream::media::stun`])
//! against the **real cap4 media capture** and proves it interoperates with the
//! camera's actual ICE, two ways:
//!
//! 1. **Decode** — our [`StunMessage::decode`] parses a real cap4 ICE
//!    connectivity-check Binding Request (type, transaction id, the
//!    PRIORITY/ICE-CONTROLLING/SOFTWARE/USERNAME/MESSAGE-INTEGRITY/FINGERPRINT
//!    attributes).
//! 2. **Encode KAT** — our [`stun::message_integrity`] (HMAC-SHA1, keyed by the
//!    **camera/answer** ICE password recovered at runtime from the capture's SDPs)
//!    and [`stun::fingerprint`] (CRC-32 ^ `0x5354554e`) reproduce that real
//!    packet's MESSAGE-INTEGRITY + FINGERPRINT bytes **EXACTLY**, and
//!    [`BindingRequest::encode`] reproduces the whole packet **byte-for-byte**.
//!
//! A third test decodes a real Binding Success response's XOR-MAPPED-ADDRESS to a
//! valid public srflx candidate (the remote/NAT half of ICE, AC#1).
//!
//! ## Why `#[ignore]`d (mirrors `cap4_replay.rs`)
//! The inputs are the gitignored, highly-sensitive cap4 capture
//! (`emulator_captures/cap4/media.pcap` + `media_meta.jsonl`): real ICE creds, the
//! camera's LAN IP, and the user's public IP. This test **reads them at runtime**;
//! it never inlines an ICE password / address / ufrag (the test source is
//! tracked). It is `#[ignore]`d so `just e2e` / CI never need the files, and
//! `assert-offline` can still enumerate it without them. Run it explicitly:
//!
//! ```text
//! cargo test -p babymonitor-core --test cap4_stun_kat -- --ignored --nocapture
//! ```

use std::path::{Path, PathBuf};

use babymonitor_core::stream::media::stun::{
    self, BindingRequest, IceRole, StunMessage, ATTR_FINGERPRINT, ATTR_ICE_CONTROLLED,
    ATTR_ICE_CONTROLLING, ATTR_MESSAGE_INTEGRITY, ATTR_PRIORITY, ATTR_SOFTWARE, ATTR_USERNAME,
    ATTR_USE_CANDIDATE, BINDING_REQUEST, MESSAGE_INTEGRITY_LEN,
};

/// The camera's LAN IP in cap4 (the host candidate the checks target).
const CAM_IP: &str = "192.0.2.184";
/// STUN magic cookie at payload `[4..8]`.
const STUN_COOKIE: [u8; 4] = [0x21, 0x12, 0xa4, 0x42];

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crate is two levels below the repo root")
        .to_path_buf()
}
fn pcap_path() -> PathBuf {
    repo_root().join("emulator_captures/cap4/media.pcap")
}
fn meta_path() -> PathBuf {
    repo_root().join("emulator_captures/cap4/media_meta.jsonl")
}

fn inputs_present() -> bool {
    for p in [pcap_path(), meta_path()] {
        if !p.exists() {
            eprintln!(
                "cap4_stun_kat: SKIP — missing local-only input {} (gitignored; see CLAUDE.md)",
                p.display()
            );
            return false;
        }
    }
    true
}

/// Minimal classic-pcap record reader (same shape as `cap4_replay.rs`).
fn parse_pcap(data: &[u8]) -> Vec<&[u8]> {
    assert!(data.len() >= 24, "pcap shorter than its 24-byte header");
    let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let le = matches!(magic, 0xa1b2_c3d4 | 0xa1b2_3c4d);
    assert!(
        le,
        "expected a little-endian classic pcap (cap4 is 0xa1b2c3d4)"
    );
    let mut out = Vec::new();
    let mut off = 24usize;
    while off + 16 <= data.len() {
        let incl =
            u32::from_le_bytes([data[off + 8], data[off + 9], data[off + 10], data[off + 11]])
                as usize;
        off += 16;
        if off + incl > data.len() {
            break;
        }
        out.push(&data[off..off + incl]);
        off += incl;
    }
    out
}

/// Decode one LINKTYPE_LINUX_SLL2 (276) frame → (dst IPv4 dotted, UDP payload).
fn sll2_udp(frame: &[u8]) -> Option<(String, &[u8])> {
    if frame.len() < 20 || u16::from_be_bytes([frame[0], frame[1]]) != 0x0800 {
        return None;
    }
    let ip = &frame[20..];
    if ip.len() < 20 || ip[0] >> 4 != 4 || ip[9] != 17 {
        return None;
    }
    let ihl = (ip[0] & 0x0f) as usize * 4;
    let udp = ip.get(ihl..)?;
    if udp.len() < 8 {
        return None;
    }
    let dst = format!("{}.{}.{}.{}", ip[16], ip[17], ip[18], ip[19]);
    Some((dst, &udp[8..]))
}

/// One walked STUN attribute: (type, attribute offset, value offset, value len).
fn walk_attrs(pkt: &[u8]) -> Vec<(u16, usize, usize, usize)> {
    let mut out = Vec::new();
    let length = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
    let end = (20 + length).min(pkt.len());
    let mut o = 20;
    while o + 4 <= end {
        let t = u16::from_be_bytes([pkt[o], pkt[o + 1]]);
        let l = u16::from_be_bytes([pkt[o + 2], pkt[o + 3]]) as usize;
        if o + 4 + l > end {
            break;
        }
        out.push((t, o, o + 4, l));
        o = (o + 4 + l + 3) & !3;
    }
    out
}

/// Find the camera-bound ICE connectivity-check Binding Request in the capture:
/// dst == camera IP, STUN magic cookie, type Binding Request, with USERNAME +
/// MESSAGE-INTEGRITY + FINGERPRINT. Returns the raw STUN packet bytes.
fn first_camera_ice_check(records: &[&[u8]]) -> Option<Vec<u8>> {
    for &frame in records {
        let Some((dst, pl)) = sll2_udp(frame) else {
            continue;
        };
        if dst != CAM_IP || pl.len() < 20 || pl[4..8] != STUN_COOKIE {
            continue;
        }
        if u16::from_be_bytes([pl[0], pl[1]]) != BINDING_REQUEST {
            continue;
        }
        let attrs = walk_attrs(pl);
        let has = |t: u16| attrs.iter().any(|a| a.0 == t);
        if has(ATTR_USERNAME) && has(ATTR_MESSAGE_INTEGRITY) && has(ATTR_FINGERPRINT) {
            return Some(pl.to_vec());
        }
    }
    None
}

/// Recover the ICE password paired with `ufrag` from the capture's SDPs (read at
/// runtime from `media_meta.jsonl`; never inlined). The SDP places `a=ice-pwd:`
/// immediately after the matching `a=ice-ufrag:` line, so we locate the ufrag and
/// read the following password value (base64-ish charset).
fn ice_pwd_for_ufrag(meta: &str, ufrag: &str) -> Option<String> {
    let needle = format!("a=ice-ufrag:{ufrag}");
    let start = meta.find(&needle)?;
    let pwd_key = "a=ice-pwd:";
    let rel = meta[start..].find(pwd_key)?;
    let after = start + rel + pwd_key.len();
    let pwd: String = meta[after..]
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '+' || *c == '/')
        .collect();
    if pwd.is_empty() {
        None
    } else {
        Some(pwd)
    }
}

#[test]
#[ignore = "local-only: needs the gitignored cap4 capture + meta under emulator_captures/cap4"]
fn cap4_ice_check_decode_and_reencode_kat() {
    if !inputs_present() {
        return;
    }
    let pcap = std::fs::read(pcap_path()).expect("read pcap");
    let records = parse_pcap(&pcap);
    let pkt = first_camera_ice_check(&records)
        .expect("a camera-bound ICE connectivity-check Binding Request in cap4");
    let meta = std::fs::read_to_string(meta_path()).expect("read media_meta");

    // ── (a) DECODE: our parser reads the real Binding Request structure ──────
    let msg = StunMessage::decode(&pkt).expect("decode real cap4 Binding Request");
    assert_eq!(msg.msg_type, BINDING_REQUEST, "type = Binding Request");
    assert_eq!(&msg.txid, &pkt[8..20], "transaction id round-trips");
    let username = msg.attr(ATTR_USERNAME).expect("USERNAME present").to_vec();
    assert!(msg.attr(ATTR_MESSAGE_INTEGRITY).is_some());
    assert!(msg.attr(ATTR_FINGERPRINT).is_some());
    assert!(msg.attr(ATTR_PRIORITY).is_some());

    // USERNAME = "<remoteUfrag>:<localUfrag>"; the camera's pwd keys the HMAC.
    let username_str = std::str::from_utf8(&username).expect("ascii USERNAME");
    let remote_ufrag = username_str
        .split(':')
        .next()
        .expect("USERNAME has a remote part");
    let camera_pwd = ice_pwd_for_ufrag(&meta, remote_ufrag)
        .expect("camera (answer) ICE pwd recovered from cap4 SDPs");
    let key = camera_pwd.as_bytes();

    // Locate the MESSAGE-INTEGRITY and FINGERPRINT attribute offsets.
    let attrs = walk_attrs(&pkt);
    let mi_off = attrs
        .iter()
        .find(|a| a.0 == ATTR_MESSAGE_INTEGRITY)
        .map(|a| a.1)
        .expect("MI offset");
    let fp_off = attrs
        .iter()
        .find(|a| a.0 == ATTR_FINGERPRINT)
        .map(|a| a.1)
        .expect("FP offset");

    // ── (b) KAT: our primitives reproduce the REAL MI + FP bytes exactly ─────
    let real_mi = &pkt[mi_off + 4..mi_off + 4 + MESSAGE_INTEGRITY_LEN];
    let calc_mi = stun::message_integrity(&pkt[..mi_off], key).expect("compute MI");
    assert_eq!(
        calc_mi.as_slice(),
        real_mi,
        "MESSAGE-INTEGRITY (HMAC-SHA1, camera pwd) must match the real packet byte-for-byte"
    );

    let real_fp = u32::from_be_bytes([
        pkt[fp_off + 4],
        pkt[fp_off + 5],
        pkt[fp_off + 6],
        pkt[fp_off + 7],
    ]);
    let calc_fp = stun::fingerprint(&pkt[..fp_off]);
    assert_eq!(
        calc_fp, real_fp,
        "FINGERPRINT (CRC-32 ^ 0x5354554e) must match the real packet"
    );

    // ── (bonus) FULL byte-exact re-encode through BindingRequest::encode ─────
    // Extract the real field values (in the capture's attribute order) and prove
    // the encoder reproduces the WHOLE 100-byte packet, not just MI/FP.
    let priority = {
        let v = msg.attr(ATTR_PRIORITY).unwrap();
        u32::from_be_bytes([v[0], v[1], v[2], v[3]])
    };
    let role = if let Some(v) = msg.attr(ATTR_ICE_CONTROLLING) {
        IceRole::Controlling(u64::from_be_bytes(v.try_into().unwrap()))
    } else {
        let v = msg.attr(ATTR_ICE_CONTROLLED).expect("a role attribute");
        IceRole::Controlled(u64::from_be_bytes(v.try_into().unwrap()))
    };
    // SOFTWARE: pass the EXACT value bytes (this camera declares the trailing
    // padding nulls as part of the value, length 8 not 5) so the re-encode is
    // byte-exact.
    let software = msg
        .attr(ATTR_SOFTWARE)
        .map(|v| String::from_utf8(v.to_vec()).expect("utf8 SOFTWARE"));
    let use_candidate = msg.attr(ATTR_USE_CANDIDATE).is_some();
    let mut txid = [0u8; 12];
    txid.copy_from_slice(&pkt[8..20]);

    let req = BindingRequest {
        txid,
        username: username_str.to_string(),
        priority,
        role,
        use_candidate,
        software,
    };
    let reencoded = req.encode(key).expect("re-encode");
    assert_eq!(
        reencoded, pkt,
        "BindingRequest::encode must reproduce the real cap4 Binding Request byte-for-byte"
    );

    eprintln!(
        "cap4 STUN KAT: decoded + byte-exact re-encoded a real {}-byte ICE check \
         (MI+FINGERPRINT reproduced under the camera ICE pwd); use_candidate={use_candidate}",
        pkt.len()
    );
}

#[test]
#[ignore = "local-only: needs the gitignored cap4 capture under emulator_captures/cap4"]
fn cap4_binding_success_yields_srflx() {
    if !inputs_present() {
        return;
    }
    let pcap = std::fs::read(pcap_path()).expect("read pcap");
    let records = parse_pcap(&pcap);

    // Find the first Binding Success Response carrying an XOR-MAPPED-ADDRESS.
    let mut srflx = None;
    for &frame in &records {
        let Some((_dst, pl)) = sll2_udp(frame) else {
            continue;
        };
        if pl.len() < 20 || pl[4..8] != STUN_COOKIE {
            continue;
        }
        if u16::from_be_bytes([pl[0], pl[1]]) != stun::BINDING_SUCCESS {
            continue;
        }
        let msg = match StunMessage::decode(pl) {
            Ok(m) => m,
            Err(_) => continue,
        };
        if let Ok(Some(addr)) = msg.xor_mapped_address() {
            srflx = Some(addr);
            break;
        }
    }

    let addr = srflx.expect("a Binding Success with XOR-MAPPED-ADDRESS in cap4");
    // Structural assertions ONLY — never print the address (the user's public IP).
    assert!(addr.is_ipv4(), "the cap4 srflx is IPv4");
    assert_ne!(addr.port(), 0, "srflx has a non-zero reflected port");
    if let std::net::IpAddr::V4(ip) = addr.ip() {
        // A reflected srflx must be a routable (non-private/loopback) address.
        assert!(
            !ip.is_private() && !ip.is_loopback() && !ip.is_unspecified(),
            "the reflected srflx must be a public address"
        );
    }
    eprintln!("cap4 STUN srflx: decoded a public XOR-MAPPED-ADDRESS (value withheld — PII)");
}
