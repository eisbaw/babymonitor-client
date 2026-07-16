# Owner SCD921 LAN network surface

This note records the bounded, owner-authorized discovery and malformed-input
run from TASK-0127.01. Raw scan reports and fuzz metadata remain in gitignored
`secrets/camera_surface/`; addresses, full MACs, and response bytes are not
reproduced here. It is a surface map, not a claim that every listener is an
application API. **Confidence: likely.** Evidence:
`secrets/camera_surface/tcp_all.nmap:1` and
`re/scripts/camera_surface_probe.py:1`.

## Scope and safety boundary

The scan covered one camera selected from the key-proven private LAN config.
Discovery was rate-limited; malformed inputs were drawn from a fixed list, were
at most 32 bytes, and never began with a valid Tuya 3.x magic. The harness checks
every listener in the pre-scan baseline, including the fuzzed listener, before
the corpus and after every case; it stops immediately if any check fails. It
contains no `localKey`, authenticated Tuya command, OTA request, recognized RTSP
state-changing method, or datapoint write. The exact reviewed corpus is pinned by
SHA-256. **Confidence: confirmed.** Evidence:
`validate_cases` in `re/scripts/camera_surface_probe.py:205` and
`test_validator_rejects_any_unreviewed_corpus_change` in
`re/scripts/test_camera_surface_probe.py:28`.

This is deliberately shallow fuzzing. Staying reachable after ten small invalid
inputs does not establish memory safety, protocol correctness, or resistance to
a larger corpus. In particular, the 6000/8684/8687 grammars are unknown: NUL and
`ff` are not recognized state-changing commands, but their non-mutation cannot be
proven until the handlers are recovered from firmware. The harness did not read
back application state; listener reachability is its only post-case observation.
**Confidence: likely.** Evidence:
`secrets/camera_surface/fuzz_bounded_20260717_v2.json:1`.

## Host identity and scan controls

Direct ARP returned the same private NIC previously associated with the camera;
the full address and MAC are withheld. Reverse DNS supplied an unrelated
corporate hostname, so it was not used as an identity signal. A second scan that
used direct layer-2 discovery reproduced the camera MAC and one-hop topology.
**Confidence: likely.** Evidence:
`secrets/camera_surface/os_fingerprint_l2.nmap:1`.

The apparent UDP DNS listener is also excluded. A control CHAOS query returned
an unrelated corporate resolver hostname, demonstrating transparent DNS
interception rather than a camera service. The only other non-closed UDP results
were `open|filtered`, which is inconclusive when no application response is
received.
**Confidence: likely.** Evidence:
`secrets/camera_surface/udp_targeted.nmap:1` and
`secrets/camera_surface/dns_interception_control.typescript:1`.

## Confirmed TCP exposure

The complete TCP connect scan found five listeners and one deliberately sampled
closed port used to improve OS fingerprinting. Nmap's name column is not protocol
proof: its `X11` and `IRC` labels are default/service-detection guesses that
conflict with the live and static evidence below. **Confidence: confirmed.**
Evidence: `secrets/camera_surface/tcp_all.nmap:1` and
`secrets/camera_surface/os_fingerprint_l2.nmap:1`.

| TCP port | What is established | What is not established |
|---:|---|---|
| 554 | An RTSP parser answers malformed requests with RTSP status lines. | No working media URL, advertised method set, or authentication scheme. |
| 6000 | An unknown binary listener returned a 27-byte response to one tiny invalid case. | It is not evidenced as X11, HTTP, TLS, or Tuya LAN. |
| 6668 | The key-proven Tuya LAN carrier used by this project. | It carries signaling/control frames, not the A/V media stream itself. |
| 8684 | TCP accepts connections and silently ignored both tiny invalid cases. | Protocol, authentication, and purpose are unknown. |
| 8687 | TCP accepts connections and silently ignored both tiny invalid cases. | Protocol, authentication, and purpose are unknown. |

### RTSP listener on 554

`FUZZ * RTSP/1.0` returned `RTSP/1.0 405 Bad Method Not Allowed request`; a
syntactically partial request was closed. The schema-2 report retains only that
bounded status line, not headers or arbitrary response bytes. This confirms a
parser, not a usable stream endpoint. Brute-forcing URL paths was intentionally
deferred until a firmware string or parent-unit capture gives a grounded path
candidate. **Confidence: likely.** Evidence:
`secrets/camera_surface/fuzz_bounded_20260717_v2.json:1` and
`response_summary` in `re/scripts/camera_surface_probe.py:189`.

### Unknown binary listener on 6000

A one-byte invalid input produced a 27-byte response, while a later 16-byte ASCII
case timed out. The retained report deliberately records only the response class,
length, and digest, so its binary grammar cannot be inferred from this artifact.
Response timing was inconsistent, so even “one request gives one rejection” is
not established. **Confidence: likely.** Evidence:
`secrets/camera_surface/fuzz_bounded_20260717_v2.json:1`.

No exact `6000` camera-listener binding was found in the app-side SDK. Literal
Java hits resolve to device-replacement error codes, timeouts, and Tuya gateway
broadcast parameters, not an implementation of this camera listener. The
Android native libraries are phone-side client code. This leaves firmware RE as
the appropriate next step. **Confidence: likely.** Evidence:
`decompiled/jadx/sources/com/thingclips/sdk/device/qdpppbq.java:24` and
`decompiled/jadx/sources/com/thingclips/smart/android/hardware/service/GwBroadcastMonitorService.java:1357`.

### Tuya LAN listener on 6668

This is the only listener with a complete protocol and authentication mapping.
The APK binds Tuya LAN to 6668 and sends camera signaling as
`IPC_LAN_302` frame type 32. The existing client has already completed a
key-confirming owner-camera exchange over this listener. Both invalid fuzz cases
were ignored and the service stayed reachable; that is rejection behavior, not
an authentication bypass. **Confidence: confirmed.** Evidence:
`decompiled/jadx/sources/com/thingclips/sdk/hardware/pdqdqbd.java:24` and
`decompiled/jadx/sources/com/thingclips/sdk/hardware/enums/FrameTypeEnum.java:33`;
the live key proof is recorded in `re/live_stream_run.md:103`.

### Unknown listeners on 8684 and 8687

Neither listener returned bytes for a single NUL or eight `ff` bytes, and both
remained reachable. No exact app-side binding or protocol marker was found, so
PPCS, RTSP, Tuya, and “camera API” labels would all be guesses. **Confidence:
likely.** Evidence: `secrets/camera_surface/fuzz_bounded_20260717_v2.json:1`.

That negative binding check was scoped to exact `6000`, `8684`, and `8687`
numeric tokens in the decompiled APK Java/resources and the existing camera/P2P
native-analysis outputs. It cannot inspect the missing camera firmware. The APK
text portion is reproducible with:

```sh
rg -n -P --glob '*.java' --glob '*.xml' \
  '(?<![0-9])(6000|8684|8687)(?![0-9])' \
  decompiled/jadx/sources decompiled/jadx/resources
```

## Bounded malformed-input result

The first retained report used schema 1 and only an aggregate 554-or-6668
liveness boolean; it is historical and does not support per-listener survival.
After review, the owner-authorized corpus was rerun with schema 2. That run
completed all ten fixed cases with a 750 ms inter-case delay, a 6-second receive
timeout, and a 512-byte response cap. Its baseline and all ten post-case sweeps
record every one of the five listeners as reachable, and every payload as fully
sent. The connect-only guard cannot exclude a very fast process restart between
checks. This is a negative smoke test, not a security assessment. **Confidence:
confirmed.** Evidence:
`secrets/camera_surface/fuzz_bounded_20260717_v2.json:1` and
`listener_liveness` in `re/scripts/camera_surface_probe.py:152`.

Reproduce the offline safety checks and inspect the exact corpus before touching
the network:

```sh
nix-shell --run 'python3 re/scripts/test_camera_surface_probe.py'
nix-shell --run 'python3 re/scripts/camera_surface_probe.py --target CAMERA_IP --dry-run'
```

Run against an owned/authorized private camera and keep the report untracked:

```sh
nix-shell --run 'python3 re/scripts/camera_surface_probe.py \
  --target CAMERA_IP --confirm-owner-camera \
  --report secrets/camera_surface/fuzz-report.json'
```

Schema 2 records the reviewed corpus hash, baseline and per-case listener maps,
full-payload-send state, bounded response metadata, completion status, and
interruption checkpoints. The writer pre-reserves a mode-0600 file beneath
owner-owned mode-0700 directories, rejects the `secrets/` root itself, and never
overwrites an existing report. **Confidence: confirmed.** Evidence:
`reserve_private_report` in `re/scripts/camera_surface_probe.py:237` and
`test_private_report_is_mode_0600_and_no_clobber` in
`re/scripts/test_camera_surface_probe.py:132`.

## OS and chipset verdict

Direct layer-2 Nmap fingerprinting classifies the device as Linux 3.10–4.11,
one hop away. Nmap OS matching is approximate, so this supports “embedded Linux”
but not a precise kernel build. **Confidence: likely.** Evidence:
`secrets/camera_surface/os_fingerprint_l2.nmap:1`.

The chipset remains **unknown**. Nmap's bundled OUI database maps the NIC prefix
to Belkin, which can identify a network module/vendor assignment but not the main
SoC. Retained cloud metadata names only `Main Module` and `MCU Module`; the camera
capability and working media-path evidence establishes H.264 and KCP, but none of
those facts names a CPU architecture or silicon vendor. **Confidence: likely.**
Evidence: `secrets/tuya_firmware_info.json:1`, `re/streaming_mode.md:170`, and
`re/streaming_mode.md:192`.

The vendor-string search was scoped to the decompiled APK Java/resources and
the extracted Android native/Ghidra outputs. It does not include camera firmware,
because no image was obtained. Hits in generic Android compatibility code were
discarded as phone-side evidence; the APK's AArch64 ELFs likewise execute on the
phone and cannot identify the camera CPU. **Confidence: likely.** Evidence:
the Android split provenance in `re/native_libs.md:3` and the missing-image result
in `re/firmware_ota.md:19`.

The scoped search is reproducible with:

```sh
rg -a -i \
  '(hisilicon|ingenic|sigmastar|rockchip|allwinner|goke|fullhan|anyka|novatek|ambarella)' \
  decompiled/jadx decompiled/nativelibs decompiled/ghidra_*
```

The shortest defensible route to a chip identification is a firmware image with
boot strings/device-tree data, a serial boot log, or a board inspection with
package markings. Network port behavior alone is insufficient.

## Next evidence-producing steps

1. Acquire or dump the main firmware, then search the kernel banner, device tree,
   bootloader environment, and `/proc/cpuinfo`-style strings.
2. Capture parent-unit traffic to ground an RTSP URL/path before sending further
   read-only `DESCRIBE` requests.
3. Correlate 6000/8684/8687 from firmware socket bindings before expanding the
   malformed corpus. Treat silence as unknown, not as proof of security.

These steps intentionally prioritize evidence that can name the implementation
behind each listener. **Confidence: likely.** Evidence:
`re/firmware_ota.md:1` and `re/scripts/camera_surface_probe.py:1`.
