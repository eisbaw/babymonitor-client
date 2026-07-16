#!/usr/bin/env python3
"""Conservative malformed-input probe for the owner's camera LAN services.

This is deliberately not a general-purpose fuzzer. It has a fixed case list,
accepts only a private IPv4 address, sends at most 32 bytes per connection, and
checks that known camera TCP services still accept connections after every case.
It never loads a Tuya key and none of its payloads is an authenticated or valid
Tuya command.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import socket
import stat
import sys
import time
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import BinaryIO, Callable, Sequence

MAX_PAYLOAD_BYTES = 32
MAX_RESPONSE_BYTES = 512
DEFAULT_TIMEOUT_SECONDS = 6.0
MIN_DELAY_SECONDS = 0.25
REPORT_SCHEMA = 2
REVIEWED_CASE_COUNT = 10
REVIEWED_PORTS = (554, 6000, 6668, 8684, 8687)
FORBIDDEN_RTSP_METHODS = {
    b"ANNOUNCE",
    b"PAUSE",
    b"PLAY",
    b"RECORD",
    b"SETUP",
    b"SET_PARAMETER",
    b"TEARDOWN",
}
EXPECTED_CORPUS_SHA256 = "e408e67824874b740d76c8ea2543a6e5153ed644e28005ddecd429e320909d3d"
REPO_ROOT = Path(__file__).resolve().parents[2]
PRIVATE_REPORT_ROOT = REPO_ROOT / "secrets"
RFC1918_NETWORKS = tuple(
    ipaddress.ip_network(network)
    for network in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)


@dataclass(frozen=True)
class ProbeCase:
    port: int
    name: str
    payload: bytes


@dataclass(frozen=True)
class ProbeResult:
    port: int
    case: str
    outcome: str
    payload_fully_sent: bool
    response_bytes: int
    response_sha256: str | None
    response_summary: str | None
    elapsed_ms: int
    target_listener_after: bool | None
    all_listeners_after: bool | None
    listeners_after: dict[int, bool] | None


CASES = (
    ProbeCase(554, "rtsp-invalid-method", b"FUZZ * RTSP/1.0\r\nCSeq: 1\r\n\r\n"),
    ProbeCase(554, "rtsp-truncated-request-line", b"OPTIONS "),
    ProbeCase(6000, "single-nul", b"\x00"),
    ProbeCase(6000, "short-ascii", b"A" * 16),
    ProbeCase(6668, "single-nul", b"\x00"),
    ProbeCase(6668, "invalid-magic-header", b"\xde\xad\xbe\xef" + b"\x00" * 12),
    ProbeCase(8684, "single-nul", b"\x00"),
    ProbeCase(8684, "short-high-bytes", b"\xff" * 8),
    ProbeCase(8687, "single-nul", b"\x00"),
    ProbeCase(8687, "short-high-bytes", b"\xff" * 8),
)
KNOWN_PORTS = tuple(sorted({case.port for case in CASES}))


def corpus_sha256(cases: Sequence[ProbeCase] | None = None) -> str:
    if cases is None:
        cases = CASES
    digest = hashlib.sha256()
    for case in cases:
        name = case.name.encode("utf-8")
        digest.update(case.port.to_bytes(2, "big"))
        digest.update(len(name).to_bytes(2, "big"))
        digest.update(name)
        digest.update(len(case.payload).to_bytes(2, "big"))
        digest.update(case.payload)
    return digest.hexdigest()


def private_ipv4(value: str) -> ipaddress.IPv4Address:
    """Parse a non-special RFC1918-style IPv4 target."""
    try:
        address = ipaddress.ip_address(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("target must be a numeric IPv4 address") from error
    if not isinstance(address, ipaddress.IPv4Address):
        raise argparse.ArgumentTypeError("target must be IPv4")
    containing_network = next(
        (network for network in RFC1918_NETWORKS if address in network), None
    )
    if containing_network is None:
        raise argparse.ArgumentTypeError("target must be an RFC1918 IPv4 address")
    if address in (
        containing_network.network_address,
        containing_network.broadcast_address,
    ):
        raise argparse.ArgumentTypeError("target must not be an RFC1918 network or broadcast address")
    return address


def delay_seconds(value: str) -> float:
    try:
        delay = float(value) / 1000.0
    except ValueError as error:
        raise argparse.ArgumentTypeError("delay must be a number of milliseconds") from error
    if not MIN_DELAY_SECONDS <= delay <= 5.0:
        raise argparse.ArgumentTypeError("delay must be between 250 and 5000 milliseconds")
    return delay


def timeout_seconds(value: str) -> float:
    try:
        timeout = float(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("timeout must be a number of seconds") from error
    if not 0.5 <= timeout <= 10.0:
        raise argparse.ArgumentTypeError("timeout must be between 0.5 and 10 seconds")
    return timeout


def port_accepts_connection(target: ipaddress.IPv4Address, port: int) -> bool:
    """Use a connect-only check; no application bytes are sent."""
    try:
        with socket.create_connection((str(target), port), timeout=1.5):
            return True
    except OSError:
        return False


def listener_liveness(target: ipaddress.IPv4Address) -> dict[int, bool]:
    """Check every listener in the pre-scanned baseline, not just the host."""
    return {port: port_accepts_connection(target, port) for port in KNOWN_PORTS}


def run_case(
    target: ipaddress.IPv4Address,
    case: ProbeCase,
    timeout: float,
    on_payload_sent: Callable[[], None] | None = None,
) -> tuple[str, bytes, int, bool]:
    started = time.monotonic()
    response = b""
    outcome = "transport-error"
    payload_fully_sent = False
    try:
        with socket.create_connection((str(target), case.port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(case.payload)
            payload_fully_sent = True
            if on_payload_sent is not None:
                on_payload_sent()
            try:
                response = sock.recv(MAX_RESPONSE_BYTES)
                outcome = "data" if response else "closed"
            except socket.timeout:
                outcome = "timeout"
            except ConnectionResetError:
                outcome = "reset"
    except ConnectionResetError:
        outcome = "reset"
    except OSError:
        outcome = "transport-error"
    elapsed_ms = round((time.monotonic() - started) * 1000)
    return outcome, response, elapsed_ms, payload_fully_sent


def response_summary(case: ProbeCase, response: bytes) -> str | None:
    """Retain only a bounded RTSP status line; never retain arbitrary response bytes."""
    if not response:
        return None
    if case.port != 554:
        return "binary-response"
    first_line = response.splitlines()[0][:160]
    try:
        decoded = first_line.decode("ascii")
    except UnicodeDecodeError:
        return "non-ascii-rtsp-response"
    if not decoded.startswith("RTSP/1.0 ") or not decoded.isprintable():
        return "unrecognized-rtsp-response"
    return decoded


def validate_cases() -> None:
    if len(CASES) != REVIEWED_CASE_COUNT:
        raise RuntimeError("probe corpus no longer has the reviewed case count")
    if tuple(sorted({case.port for case in CASES})) != REVIEWED_PORTS:
        raise RuntimeError("probe corpus contains an unreviewed port")
    for case in CASES:
        if not case.payload or len(case.payload) > MAX_PAYLOAD_BYTES:
            raise RuntimeError(f"unsafe payload length in case {case.name}")
        method = case.payload.split(maxsplit=1)[0].upper()
        if case.port == 554 and method in FORBIDDEN_RTSP_METHODS:
            raise RuntimeError(f"stateful RTSP method in case {case.name}")
    valid_tuya_prefixes = (b"\x00\x00\x55\xaa", b"\x00\x00\x66\x99")
    for case in CASES:
        if case.port == 6668 and case.payload.startswith(valid_tuya_prefixes):
            raise RuntimeError(f"case {case.name} starts with a valid Tuya frame magic")
    if corpus_sha256() != EXPECTED_CORPUS_SHA256:
        raise RuntimeError("probe corpus differs from the reviewed byte-for-byte manifest")


def ensure_private_directory(path: Path) -> None:
    try:
        os.mkdir(path, 0o700)
        os.chmod(path, 0o700)
    except FileExistsError:
        pass
    metadata = os.lstat(path)
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise ValueError("private report parent is not a real directory")
    if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o700:
        raise PermissionError("private report parent must be owner-owned mode 0700")


def reserve_private_report(path: Path) -> BinaryIO:
    root = Path(os.path.abspath(PRIVATE_REPORT_ROOT.expanduser()))
    resolved = Path(os.path.abspath(path.expanduser()))
    try:
        relative = resolved.relative_to(root)
    except ValueError as error:
        raise ValueError("report path must be beneath the repository's secrets/ directory") from error
    if not relative.parts:
        raise ValueError("report path must name a file beneath secrets/")

    ensure_private_directory(root)
    parent = root
    for component in relative.parts[:-1]:
        parent /= component
        ensure_private_directory(parent)

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(resolved, flags, 0o600)
    os.fchmod(fd, 0o600)
    metadata = os.fstat(fd)
    if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o600:
        os.close(fd)
        raise PermissionError("private report must be a regular owner-only file")
    return os.fdopen(fd, "wb")


def update_private_report(report_file: BinaryIO, report: dict[str, object]) -> None:
    payload = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode()
    report_file.seek(0)
    report_file.truncate(0)
    report_file.write(payload)
    report_file.flush()
    os.fsync(report_file.fileno())


def report_payload(
    args: argparse.Namespace,
    results: Sequence[ProbeResult],
    status: str,
    baseline_listeners: dict[int, bool] | None = None,
) -> dict[str, object]:
    return {
        "schema": REPORT_SCHEMA,
        "status": status,
        "target": "private-owner-camera",
        "corpus_sha256": corpus_sha256(),
        "baseline_listeners": baseline_listeners,
        "limits": {
            "max_payload_bytes": MAX_PAYLOAD_BYTES,
            "max_response_bytes": MAX_RESPONSE_BYTES,
            "delay_ms": round(args.delay_ms * 1000),
            "timeout_seconds": args.timeout_seconds,
        },
        "completed_all_cases": (
            status == "complete"
            and len(results) == len(CASES)
            and all(result.payload_fully_sent for result in results)
            and all(result.all_listeners_after for result in results)
        ),
        "results": [asdict(result) for result in results],
    }


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--target", required=True, type=private_ipv4)
    result.add_argument(
        "--confirm-owner-camera",
        action="store_true",
        help="confirm this private address is a camera you own or are authorized to test",
    )
    result.add_argument(
        "--delay-ms",
        default=0.75,
        type=delay_seconds,
        metavar="MILLISECONDS",
        help="pause after every case (250-5000 ms; default: 750)",
    )
    result.add_argument(
        "--timeout-seconds",
        default=DEFAULT_TIMEOUT_SECONDS,
        type=timeout_seconds,
        metavar="SECONDS",
        help="per-case receive timeout (0.5-10; default: 6)",
    )
    result.add_argument("--report", type=Path, help="new JSON path beneath secrets/")
    result.add_argument("--dry-run", action="store_true", help="list cases without opening sockets")
    return result


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    validate_cases()

    if args.dry_run:
        for case in CASES:
            print(f"port={case.port} case={case.name} bytes={len(case.payload)}")
        return 0

    if not args.confirm_owner_camera:
        print("refusing network probes without --confirm-owner-camera", file=sys.stderr)
        return 2

    report_file: BinaryIO | None = None
    results: list[ProbeResult] = []
    if args.report:
        try:
            report_file = reserve_private_report(args.report)
            update_private_report(report_file, report_payload(args, results, "in-progress"))
        except ValueError as error:
            if report_file is not None:
                report_file.close()
            print(f"could not write private report: {error}", file=sys.stderr)
            return 1
        except OSError:
            if report_file is not None:
                report_file.close()
            print("could not create the private report", file=sys.stderr)
            return 1

    status = "in-progress"
    baseline: dict[int, bool] | None = None
    try:
        baseline = listener_liveness(args.target)
        if report_file is not None:
            try:
                update_private_report(
                    report_file,
                    report_payload(args, results, "in-progress", baseline),
                )
            except OSError:
                status = "report-checkpoint-failed"
                print(
                    "could not checkpoint the private report; sent no probe cases",
                    file=sys.stderr,
                )
        if status == "report-checkpoint-failed":
            pass
        elif not all(baseline.values()):
            status = "preflight-liveness-failed"
            print(
                "one or more baseline camera listeners failed before the first probe; sent nothing",
                file=sys.stderr,
            )
        else:
            for case in CASES:
                result = ProbeResult(
                    port=case.port,
                    case=case.name,
                    outcome="connecting",
                    payload_fully_sent=False,
                    response_bytes=0,
                    response_sha256=None,
                    response_summary=None,
                    elapsed_ms=0,
                    target_listener_after=None,
                    all_listeners_after=None,
                    listeners_after=None,
                )
                results.append(result)
                checkpoint_failed = False
                if report_file is not None:
                    try:
                        update_private_report(
                            report_file,
                            report_payload(args, results, "in-progress", baseline),
                        )
                    except OSError:
                        checkpoint_failed = True
                        print(
                            "could not checkpoint the probe attempt; sent no case bytes",
                            file=sys.stderr,
                        )
                if checkpoint_failed:
                    status = "report-checkpoint-failed"
                    break

                def mark_payload_sent() -> None:
                    nonlocal result, checkpoint_failed
                    result = replace(
                        result,
                        outcome="awaiting-response",
                        payload_fully_sent=True,
                    )
                    results[-1] = result
                    if report_file is not None:
                        try:
                            update_private_report(
                                report_file,
                                report_payload(args, results, "in-progress", baseline),
                            )
                        except OSError:
                            checkpoint_failed = True
                            print(
                                "could not checkpoint the fully sent payload",
                                file=sys.stderr,
                            )

                outcome, response, elapsed_ms, payload_fully_sent = run_case(
                    args.target,
                    case,
                    args.timeout_seconds,
                    mark_payload_sent,
                )
                result = replace(
                    result,
                    outcome=outcome,
                    payload_fully_sent=payload_fully_sent,
                    response_bytes=len(response),
                    response_sha256=(
                        hashlib.sha256(response).hexdigest() if response else None
                    ),
                    response_summary=response_summary(case, response),
                    elapsed_ms=elapsed_ms,
                )
                results[-1] = result
                time.sleep(args.delay_ms)
                listeners_after = listener_liveness(args.target)
                target_listener_after = listeners_after[case.port]
                all_listeners_after = all(listeners_after.values())
                result = replace(
                    result,
                    target_listener_after=target_listener_after,
                    all_listeners_after=all_listeners_after,
                    listeners_after=listeners_after,
                )
                results[-1] = result
                if report_file is not None:
                    try:
                        update_private_report(
                            report_file,
                            report_payload(args, results, "in-progress", baseline),
                        )
                    except OSError:
                        checkpoint_failed = True
                        print(
                            "could not checkpoint post-probe listener state",
                            file=sys.stderr,
                        )
                print(
                    f"port={case.port} case={case.name} outcome={outcome} "
                    f"payload_fully_sent={str(payload_fully_sent).lower()} "
                    f"response_bytes={len(response)} "
                    f"target_listener_after={str(target_listener_after).lower()} "
                    f"all_listeners_after={str(all_listeners_after).lower()}"
                )
                if checkpoint_failed:
                    status = "report-checkpoint-failed"
                    print(
                        "private report checkpoint failed; aborting remaining cases",
                        file=sys.stderr,
                    )
                    break
                if outcome == "transport-error" or not payload_fully_sent:
                    status = "probe-transport-failed"
                    print("probe transport failed; aborting remaining cases", file=sys.stderr)
                    break
                if not all_listeners_after:
                    status = "liveness-failed"
                    print(
                        "listener liveness guard failed; aborting remaining cases",
                        file=sys.stderr,
                    )
                    break
            else:
                status = "complete"
    except BaseException:
        if report_file is not None:
            try:
                update_private_report(
                    report_file,
                    report_payload(args, results, "interrupted", baseline),
                )
            except OSError:
                print("could not record interrupted probe state", file=sys.stderr)
            report_file.close()
        raise

    if report_file is not None:
        try:
            update_private_report(
                report_file,
                report_payload(args, results, status, baseline),
            )
        except OSError:
            print("could not finalize the private report", file=sys.stderr)
            report_file.close()
            return 1
        report_file.close()

    return 0 if status == "complete" else 1


if __name__ == "__main__":
    raise SystemExit(main())
