#!/usr/bin/env python3
"""Offline safety tests for camera_surface_probe.py."""

from __future__ import annotations

import argparse
import io
import json
import os
import stat
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import camera_surface_probe as probe


class CameraSurfaceProbeTests(unittest.TestCase):
    def test_cases_are_nonempty_and_bounded(self) -> None:
        probe.validate_cases()
        self.assertTrue(probe.CASES)
        self.assertTrue(all(0 < len(case.payload) <= 32 for case in probe.CASES))
        self.assertEqual(probe.corpus_sha256(), probe.EXPECTED_CORPUS_SHA256)

    def test_validator_rejects_any_unreviewed_corpus_change(self) -> None:
        variants = {
            "empty": (),
            "oversized": (
                replace(probe.CASES[0], payload=b"A" * 33),
                *probe.CASES[1:],
            ),
            "valid-tuya-magic": (
                *probe.CASES[:4],
                replace(probe.CASES[4], payload=b"\x00\x00\x55\xaa"),
                *probe.CASES[5:],
            ),
            "stateful-rtsp": (
                replace(probe.CASES[0], payload=b"PLAY * RTSP/1.0\r\n\r\n"),
                *probe.CASES[1:],
            ),
            "unreviewed-port": (
                replace(probe.CASES[0], port=1234),
                *probe.CASES[1:],
            ),
            "byte-change": (
                replace(probe.CASES[0], payload=b"NOPE * RTSP/1.0\r\nCSeq: 1\r\n\r\n"),
                *probe.CASES[1:],
            ),
        }
        for name, cases in variants.items():
            with self.subTest(name=name), patch.object(probe, "CASES", cases):
                with self.assertRaises(RuntimeError):
                    probe.validate_cases()

    def test_tuya_port_cases_never_start_with_valid_magic(self) -> None:
        valid_magic = (b"\x00\x00\x55\xaa", b"\x00\x00\x66\x99")
        for case in probe.CASES:
            if case.port == 6668:
                self.assertFalse(case.payload.startswith(valid_magic))

    def test_target_must_be_private_ipv4(self) -> None:
        for valid in ("10.0.0.1", "172.16.0.1", "192.168.1.2"):
            with self.subTest(valid=valid):
                self.assertEqual(str(probe.private_ipv4(valid)), valid)
        for invalid in (
            "127.0.0.1",
            "169.254.1.1",
            "192.0.0.1",
            "192.0.2.1",
            "100.64.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "240.0.0.1",
            "10.0.0.0",
            "10.255.255.255",
            "8.8.8.8",
            "::1",
            "camera.local",
        ):
            with self.subTest(invalid=invalid), self.assertRaises(argparse.ArgumentTypeError):
                probe.private_ipv4(invalid)

    def test_dry_run_needs_no_authorization_and_opens_no_socket(self) -> None:
        output = io.StringIO()
        with (
            redirect_stdout(output),
            patch.object(probe, "listener_liveness") as liveness,
            patch.object(probe, "run_case") as run_case,
        ):
            status = probe.main(["--target", "192.168.1.2", "--dry-run"])
        self.assertEqual(status, 0)
        self.assertEqual(len(output.getvalue().splitlines()), len(probe.CASES))
        liveness.assert_not_called()
        run_case.assert_not_called()

    def test_live_mode_without_confirmation_opens_no_report_or_socket(self) -> None:
        errors = io.StringIO()
        with (
            patch.object(probe, "reserve_private_report") as reserve,
            patch.object(probe, "listener_liveness") as liveness,
            patch.object(probe, "run_case") as run_case,
            redirect_stderr(errors),
        ):
            status = probe.main(
                [
                    "--target",
                    "192.168.1.2",
                    "--report",
                    "secrets/should-not-exist.json",
                ]
            )
        self.assertEqual(status, 2)
        reserve.assert_not_called()
        liveness.assert_not_called()
        run_case.assert_not_called()

    def test_liveness_checks_every_baseline_listener(self) -> None:
        target = probe.private_ipv4("192.168.1.2")
        with patch.object(
            probe,
            "port_accepts_connection",
            side_effect=lambda _target, port: port != 6000,
        ) as check:
            result = probe.listener_liveness(target)
        self.assertEqual(tuple(result), probe.KNOWN_PORTS)
        self.assertFalse(result[6000])
        self.assertEqual(check.call_count, len(probe.KNOWN_PORTS))

    def test_private_report_is_mode_0600_and_no_clobber(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            report_path = root / "nested" / "run" / "report.json"
            with patch.object(probe, "PRIVATE_REPORT_ROOT", root):
                previous_umask = os.umask(0)
                try:
                    report_file = probe.reserve_private_report(report_path)
                    probe.update_private_report(report_file, {"target": "redacted"})
                    report_file.close()
                finally:
                    os.umask(previous_umask)
                self.assertEqual(json.loads(report_path.read_text()), {"target": "redacted"})
                mode = stat.S_IMODE(report_path.stat().st_mode)
                self.assertEqual(mode, 0o600)
                self.assertEqual(stat.S_IMODE((root / "nested").stat().st_mode), 0o700)
                self.assertEqual(stat.S_IMODE((root / "nested" / "run").stat().st_mode), 0o700)
                with self.assertRaises(FileExistsError):
                    probe.reserve_private_report(report_path)

    def test_private_report_rejects_path_outside_secrets_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            with patch.object(probe, "PRIVATE_REPORT_ROOT", root / "secrets"):
                with self.assertRaises(ValueError):
                    probe.reserve_private_report(root / "public.json")

    def test_private_report_rejects_secrets_root_as_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve() / "secrets"
            with patch.object(probe, "PRIVATE_REPORT_ROOT", root):
                with self.assertRaises(ValueError):
                    probe.reserve_private_report(root)
            self.assertFalse(root.exists())

    def test_response_summary_retains_only_rtsp_status_line(self) -> None:
        rtsp_case = probe.CASES[0]
        response = b"RTSP/1.0 405 Bad Method Not Allowed request\r\nDate: private\r\n\r\n"
        self.assertEqual(
            probe.response_summary(rtsp_case, response),
            "RTSP/1.0 405 Bad Method Not Allowed request",
        )
        self.assertEqual(
            probe.response_summary(probe.CASES[2], b"secret-binary"),
            "binary-response",
        )
        self.assertIsNone(probe.response_summary(rtsp_case, b""))

    def test_bad_report_path_opens_no_network_socket(self) -> None:
        errors = io.StringIO()
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.object(probe, "PRIVATE_REPORT_ROOT", Path(directory) / "secrets"),
            patch.object(probe, "listener_liveness") as liveness,
            patch.object(probe, "run_case") as run_case,
            redirect_stdout(io.StringIO()),
            redirect_stderr(errors),
        ):
            status = probe.main(
                [
                    "--target",
                    "192.168.1.2",
                    "--confirm-owner-camera",
                    "--report",
                    str(Path(directory) / "outside.json"),
                ]
            )
        self.assertEqual(status, 1)
        liveness.assert_not_called()
        run_case.assert_not_called()

    def test_existing_report_opens_no_network_socket(self) -> None:
        errors = io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            report_path = root / "report.json"
            report_path.write_text("existing")
            with (
                patch.object(probe, "PRIVATE_REPORT_ROOT", root),
                patch.object(probe, "listener_liveness") as liveness,
                patch.object(probe, "run_case") as run_case,
                redirect_stdout(io.StringIO()),
                redirect_stderr(errors),
            ):
                status = probe.main(
                    [
                        "--target",
                        "192.168.1.2",
                        "--confirm-owner-camera",
                        "--report",
                        str(report_path),
                    ]
                )
        self.assertEqual(status, 1)
        liveness.assert_not_called()
        run_case.assert_not_called()

    def test_transport_failure_aborts_and_cannot_report_complete(self) -> None:
        all_live = {port: True for port in probe.KNOWN_PORTS}
        errors = io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            report_path = root / "transport.json"
            with (
                patch.object(probe, "PRIVATE_REPORT_ROOT", root),
                patch.object(probe, "listener_liveness", return_value=all_live),
                patch.object(
                    probe,
                    "run_case",
                    return_value=("transport-error", b"", 1, False),
                ) as run_case,
                patch.object(probe.time, "sleep"),
                redirect_stdout(io.StringIO()),
                redirect_stderr(errors),
            ):
                status = probe.main(
                    [
                        "--target",
                        "192.168.1.2",
                        "--confirm-owner-camera",
                        "--report",
                        str(report_path),
                    ]
                )
            report = json.loads(report_path.read_text())
            self.assertEqual(report["schema"], 2)
            self.assertEqual(report["corpus_sha256"], probe.EXPECTED_CORPUS_SHA256)
            self.assertEqual(report["status"], "probe-transport-failed")
            self.assertFalse(report["completed_all_cases"])
            self.assertFalse(report["results"][0]["payload_fully_sent"])
            self.assertEqual(len(report["results"]), 1)
            self.assertEqual(status, 1)
            self.assertEqual(run_case.call_count, 1)

    def test_preflight_listener_loss_sends_no_probe_and_is_recorded(self) -> None:
        one_down = {port: True for port in probe.KNOWN_PORTS}
        one_down[8684] = False
        errors = io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            report_path = root / "preflight.json"
            with (
                patch.object(probe, "PRIVATE_REPORT_ROOT", root),
                patch.object(probe, "listener_liveness", return_value=one_down),
                patch.object(probe, "run_case") as run_case,
                redirect_stdout(io.StringIO()),
                redirect_stderr(errors),
            ):
                status = probe.main(
                    [
                        "--target",
                        "192.168.1.2",
                        "--confirm-owner-camera",
                        "--report",
                        str(report_path),
                    ]
                )
            report = json.loads(report_path.read_text())
            self.assertEqual(status, 1)
            run_case.assert_not_called()
            self.assertEqual(report["status"], "preflight-liveness-failed")
            self.assertFalse(report["baseline_listeners"]["8684"])
            self.assertEqual(report["results"], [])

    def test_success_checks_every_listener_after_every_case(self) -> None:
        all_live = {port: True for port in probe.KNOWN_PORTS}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            report_path = root / "complete.json"
            with (
                patch.object(probe, "PRIVATE_REPORT_ROOT", root),
                patch.object(
                    probe,
                    "listener_liveness",
                    return_value=all_live,
                ) as liveness,
                patch.object(
                    probe,
                    "run_case",
                    return_value=("timeout", b"", 1, True),
                ) as run_case,
                patch.object(probe.time, "sleep"),
                redirect_stdout(io.StringIO()),
                redirect_stderr(io.StringIO()),
            ):
                status = probe.main(
                    [
                        "--target",
                        "192.168.1.2",
                        "--confirm-owner-camera",
                        "--report",
                        str(report_path),
                    ]
                )
            report = json.loads(report_path.read_text())
            self.assertEqual(status, 0)
            self.assertEqual(run_case.call_count, len(probe.CASES))
            self.assertEqual(liveness.call_count, len(probe.CASES) + 1)
            self.assertEqual(report["schema"], 2)
            self.assertEqual(report["status"], "complete")
            self.assertTrue(report["completed_all_cases"])
            self.assertEqual(report["corpus_sha256"], probe.EXPECTED_CORPUS_SHA256)
            self.assertTrue(all(report["baseline_listeners"].values()))
            self.assertEqual(len(report["results"]), len(probe.CASES))

    def test_any_listener_loss_aborts_after_current_case(self) -> None:
        all_live = {port: True for port in probe.KNOWN_PORTS}
        one_down = dict(all_live)
        one_down[554] = False
        errors = io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            report_path = root / "liveness.json"
            with (
                patch.object(probe, "PRIVATE_REPORT_ROOT", root),
                patch.object(
                    probe,
                    "listener_liveness",
                    side_effect=(all_live, one_down),
                ),
                patch.object(
                    probe,
                    "run_case",
                    return_value=("timeout", b"", 1, True),
                ) as run_case,
                patch.object(probe.time, "sleep"),
                redirect_stdout(io.StringIO()),
                redirect_stderr(errors),
            ):
                status = probe.main(
                    [
                        "--target",
                        "192.168.1.2",
                        "--confirm-owner-camera",
                        "--report",
                        str(report_path),
                    ]
                )
            report = json.loads(report_path.read_text())
            self.assertEqual(report["corpus_sha256"], probe.EXPECTED_CORPUS_SHA256)
            self.assertEqual(report["status"], "liveness-failed")
            self.assertFalse(report["completed_all_cases"])
            self.assertFalse(report["results"][0]["all_listeners_after"])
            self.assertFalse(report["results"][0]["listeners_after"]["554"])
            self.assertEqual(status, 1)
            self.assertEqual(run_case.call_count, 1)

    def test_interrupt_checkpoints_completed_results(self) -> None:
        all_live = {port: True for port in probe.KNOWN_PORTS}
        errors = io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            report_path = root / "interrupted.json"
            with (
                patch.object(probe, "PRIVATE_REPORT_ROOT", root),
                patch.object(probe, "listener_liveness", return_value=all_live),
                patch.object(
                    probe,
                    "run_case",
                    side_effect=(("timeout", b"", 1, True), KeyboardInterrupt()),
                ),
                patch.object(probe.time, "sleep"),
                redirect_stdout(io.StringIO()),
                redirect_stderr(errors),
                self.assertRaises(KeyboardInterrupt),
            ):
                probe.main(
                    [
                        "--target",
                        "192.168.1.2",
                        "--confirm-owner-camera",
                        "--report",
                        str(report_path),
                    ]
                )
            report = json.loads(report_path.read_text())
            self.assertEqual(report["schema"], 2)
            self.assertEqual(report["corpus_sha256"], probe.EXPECTED_CORPUS_SHA256)
            self.assertEqual(report["status"], "interrupted")
            self.assertFalse(report["completed_all_cases"])
            self.assertEqual(len(report["results"]), 2)
            self.assertTrue(report["results"][0]["payload_fully_sent"])
            self.assertTrue(report["results"][0]["all_listeners_after"])
            self.assertEqual(report["results"][1]["outcome"], "connecting")
            self.assertFalse(report["results"][1]["payload_fully_sent"])
            self.assertIsNone(report["results"][1]["listeners_after"])

    def test_interrupt_after_send_records_in_flight_result(self) -> None:
        all_live = {port: True for port in probe.KNOWN_PORTS}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            report_path = root / "interrupted-after-send.json"
            with (
                patch.object(probe, "PRIVATE_REPORT_ROOT", root),
                patch.object(probe, "listener_liveness", return_value=all_live) as liveness,
                patch.object(
                    probe,
                    "run_case",
                    return_value=("timeout", b"", 1, True),
                ) as run_case,
                patch.object(probe.time, "sleep", side_effect=KeyboardInterrupt()),
                redirect_stdout(io.StringIO()),
                redirect_stderr(io.StringIO()),
                self.assertRaises(KeyboardInterrupt),
            ):
                probe.main(
                    [
                        "--target",
                        "192.168.1.2",
                        "--confirm-owner-camera",
                        "--report",
                        str(report_path),
                    ]
                )
            report = json.loads(report_path.read_text())
            self.assertEqual(run_case.call_count, 1)
            self.assertEqual(liveness.call_count, 1)
            self.assertEqual(report["status"], "interrupted")
            self.assertEqual(len(report["results"]), 1)
            self.assertTrue(report["results"][0]["payload_fully_sent"])
            self.assertIsNone(report["results"][0]["listeners_after"])

    def test_interrupt_inside_recv_records_fully_sent_payload(self) -> None:
        class InterruptingSocket:
            def __enter__(self):
                return self

            def __exit__(self, _kind, _value, _traceback):
                return False

            def settimeout(self, _timeout):
                pass

            def sendall(self, _payload):
                pass

            def recv(self, _limit):
                raise KeyboardInterrupt

        all_live = {port: True for port in probe.KNOWN_PORTS}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            report_path = root / "interrupted-in-recv.json"
            with (
                patch.object(probe, "PRIVATE_REPORT_ROOT", root),
                patch.object(probe, "listener_liveness", return_value=all_live),
                patch.object(
                    probe.socket,
                    "create_connection",
                    return_value=InterruptingSocket(),
                ),
                redirect_stdout(io.StringIO()),
                redirect_stderr(io.StringIO()),
                self.assertRaises(KeyboardInterrupt),
            ):
                probe.main(
                    [
                        "--target",
                        "192.168.1.2",
                        "--confirm-owner-camera",
                        "--report",
                        str(report_path),
                    ]
                )
            report = json.loads(report_path.read_text())
            self.assertEqual(report["status"], "interrupted")
            self.assertEqual(len(report["results"]), 1)
            self.assertEqual(report["results"][0]["outcome"], "awaiting-response")
            self.assertTrue(report["results"][0]["payload_fully_sent"])
            self.assertIsNone(report["results"][0]["listeners_after"])


if __name__ == "__main__":
    unittest.main()
