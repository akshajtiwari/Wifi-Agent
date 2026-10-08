from __future__ import annotations

import hashlib
import configparser
from importlib.util import find_spec
import io
import json
import logging
import os
from pathlib import Path
import plistlib
import socket
import sys
import tempfile
import threading
import types
import unittest
from unittest.mock import Mock, patch
import xml.etree.ElementTree as ET

import wifi_agent as app


NEWER_VERSION = f"{app._version_tuple(app.APP_VERSION)[0] + 1}.0.0"


def test_logger() -> logging.Logger:
    logger = logging.getLogger("wifi-agent-tests")
    logger.handlers[:] = [logging.NullHandler()]
    return logger


class FakeResponse:
    def __init__(self, content: bytes):
        self.stream = io.BytesIO(content)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        return None

    def read(self, size: int = -1) -> bytes:
        return self.stream.read(size)


class FakeClock:
    """Monotonic time that advances on every read, with wall time in step."""

    def __init__(self, step: float = 3.0, wall_offset: float = 1_000_000.0):
        self.now = 0.0
        self.step = step
        self.wall_offset = wall_offset

    def monotonic(self) -> float:
        self.now += self.step
        return self.now

    def time(self) -> float:
        return self.wall_offset + self.now


class FakeOpener:
    def __init__(self, content: bytes):
        self.content = content
        self.requests = []

    def open(self, request, timeout: float):
        self.requests.append((request, timeout))
        return FakeResponse(self.content)


class ConfigTests(unittest.TestCase):
    def test_defaults_migrate_old_configuration(self) -> None:
        config = app.validate_config({"username": "student"}, require_username=True)
        self.assertEqual(config["portal_scheme"], "https")
        self.assertEqual(config["login_backoff_max_seconds"], 600)

    def test_ipv6_authority_is_bracketed(self) -> None:
        self.assertEqual(app._portal_authority("2001:db8::1", 8090), "[2001:db8::1]:8090")

    def test_rejects_url_in_host_field(self) -> None:
        with self.assertRaisesRegex(ValueError, "hostname or IP"):
            app.validate_config({"portal_host": "https://portal.example/login"})

    def test_rejects_unsafe_ranges(self) -> None:
        for change in ({"portal_port": 0}, {"check_interval_seconds": 2}, {"login_backoff_max_seconds": 9000}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                app.validate_config(change)

    def test_config_file_never_persists_unknown_password_key(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with (
                patch.object(app, "app_dir", return_value=root),
                patch.object(app, "CONFIG_PATH", root / "config.json"),
            ):
                app.save_config({**app.DEFAULT_CONFIG, "username": "student", "password": "not-for-disk"})
                stored = (root / "config.json").read_text(encoding="utf-8")
                self.assertNotIn("password", stored.casefold())
                if sys.platform != "win32":
                    self.assertEqual((root / "config.json").stat().st_mode & 0o777, 0o600)

    def test_malformed_status_pid_is_treated_as_not_running(self) -> None:
        self.assertFalse(app.snapshot_process_running({"process_id": "not-a-pid"}))

    def test_ui_pane_state_is_private_and_round_trips(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state_path = root / "ui-state.json"
            with patch.object(app, "app_dir", return_value=root), patch.object(app, "UI_STATE_PATH", state_path):
                app.save_ui_state({"last_pane": "diagnostics"})
                self.assertEqual(app.load_ui_state()["last_pane"], "diagnostics")
                if sys.platform != "win32":
                    self.assertEqual(state_path.stat().st_mode & 0o777, 0o600)


class UpdateTests(unittest.TestCase):
    def release_payload(self, version: str, *, digest: str | None = None) -> dict:
        asset_name = f"WiFiAgent-{version}-Windows-x64-Setup.exe"
        return {
            "tag_name": f"v{version}",
            "html_url": f"https://github.com/akshajtiwari/Wifi-Agent/releases/tag/v{version}",
            "assets": [
                {
                    "name": asset_name,
                    "state": "uploaded",
                    "size": 123,
                    "digest": digest or "sha256:" + "a" * 64,
                    "browser_download_url": (
                        f"https://github.com/akshajtiwari/Wifi-Agent/releases/download/v{version}/{asset_name}"
                    ),
                }
            ],
        }

    def test_selects_platform_specific_installer_names(self) -> None:
        self.assertEqual(
            app._update_asset_name("1.4.0", "win32", "AMD64"),
            "WiFiAgent-1.4.0-Windows-x64-Setup.exe",
        )
        self.assertEqual(
            app._update_asset_name("1.4.0", "darwin", "arm64"),
            "WiFiAgent-1.4.0-macOS-arm64.pkg",
        )
        self.assertEqual(
            app._update_asset_name("1.4.0", "darwin", "x86_64"),
            "WiFiAgent-1.4.0-macOS-x86_64.pkg",
        )

    def test_latest_release_returns_verified_compatible_update(self) -> None:
        payload = self.release_payload(NEWER_VERSION)
        opener = FakeOpener(json.dumps(payload).encode())
        update = app.check_for_update(opener=opener, system="win32", machine="AMD64")
        self.assertIsNotNone(update)
        assert update is not None
        self.assertEqual(update.version, NEWER_VERSION)
        self.assertEqual(update.sha256, "a" * 64)
        self.assertEqual(opener.requests[0][0].get_header("X-github-api-version"), app.GITHUB_API_VERSION)

    def test_current_release_does_not_offer_an_update(self) -> None:
        payload = self.release_payload(app.APP_VERSION)
        self.assertIsNone(
            app.check_for_update(
                opener=FakeOpener(json.dumps(payload).encode()),
                system="win32",
                machine="AMD64",
            )
        )

    def test_release_without_digest_is_rejected(self) -> None:
        payload = self.release_payload(NEWER_VERSION)
        payload["assets"][0]["digest"] = None
        with self.assertRaisesRegex(RuntimeError, "SHA-256"):
            app.check_for_update(
                opener=FakeOpener(json.dumps(payload).encode()),
                system="win32",
                machine="AMD64",
            )

    def test_untrusted_release_download_url_is_rejected(self) -> None:
        payload = self.release_payload(NEWER_VERSION)
        payload["assets"][0]["browser_download_url"] = "https://example.com/update.exe"
        with self.assertRaisesRegex(RuntimeError, "trusted GitHub"):
            app.check_for_update(
                opener=FakeOpener(json.dumps(payload).encode()),
                system="win32",
                machine="AMD64",
            )

    def test_oversized_update_is_rejected(self) -> None:
        payload = self.release_payload(NEWER_VERSION)
        payload["assets"][0]["size"] = app.MAX_UPDATE_SIZE + 1
        with self.assertRaisesRegex(RuntimeError, "safety limit"):
            app.check_for_update(
                opener=FakeOpener(json.dumps(payload).encode()),
                system="win32",
                machine="AMD64",
            )

    def test_download_is_saved_only_after_digest_verification(self) -> None:
        content = b"verified native installer"
        digest = hashlib.sha256(content).hexdigest()
        update = app.UpdateInfo(
            "1.3.0",
            "WiFiAgent-1.3.0-Windows-x64-Setup.exe",
            "https://github.com/akshajtiwari/Wifi-Agent/releases/download/v1.3.0/test.exe",
            "https://github.com/akshajtiwari/Wifi-Agent/releases/tag/v1.3.0",
            len(content),
            digest,
        )
        with tempfile.TemporaryDirectory() as directory, patch.object(app, "app_dir", return_value=Path(directory)):
            installer = app.download_update(update, opener=FakeOpener(content))
            self.assertEqual(installer.read_bytes(), content)
            self.assertFalse(installer.with_suffix(".exe.part").exists())

    def test_digest_mismatch_deletes_partial_download(self) -> None:
        content = b"tampered installer"
        update = app.UpdateInfo(
            "1.3.0",
            "WiFiAgent-1.3.0-Windows-x64-Setup.exe",
            "https://github.com/akshajtiwari/Wifi-Agent/releases/download/v1.3.0/test.exe",
            "https://github.com/akshajtiwari/Wifi-Agent/releases/tag/v1.3.0",
            len(content),
            "0" * 64,
        )
        with tempfile.TemporaryDirectory() as directory, patch.object(app, "app_dir", return_value=Path(directory)):
            with self.assertRaisesRegex(RuntimeError, "SHA-256"):
                app.download_update(update, opener=FakeOpener(content))
            self.assertEqual(list((Path(directory) / "updates").glob("*")), [])

    def test_windows_update_uses_silent_forced_close_installer(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            installer = root / "updates" / "update.exe"
            installer.parent.mkdir()
            installer.write_bytes(b"installer")
            with (
                patch.object(app, "app_dir", return_value=root),
                patch.object(app.sys, "platform", "win32"),
                patch.object(app.subprocess, "Popen") as popen,
            ):
                app.install_downloaded_update(installer)
        arguments = popen.call_args.args[0]
        self.assertEqual(arguments[0], str(installer))
        self.assertIn("/VERYSILENT", arguments)
        self.assertIn("/FORCECLOSEAPPLICATIONS", arguments)

    def test_macos_update_uses_native_administrator_prompt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            installer = root / "updates" / "update.pkg"
            installer.parent.mkdir()
            installer.write_bytes(b"installer")
            with (
                patch.object(app, "app_dir", return_value=root),
                patch.object(app.sys, "platform", "darwin"),
                patch.object(app.subprocess, "run") as run,
            ):
                app.install_downloaded_update(installer)
        arguments = run.call_args.args[0]
        self.assertEqual(arguments[0], "osascript")
        self.assertIn("administrator privileges", arguments[2])
        self.assertEqual(arguments[-1], str(installer))


class PortalTests(unittest.TestCase):
    def test_namespaced_xml_is_understood(self) -> None:
        result = app.PortalClient._response_summary(
            '<r xmlns="urn:test"><status>LIVE</status><message>Signed in</message></r>'
        )
        self.assertTrue(result.ok)
        self.assertEqual(result.kind, "alive")
        self.assertIn("Signed in", result.message)

    def test_failure_response_is_not_accepted(self) -> None:
        result = app.PortalClient._response_summary(
            "<response><status>ERROR</status><message>Invalid credentials</message></response>"
        )
        self.assertFalse(result.ok)
        self.assertEqual(result.kind, "rejected")

    def test_nominal_ack_with_logged_out_message_is_not_accepted(self) -> None:
        result = app.PortalClient._response_summary(
            "<response><status>ACK</status><message>User is not logged in</message></response>"
        )
        self.assertFalse(result.ok)
        self.assertEqual(result.kind, "expired")

    def test_sophos_keepalive_ack_means_session_is_alive(self) -> None:
        result = app.PortalClient._response_summary(
            "<?xml version='1.0' ?><requestresponse><ack><![CDATA[ack]]></ack></requestresponse>"
        )
        self.assertEqual(result, app.PortalResult(True, "ack", "alive"))

    def test_sophos_keepalive_login_again_means_session_expired(self) -> None:
        result = app.PortalClient._response_summary(
            "<requestresponse><ack><![CDATA[login_again]]></ack></requestresponse>"
        )
        self.assertFalse(result.ok)
        self.assertEqual(result.kind, "expired")

    def test_login_failures_are_classified(self) -> None:
        cases = {
            "Login failed. Invalid user name/password. Please contact the administrator": "rejected",
            "The system could not log you on. Make sure your password is correct": "rejected",
            "You have reached Maximum Login Limit.": "limit",
            "Your data transfer has been exceeded, Please contact the administrator": "denied",
        }
        for message, kind in cases.items():
            with self.subTest(message=message):
                result = app.PortalClient._response_summary(
                    f"<requestresponse><status>LOGIN</status><message>{message}</message></requestresponse>"
                )
                self.assertFalse(result.ok)
                self.assertEqual(result.kind, kind)

    def test_successful_login_message_is_accepted(self) -> None:
        result = app.PortalClient._response_summary(
            "<requestresponse><status><![CDATA[LIVE]]></status>"
            "<message><![CDATA[You are signed in as {username}]]></message></requestresponse>"
        )
        self.assertTrue(result.ok)
        self.assertEqual(result.kind, "alive")

    def test_requests_carry_portal_timestamp_and_product_type(self) -> None:
        client = app.PortalClient(app.validate_config({"username": "student"}), "top-secret")
        opener = FakeOpener(b"<requestresponse><ack>ack</ack></requestresponse>")
        client.opener = opener
        self.assertEqual(client.keep_alive().kind, "alive")
        keepalive_url = opener.requests[0][0].full_url
        self.assertIn("mode=192", keepalive_url)
        self.assertIn("producttype=0", keepalive_url)
        self.assertRegex(keepalive_url, r"&a=\d{13}")
        client.login()
        form = opener.requests[1][0].data.decode()
        self.assertIn("mode=191", form)
        self.assertRegex(form, r"(^|&)a=\d{13}")
        self.assertIn("producttype=0", form)

    def test_network_failure_is_reported_as_network_kind(self) -> None:
        client = app.PortalClient(app.validate_config({"username": "student"}), "top-secret")
        client.opener = types.SimpleNamespace(open=Mock(side_effect=app.URLError("timed out")))
        result = client.keep_alive()
        self.assertFalse(result.ok)
        self.assertEqual(result.kind, "network")

    def test_portal_message_redacts_password_and_controls(self) -> None:
        client = app.PortalClient(app.validate_config({"username": "student"}), "top-secret")
        self.assertEqual(client._safe_message("Error\nfor top-secret"), "Error for [redacted]")

    def test_connectivity_redirects_are_never_followed(self) -> None:
        handler = app._NoRedirect()
        self.assertIsNone(handler.redirect_request(None, None, 302, "Found", {}, "http://portal.local"))


class MonitorTests(unittest.TestCase):
    def make_monitor(self, client) -> tuple[app.AgentMonitor, dict]:
        config = app.validate_config({"username": "student", "check_interval_seconds": 30})
        client.host = str(config["portal_host"])
        client.port = int(config["portal_port"])
        monitor = app.AgentMonitor(logger=test_logger())
        monitor._load_client = Mock(return_value=(config, client))
        return monitor, config

    def test_offline_reachable_portal_logs_in_and_verifies_internet(self) -> None:
        client = types.SimpleNamespace(
            login=Mock(return_value=app.PortalResult(True, "LIVE", "alive")),
            keep_alive=Mock(return_value=app.PortalResult(False, "", "unknown")),
        )
        monitor, _ = self.make_monitor(client)
        with (
            patch.object(app, "wired_interfaces", return_value=["Ethernet"]),
            patch.object(app, "portal_port_open", return_value=True),
            patch.object(app, "internet_available", side_effect=[False, True]),
            patch.object(app, "write_status"),
            patch.object(monitor.stop_event, "wait", return_value=False),
        ):
            self.assertTrue(monitor.check_once())
        client.login.assert_called_once_with()
        self.assertEqual(monitor.snapshot.phase, "online")

    def test_login_failures_use_bounded_backoff(self) -> None:
        client = types.SimpleNamespace(
            login=Mock(return_value=app.PortalResult(False, "Invalid password", "rejected")),
            keep_alive=Mock(return_value=app.PortalResult(False, "login_again", "expired")),
        )
        monitor, config = self.make_monitor(client)
        config["login_backoff_max_seconds"] = 60
        with (
            patch.object(app, "wired_interfaces", return_value=["Ethernet"]),
            patch.object(app, "portal_port_open", return_value=True),
            patch.object(app, "internet_available", return_value=False),
            patch.object(app, "write_status"),
            patch.object(app.random, "uniform", return_value=1.0),
        ):
            monitor.check_once()
            monitor._next_login_at = 0
            monitor.check_once()
            monitor._next_login_at = 0
            monitor.check_once()
        self.assertEqual(client.login.call_count, 3)
        self.assertEqual(monitor.snapshot.retry_in_seconds, 60)

    def test_live_portal_session_is_connected_when_public_probe_fails(self) -> None:
        client = types.SimpleNamespace(
            login=Mock(),
            keep_alive=Mock(return_value=app.PortalResult(True, "ack", "alive")),
        )
        monitor, _ = self.make_monitor(client)
        with (
            patch.object(app, "wired_interfaces", return_value=["Ethernet"]),
            patch.object(app, "portal_port_open", return_value=True),
            patch.object(app, "internet_available", return_value=False),
            patch.object(app, "write_status"),
        ):
            self.assertTrue(monitor.check_once())
        client.login.assert_not_called()
        self.assertEqual(monitor.snapshot.phase, "connected")
        self.assertTrue(monitor.snapshot.portal_authenticated)

    def test_accepted_login_stays_connected_when_public_probe_fails(self) -> None:
        client = types.SimpleNamespace(
            login=Mock(return_value=app.PortalResult(True, "ACK Signed in", "alive")),
            keep_alive=Mock(return_value=app.PortalResult(False, "", "unknown")),
        )
        monitor, _ = self.make_monitor(client)
        with (
            patch.object(app, "wired_interfaces", return_value=["Ethernet"]),
            patch.object(app, "portal_port_open", return_value=True),
            patch.object(app, "internet_available", return_value=False),
            patch.object(app, "write_status"),
            patch.object(monitor.stop_event, "wait", return_value=False),
        ):
            self.assertTrue(monitor.check_once())
        self.assertEqual(monitor.snapshot.phase, "connected")
        self.assertTrue(monitor.snapshot.portal_authenticated)
        self.assertEqual(monitor.snapshot.consecutive_login_failures, 0)

    def test_unreachable_port_resets_retry_storm(self) -> None:
        client = types.SimpleNamespace(login=Mock(), keep_alive=Mock())
        monitor, _ = self.make_monitor(client)
        monitor._login_failures = 4
        monitor._next_login_at = 999999
        with (
            patch.object(app, "wired_interfaces", return_value=["Ethernet"]),
            patch.object(app, "portal_port_open", return_value=False),
            patch.object(app, "internet_available", return_value=False),
            patch.object(app, "write_status"),
        ):
            monitor.check_once()
        self.assertEqual(monitor._login_failures, 0)
        client.login.assert_not_called()

    def test_expired_session_logs_in_without_waiting_for_public_probes(self) -> None:
        client = types.SimpleNamespace(
            login=Mock(return_value=app.PortalResult(True, "LIVE", "alive")),
            keep_alive=Mock(return_value=app.PortalResult(False, "login_again", "expired")),
        )
        monitor, _ = self.make_monitor(client)
        probes = Mock(return_value=True)
        with (
            patch.object(app, "wired_interfaces", return_value=["eth0"]),
            patch.object(app, "portal_port_open", return_value=True),
            patch.object(app, "internet_available", probes),
            patch.object(app, "write_status"),
            patch.object(monitor.stop_event, "wait", return_value=False),
        ):
            self.assertTrue(monitor.check_once())
        client.login.assert_called_once_with()
        # Probed once, only after logging in again.
        probes.assert_called_once_with()
        self.assertEqual(monitor.snapshot.phase, "online")

    def test_recovery_time_is_recorded_after_a_portal_logout(self) -> None:
        client = types.SimpleNamespace(
            login=Mock(return_value=app.PortalResult(True, "LIVE", "alive")),
            keep_alive=Mock(side_effect=[
                app.PortalResult(True, "ack", "alive"),
                app.PortalResult(False, "login_again", "expired"),
            ]),
        )
        monitor, _ = self.make_monitor(client)
        with (
            patch.object(app, "wired_interfaces", return_value=["eth0"]),
            patch.object(app, "portal_port_open", return_value=True),
            patch.object(app, "internet_available", return_value=True),
            patch.object(app, "write_status"),
            patch.object(monitor.stop_event, "wait", return_value=False),
        ):
            monitor.check_once()
            monitor.check_once()
        self.assertEqual(monitor.snapshot.phase, "online")
        self.assertIsNotNone(monitor.snapshot.last_recovery_seconds)
        self.assertIsNone(monitor.snapshot.session_lost_at)
        self.assertIsNotNone(monitor.snapshot.last_login_at)

    def test_relogin_is_published_once_with_its_final_state(self) -> None:
        client = types.SimpleNamespace(
            login=Mock(return_value=app.PortalResult(True, "LIVE", "alive")),
            keep_alive=Mock(return_value=app.PortalResult(False, "login_again", "expired")),
        )
        monitor, _ = self.make_monitor(client)
        published = []
        monitor.status_callback = published.append
        with (
            patch.object(app, "wired_interfaces", return_value=["eth0"]),
            patch.object(app, "portal_port_open", return_value=True),
            patch.object(app, "internet_available", return_value=True),
            patch.object(app, "write_status"),
            patch.object(monitor.stop_event, "wait", return_value=False),
        ):
            monitor.check_once()
        # Observers never see a new login time paired with a stale phase.
        self.assertEqual([(item.phase, bool(item.last_login_at)) for item in published], [("online", True)])

    def test_retry_delay_depends_on_failure_kind(self) -> None:
        config = app.validate_config({"username": "student", "check_interval_seconds": 30})
        monitor = app.AgentMonitor(logger=test_logger())
        with patch.object(app.random, "uniform", return_value=1.0):
            self.assertEqual(monitor._schedule_login_retry(config, "limit"), 30)
            monitor._reset_login_backoff()
            transient = [monitor._schedule_login_retry(config, "network") for _ in range(5)]
            monitor._reset_login_backoff()
            rejected = [monitor._schedule_login_retry(config, "rejected") for _ in range(3)]
        self.assertEqual(transient, [10, 20, 40, 60, 60])
        self.assertEqual(rejected, [30, 60, 120])

    def test_rejected_password_is_reported_in_snapshot(self) -> None:
        client = types.SimpleNamespace(
            login=Mock(return_value=app.PortalResult(False, "Invalid user name/password", "rejected")),
            keep_alive=Mock(return_value=app.PortalResult(False, "login_again", "expired")),
        )
        monitor, _ = self.make_monitor(client)
        with (
            patch.object(app, "wired_interfaces", return_value=["eth0"]),
            patch.object(app, "portal_port_open", return_value=True),
            patch.object(app, "write_status"),
        ):
            monitor.check_once()
        self.assertEqual(monitor.snapshot.phase, "backoff")
        self.assertEqual(monitor.snapshot.last_login_error_kind, "rejected")
        self.assertIn("password", monitor.snapshot.message)

    def test_vault_outage_is_a_distinct_retryable_phase(self) -> None:
        monitor = app.AgentMonitor(logger=test_logger())
        monitor._load_client = Mock(side_effect=app.VaultUnavailable("Secret Service is locked"))
        with patch.object(app, "write_status"):
            self.assertFalse(monitor.check_once())
        self.assertEqual(monitor.snapshot.phase, "vault-unavailable")
        self.assertEqual(monitor._next_wait_seconds(), app.DEGRADED_CHECK_SECONDS)

    def test_locked_vault_is_retried_with_backoff_to_avoid_repeated_prompts(self) -> None:
        monitor = app.AgentMonitor(logger=test_logger())
        monitor._load_client = Mock(side_effect=app.VaultUnavailable("locked"))
        waits = []
        with patch.object(app, "write_status"):
            for _ in range(8):
                monitor.check_once()
                waits.append(monitor._next_wait_seconds())
        self.assertEqual(waits, [10, 20, 40, 80, 160, 300, 300, 300])

    def test_degraded_states_are_checked_sooner(self) -> None:
        monitor = app.AgentMonitor(logger=test_logger())
        monitor._config = app.validate_config({"check_interval_seconds": 120})
        monitor.snapshot.phase = "online"
        self.assertEqual(monitor._next_wait_seconds(), 120)
        monitor.snapshot.phase = "offline"
        self.assertEqual(monitor._next_wait_seconds(), app.DEGRADED_CHECK_SECONDS)
        monitor.snapshot.phase = "backoff"
        monitor.snapshot.retry_in_seconds = 45
        self.assertEqual(monitor._next_wait_seconds(), 45)

    def test_resume_from_sleep_wakes_the_monitor_and_clears_backoff(self) -> None:
        monitor = app.AgentMonitor(logger=test_logger())
        monitor._login_failures = 3
        monitor._next_login_at = 10_000.0
        wall = iter([1000.0, 1000.0, 1600.0])
        fake_time = types.SimpleNamespace(monotonic=lambda: 50.0, time=lambda: next(wall))
        with (
            patch.object(app, "time", fake_time),
            patch.object(monitor.wake_event, "wait", return_value=False),
            patch.object(monitor, "_network_fingerprint", return_value=None),
        ):
            monitor._wait_for_next_check(300)
        self.assertEqual(monitor._login_failures, 0)
        self.assertEqual(monitor._next_login_at, 0.0)

    def test_wired_network_change_wakes_the_monitor(self) -> None:
        monitor = app.AgentMonitor(logger=test_logger())
        monitor._login_failures = 2
        monitor._network_signature = ("auto", (("eth0", ("10.0.0.5",)),))
        fake_time = FakeClock()
        changed = ("auto", (("eth0", ("172.16.0.9",)),))
        with (
            patch.object(app, "time", fake_time),
            patch.object(monitor.wake_event, "wait", return_value=False),
            patch.object(monitor, "_network_fingerprint", return_value=changed),
        ):
            monitor._wait_for_next_check(900)
        self.assertEqual(monitor._network_signature, changed)
        self.assertEqual(monitor._login_failures, 0)

    def test_new_interface_selection_is_not_treated_as_a_network_change(self) -> None:
        monitor = app.AgentMonitor(logger=test_logger())
        monitor._login_failures = 2
        monitor._network_signature = ("auto", ())
        fake_time = FakeClock()
        with (
            patch.object(app, "time", fake_time),
            patch.object(monitor.wake_event, "wait", return_value=False),
            patch.object(monitor, "_network_fingerprint", return_value=("eth1", (("eth1", ("10.1.1.1",)),))),
        ):
            monitor._wait_for_next_check(30)
        self.assertEqual(monitor._login_failures, 2)


    def test_pause_prevents_network_activity(self) -> None:
        monitor = app.AgentMonitor(logger=test_logger())
        monitor.pause_event.set()
        with patch.object(app, "wired_interfaces") as interfaces, patch.object(app, "write_status"):
            self.assertFalse(monitor.check_once())
        interfaces.assert_not_called()


class StartupTests(unittest.TestCase):
    def test_initial_setup_requires_credentials_and_startup(self) -> None:
        config = app.validate_config({"username": "student"})
        self.assertFalse(app.initial_setup_complete(config, startup_installed=False))
        with patch.object(app, "get_password", return_value="secret"):
            self.assertTrue(app.initial_setup_complete(config, startup_installed=True))

    def test_initial_setup_detects_missing_vault_password(self) -> None:
        config = app.validate_config({"username": "student"})
        with patch.object(app, "get_password", side_effect=RuntimeError("missing")):
            self.assertFalse(app.initial_setup_complete(config, startup_installed=True))

    def test_frozen_application_commands_do_not_reference_source_script(self) -> None:
        executable = Path("/Applications/WiFi Agent.app/Contents/MacOS/WiFi Agent")
        with (
            patch.object(app.sys, "frozen", True, create=True),
            patch.object(app.sys, "executable", str(executable)),
            patch.object(app.sys, "platform", "darwin"),
        ):
            self.assertEqual(app._service_command(), [str(executable), "tray"])
            self.assertEqual(app._application_working_directory(), executable.parent)

    def test_macos_install_at_login_rejects_app_running_from_disk_image(self) -> None:
        with (
            patch.object(app.sys, "frozen", True, create=True),
            patch.object(app.sys, "executable", "/Volumes/WiFi Agent/WiFi Agent.app/Contents/MacOS/WiFi Agent"),
            patch.object(app.sys, "platform", "darwin"),
        ):
            with self.assertRaisesRegex(RuntimeError, "Applications folder"):
                app.install_startup()

    @unittest.skipIf(sys.platform == "win32", "Unix lock behavior")
    def test_single_instance_lock_rejects_duplicate_monitor(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(app, "app_dir", return_value=root), patch.object(app, "LOCK_PATH", root / "agent.lock"):
                with app.SingleInstance():
                    with self.assertRaisesRegex(RuntimeError, "already running"):
                        with app.SingleInstance():
                            self.fail("duplicate instance unexpectedly acquired the lock")

    def test_windows_service_runs_tray_with_restart_policy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            captured: dict[str, bytes] = {}

            def fake_run(arguments, **kwargs):
                if "/XML" in arguments:
                    task_path = Path(arguments[arguments.index("/XML") + 1])
                    captured["task"] = task_path.read_bytes()
                return types.SimpleNamespace(returncode=0, stdout="", stderr="")

            with (
                patch.object(app.sys, "platform", "win32"),
                patch.object(app, "app_dir", return_value=root),
                patch.object(app, "load_config", return_value=app.validate_config({"username": "student"})),
                patch.object(app, "get_password", return_value="secret"),
                patch.object(app.subprocess, "run", side_effect=fake_run),
            ):
                app.install_startup()

            task = ET.fromstring(captured["task"])
            namespace = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}
            arguments = task.findtext(".//t:Arguments", namespaces=namespace) or ""
            self.assertIn("tray", arguments)
            self.assertIsNotNone(task.find(".//t:RestartOnFailure", namespace))
            self.assertEqual(task.findtext(".//t:MultipleInstancesPolicy", namespaces=namespace), "IgnoreNew")

    def test_macos_launch_agent_runs_menu_bar_and_stays_quit_after_clean_exit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake_result = types.SimpleNamespace(returncode=0, stdout="", stderr="")
            with (
                patch.object(app.sys, "platform", "darwin"),
                patch.object(app.Path, "home", return_value=root),
                patch.object(app, "app_dir", return_value=root / "config"),
                patch.object(app, "load_config", return_value=app.validate_config({"username": "student"})),
                patch.object(app, "get_password", return_value="secret"),
                patch.object(app.subprocess, "run", return_value=fake_result),
            ):
                app.install_startup()

            plist_path = root / "Library" / "LaunchAgents" / "com.local.wifi-agent.plist"
            with plist_path.open("rb") as handle:
                payload = plistlib.load(handle)
            self.assertEqual(payload["ProgramArguments"][-1], "tray")
            self.assertEqual(payload["KeepAlive"], {"SuccessfulExit": False})


class FakeVault:
    def __init__(self) -> None:
        self.passwords: dict[tuple[str, str], str] = {}

    def get_password(self, service: str, username: str) -> str | None:
        return self.passwords.get((service, username))

    def set_password(self, service: str, username: str, password: str) -> None:
        self.passwords[(service, username)] = password

    def delete_password(self, service: str, username: str) -> None:
        self.passwords.pop((service, username), None)


class CredentialTests(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name) / "WiFiAgent"
        for patcher in (
            patch.object(app, "CREDENTIALS_PATH", self.root / "credentials.json"),
            patch.object(app, "ensure_dependencies"),
            patch.object(app.sys, "platform", "linux"),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    @unittest.skipIf(sys.platform == "win32", "POSIX permissions")
    def test_without_a_vault_linux_keeps_the_password_in_a_private_file(self) -> None:
        with patch.object(app, "_active_keyring", return_value=None):
            self.assertEqual(app.store_credentials("student", "top-secret"), "file")
            self.assertEqual(app.get_password("student", "file"), "top-secret")
        self.assertEqual(app.CREDENTIALS_PATH.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.root.stat().st_mode & 0o777, 0o700)
        self.assertNotIn("top-secret", app.CREDENTIALS_PATH.read_text())

    def test_vault_is_preferred_and_removes_a_stale_file_copy(self) -> None:
        vault = FakeVault()
        with patch.object(app, "_active_keyring", return_value=None):
            app.store_credentials("student", "old-secret")
        with patch.object(app, "_active_keyring", return_value=vault):
            self.assertEqual(app.store_credentials("student", "new-secret"), "vault")
            self.assertEqual(app.get_password("student", "vault"), "new-secret")
        self.assertFalse(app.CREDENTIALS_PATH.exists())

    def test_password_saved_while_vault_was_locked_beats_the_older_vault_copy(self) -> None:
        vault = FakeVault()
        vault.set_password(app.KEYRING_SERVICE, "student", "old-secret")
        locked = Mock(side_effect=app.VaultUnavailable("locked"))
        with patch.object(app, "_with_vault", locked):
            self.assertEqual(app.store_credentials("student", "new-secret"), "file")
        with patch.object(app, "_active_keyring", return_value=vault):
            self.assertEqual(app.get_password("student", "file"), "new-secret")

    def test_stuck_vault_request_is_abandoned_eventually(self) -> None:
        release = threading.Event()
        self.addCleanup(release.set)

        class HangingVault(FakeVault):
            def get_password(self, service: str, username: str) -> str | None:
                release.wait(5)
                return None

        with patch.object(app, "_active_keyring", return_value=HangingVault()):
            with self.assertRaises(app.VaultUnavailable):
                app._with_vault(lambda backend: backend.get_password("s", "u"), timeout=0.05)
        with (
            patch.object(app, "VAULT_ABANDON_SECONDS", 0.0),
            patch.object(app, "_active_keyring", return_value=FakeVault()),
        ):
            self.assertIsNone(app._with_vault(lambda backend: backend.get_password("s", "u"), timeout=1))
        release.set()

    def test_missing_vault_for_a_vault_password_is_reported_as_vault_outage(self) -> None:
        with patch.object(app, "_active_keyring", return_value=None):
            with self.assertRaises(app.VaultUnavailable):
                app.get_password("student", "vault")
            with self.assertRaises(app.VaultUnavailable):
                app.get_password("student", "")  # configurations from before 1.4.0
            with self.assertRaises(RuntimeError) as missing:
                app.get_password("student", "file")
        self.assertNotIsInstance(missing.exception, app.VaultUnavailable)

    def test_vault_that_never_answers_times_out(self) -> None:
        release = threading.Event()
        self.addCleanup(release.set)

        class HangingVault(FakeVault):
            def get_password(self, service: str, username: str) -> str | None:
                release.wait(5)
                return None

        with patch.object(app, "_active_keyring", return_value=HangingVault()):
            with self.assertRaises(app.VaultUnavailable):
                app._with_vault(lambda backend: backend.get_password("s", "u"), timeout=0.05)
            # While that request is stuck, later calls fail fast instead of piling up.
            with self.assertRaisesRegex(app.VaultUnavailable, "earlier request"):
                app._with_vault(lambda backend: backend.get_password("s", "u"), timeout=0.05)
        release.set()
        app._vault_state["worker"].join(1)

    def test_secret_service_that_starts_later_is_detected(self) -> None:
        class FailBackend:
            priority = 0

        class SecretServiceKeyring:
            priority = 5

        fake_keyring = types.SimpleNamespace(get_keyring=Mock(return_value=FailBackend()), set_keyring=Mock())
        secret_service = types.ModuleType("keyring.backends.SecretService")
        secret_service.Keyring = SecretServiceKeyring
        backends = types.ModuleType("keyring.backends")
        backends.SecretService = secret_service
        with (
            patch.object(app, "keyring", fake_keyring),
            patch.dict(sys.modules, {
                "keyring": fake_keyring,
                "keyring.backends": backends,
                "keyring.backends.SecretService": secret_service,
            }),
            patch.dict(app._vault_state, {"probed_at": float("-inf")}),
        ):
            backend = app._active_keyring()
        self.assertIsInstance(backend, SecretServiceKeyring)
        fake_keyring.set_keyring.assert_called_once_with(backend)


class NotificationPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = 0.0
        self.policy = app.NotificationPolicy(clock=lambda: self.now)

    def observe(self, **fields):
        return self.policy.observe(app.AgentSnapshot(**fields))

    def test_first_login_then_silent_steady_state(self) -> None:
        self.assertIsNone(self.observe(phase="starting"))
        first = self.observe(phase="online", last_login_at="t1")
        self.assertEqual(first.kind, "signed-in")
        self.assertIsNone(self.observe(phase="online", last_login_at="t1"))

    def test_relogin_after_portal_logout_reports_recovery_time(self) -> None:
        self.observe(phase="online", last_login_at="t1")
        notice = self.observe(phase="online", last_login_at="t2", last_recovery_seconds=4)
        self.assertEqual(notice.summary, "Signed back in automatically")
        self.assertIn("4s offline", notice.body)

    def test_rejected_password_is_critical_once_per_incident(self) -> None:
        fields = dict(
            phase="backoff", consecutive_login_failures=1, last_login_error="Invalid password",
            last_login_error_kind="rejected",
        )
        notice = self.observe(**fields)
        self.assertEqual((notice.kind, notice.urgency, notice.attention), ("password", 2, True))
        fields["consecutive_login_failures"] = 2
        self.assertIsNone(self.observe(**fields))
        recovered = self.observe(phase="online", last_login_at="t1")
        self.assertEqual(recovered.summary, "Signed back in automatically")

    def test_rejected_password_after_a_transient_failure_is_still_announced(self) -> None:
        first = self.observe(
            phase="backoff", consecutive_login_failures=1, last_login_error="timed out",
            last_login_error_kind="network",
        )
        self.assertEqual(first.kind, "login-failed")
        rejected = self.observe(
            phase="backoff", consecutive_login_failures=2, last_login_error="Invalid password",
            last_login_error_kind="rejected",
        )
        self.assertEqual((rejected.kind, rejected.urgency), ("password", 2))
        self.assertIsNone(self.observe(
            phase="backoff", consecutive_login_failures=3, last_login_error="Invalid password",
            last_login_error_kind="rejected",
        ))

    def test_vault_outage_waits_for_a_grace_period(self) -> None:
        self.assertIsNone(self.observe(phase="vault-unavailable", message="locked"))
        self.now = app.NotificationPolicy.VAULT_GRACE_SECONDS + 1
        notice = self.observe(phase="vault-unavailable", message="locked")
        self.assertEqual((notice.kind, notice.attention), ("vault", True))
        self.assertIsNone(self.observe(phase="vault-unavailable", message="locked"))

    def test_cable_unplug_and_pause_are_not_announced(self) -> None:
        self.observe(phase="online", last_login_at="t1")
        self.assertIsNone(self.observe(phase="offline", ethernet_connected=False, last_login_at="t1"))
        self.assertIsNone(self.observe(phase="paused", last_login_at="t1"))

    def test_unreachable_portal_is_announced_after_grace_and_recovery_follows(self) -> None:
        fields = dict(phase="offline", ethernet_connected=True, portal_port_open=False, internet_available=False)
        self.assertIsNone(self.observe(**fields))
        self.now = 31
        self.assertEqual(self.observe(**fields).kind, "portal-unreachable")
        self.assertEqual(self.observe(phase="online", last_recovery_seconds=40).kind, "recovered")


class LinuxTrayTests(unittest.TestCase):
    def test_pixmap_is_argb32_with_transparent_corners(self) -> None:
        pixels = app.wifi_icon_pixmap(22, (52, 199, 89))
        self.assertIsInstance(pixels, bytes)
        self.assertEqual(len(pixels), 22 * 22 * 4)
        self.assertEqual(pixels[0], 0)  # top-left alpha
        center = (int(22 * 0.80) * 22 + 11) * 4
        self.assertEqual(pixels[center:center + 4], bytes((255, 52, 199, 89)))

    def test_phase_colours(self) -> None:
        self.assertEqual(app.tray_tone("online"), "good")
        self.assertEqual(app.tray_tone("vault-unavailable"), "bad")
        self.assertEqual(app.tray_tone("paused"), "idle")
        self.assertEqual(app.tray_tone("backoff"), "busy")

    def test_menu_layout(self) -> None:
        items = app.tray_menu_items(app.AgentSnapshot(message="Portal_session connected"), paused=True)
        root_id, root, children = app.dbusmenu_layout(items)
        self.assertEqual((root_id, root["children-display"]), (0, ("s", "submenu")))
        ids = [child[1][0] for child in children]
        self.assertEqual(len(ids), len(set(ids)))
        status = dict((child[1][0], child[1][1]) for child in children)[2]
        self.assertEqual(status["enabled"], ("b", False))
        self.assertIn("__", status["label"][1])
        self.assertIn(("s", "Resume monitoring"), [child[1][1].get("label") for child in children])
        self.assertEqual(app.dbusmenu_layout(items, depth=0)[2], [])
        self.assertEqual(app.dbusmenu_layout(items, 4, names=["label"])[1], {"label": ("s", "Check and log in now")})

    def test_status_notifier_properties(self) -> None:
        properties = app.sni_properties(app.AgentSnapshot(phase="needs-setup", message="<setup>"))
        self.assertEqual(properties["Status"], ("s", "NeedsAttention"))
        self.assertEqual(properties["ItemIsMenu"], ("b", False))
        self.assertEqual(properties["Menu"], ("o", "/MenuBar"))
        self.assertEqual(properties["ToolTip"][1][3], "&lt;setup&gt;")
        self.assertEqual(app.sni_properties(app.AgentSnapshot(phase="online"))["Status"], ("s", "Active"))

    def test_update_reports_only_visible_changes(self) -> None:
        server = app.TrayObjectServer({})
        self.assertEqual(server.update(app.AgentSnapshot(phase="online", message="ok"), False), {"icon", "status", "tooltip", "menu"})
        self.assertEqual(server.update(app.AgentSnapshot(phase="connected", message="ok"), False), set())
        revision = server.revision
        self.assertEqual(server.update(app.AgentSnapshot(phase="connected", message="ok"), True), {"menu"})
        self.assertEqual(server.revision, revision + 1)


@unittest.skipUnless(find_spec("jeepney"), "jeepney is not installed")
class LinuxTrayDBusTests(unittest.TestCase):
    def call(self, server, path, interface, member, signature=None, body=()):
        from jeepney import DBusAddress, new_method_call
        from jeepney.low_level import HeaderFields, Parser

        message = new_method_call(DBusAddress(path, bus_name=":1.5", interface=interface), member, signature, body)
        message.header.serial = 7
        message.header.fields[HeaderFields.sender] = ":1.9"
        reply = server.handle(message)
        return Parser().feed(reply.serialise(serial=1))[0]

    def test_properties_layout_and_events_round_trip(self) -> None:
        from jeepney import MessageType

        actions = {"quit": Mock(), "open": Mock()}
        server = app.TrayObjectServer(actions)
        server.update(app.AgentSnapshot(phase="online", message="Connected"), False)

        reply = self.call(server, app.SNI_PATH, "org.freedesktop.DBus.Properties", "GetAll", "s", (app.SNI_INTERFACE,))
        self.assertEqual(reply.header.message_type, MessageType.method_return)
        self.assertEqual(reply.body[0]["Id"], ("s", "wifi-agent"))

        reply = self.call(server, app.DBUSMENU_PATH, app.DBUSMENU_INTERFACE, "GetLayout", "iias", (0, -1, []))
        revision, (root_id, _props, children) = reply.body
        self.assertEqual((revision, root_id, len(children)), (server.revision, 0, 10))

        self.call(server, app.DBUSMENU_PATH, app.DBUSMENU_INTERFACE, "Event", "isvu", (10, "clicked", ("s", ""), 0))
        actions["quit"].assert_called_once_with()
        self.call(server, app.SNI_PATH, app.SNI_INTERFACE, "Activate", "ii", (0, 0))
        actions["open"].assert_called_once_with()

        reply = self.call(server, app.DBUSMENU_PATH, app.DBUSMENU_INTERFACE, "AboutToShowGroup", "ai", ([1, 99],))
        self.assertEqual(reply.body, ([], [99]))

        reply = self.call(server, app.SNI_PATH, app.SNI_INTERFACE, "Nonexistent")
        self.assertEqual(reply.header.message_type, MessageType.error)


class SystemdTests(unittest.TestCase):
    def test_unit_restarts_always_with_watchdog_and_skips_uninstalled_program(self) -> None:
        text = app._linux_unit_text(["/usr/bin/python3", "/opt/100%/wifi_agent.py", "run"])
        for line in (
            "Type=notify",
            "Restart=always",
            "WatchdogSec=180",
            f"RestartPreventExitStatus={app.EXIT_ALREADY_RUNNING}",
            "StartLimitIntervalSec=0",
            "ConditionPathExists=/opt/100%%/wifi_agent.py",
            'ExecStart="/usr/bin/python3" "/opt/100%%/wifi_agent.py" "run"',
        ):
            self.assertIn(line + "\n", text)
        self.assertNotIn("network-online.target", text)

    @unittest.skipIf(sys.platform == "win32", "systemd")
    def test_outdated_unit_is_detected_and_install_rewrites_it(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = types.SimpleNamespace(returncode=0, stdout="", stderr="")
            with (
                patch.object(app.sys, "platform", "linux"),
                patch.object(app.Path, "home", return_value=root),
                patch.object(app, "app_dir", return_value=root / "config"),
                patch.object(app.subprocess, "run", return_value=result) as run,
            ):
                unit = app._linux_unit_path()
                unit.parent.mkdir(parents=True)
                unit.write_text("[Service]\nExecStart=old\nRestart=on-failure\n")
                self.assertTrue(app.startup_unit_outdated())
                app.install_startup(require_credentials=False)
                self.assertFalse(app.startup_unit_outdated())
            commands = [call.args[0] for call in run.call_args_list]
            self.assertIn(["systemctl", "--user", "restart", app.SYSTEMD_UNIT_NAME], commands)

    @unittest.skipUnless(hasattr(socket, "AF_UNIX"), "Unix sockets")
    def test_sd_notify_sends_datagrams_to_systemd(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "notify")
            with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as receiver:
                receiver.bind(path)
                with patch.dict(os.environ, {"NOTIFY_SOCKET": path}):
                    self.assertTrue(app.sd_notify("READY=1"))
                self.assertEqual(receiver.recv(64), b"READY=1")
        with patch.dict(os.environ, {"NOTIFY_SOCKET": ""}):
            self.assertFalse(app.sd_notify("READY=1"))

    def test_duplicate_monitor_exits_without_a_restart_loop(self) -> None:
        with (
            patch.object(app, "ensure_dependencies"),
            patch.object(app, "build_logger", return_value=test_logger()),
            patch.object(app.SingleInstance, "__enter__", side_effect=app.AlreadyRunning("WiFi Agent is already running.")),
            patch.object(app.sys, "stderr", io.StringIO()),
        ):
            self.assertEqual(app.run_agent(tray=False), app.EXIT_ALREADY_RUNNING)

    def test_gui_environment_is_read_from_the_user_manager(self) -> None:
        output = "DISPLAY=:0\nWAYLAND_DISPLAY=wayland-1\nPATH=/usr/bin\n"
        with (
            patch.object(app.sys, "platform", "linux"),
            patch.dict(app._USER_MANAGER_ENVIRONMENT, {"at": float("-inf"), "values": {}}),
            patch.dict(os.environ, {"DISPLAY": "", "WAYLAND_DISPLAY": ""}),
            patch.object(app.shutil, "which", return_value="/usr/bin/systemctl"),
            patch.object(app.subprocess, "run", return_value=types.SimpleNamespace(stdout=output)),
        ):
            environment = app._graphical_environment()
        self.assertEqual(environment["DISPLAY"], ":0")
        self.assertEqual(environment["WAYLAND_DISPLAY"], "wayland-1")
        self.assertNotEqual(environment.get("PATH"), "/usr/bin" if os.environ.get("PATH") != "/usr/bin" else None)


class CrashReportingTests(unittest.TestCase):
    def test_unexpected_error_is_logged_and_shown_for_gui_launches(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            crash_log = Path(directory) / "crash.log"
            with (
                patch.object(app, "CRASH_LOG_PATH", crash_log),
                patch.object(app, "_enable_fault_log"),
                patch.object(app, "_dispatch", side_effect=ZeroDivisionError("boom")),
                patch.object(app, "_show_fatal_error") as alert,
                patch.object(app.sys, "argv", ["wifi_agent.py", "setup"]),
                patch.object(app.sys, "stderr", io.StringIO()),
            ):
                self.assertEqual(app.main(), 70)
            self.assertIn("ZeroDivisionError", crash_log.read_text())
            alert.assert_called_once()

    def test_background_failures_never_open_dialogs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with (
                patch.object(app, "CRASH_LOG_PATH", Path(directory) / "crash.log"),
                patch.object(app, "_enable_fault_log"),
                patch.object(app, "_dispatch", side_effect=RuntimeError("no portal")),
                patch.object(app, "_show_fatal_error") as alert,
                patch.object(app.sys, "argv", ["wifi_agent.py", "tray"]),
                patch.object(app.sys, "stderr", io.StringIO()),
            ):
                self.assertEqual(app.main(), 2)
            alert.assert_not_called()

    def test_self_test_writes_its_result_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = Path(directory) / "result.txt"
            with patch.object(app, "_self_test_checks"):
                self.assertEqual(app.run_packaging_self_test(str(result)), 0)
            self.assertEqual(result.read_text().strip(), "ok")
            with patch.object(app, "_self_test_checks", side_effect=RuntimeError("Tk missing")), \
                    patch.object(app.sys, "stderr", io.StringIO()):
                self.assertEqual(app.run_packaging_self_test(str(result)), 1)
            self.assertIn("Tk missing", result.read_text())


class MacOSMenuBarTests(unittest.TestCase):
    def test_reopen_event_opens_settings_and_dock_icon_is_hidden(self) -> None:
        manager = Mock()
        application = Mock()
        appkit = types.SimpleNamespace(
            NSApplication=types.SimpleNamespace(sharedApplication=Mock(return_value=application)),
            NSApplicationActivationPolicyAccessory=1,
            NSAppleEventManager=types.SimpleNamespace(sharedAppleEventManager=Mock(return_value=manager)),
        )

        class NSObject:
            @classmethod
            def alloc(cls):
                return cls()

            def init(self):
                return self

        foundation = types.SimpleNamespace(NSObject=NSObject)
        objc = types.SimpleNamespace(typedSelector=lambda signature: (lambda function: function))
        app_helper = types.SimpleNamespace(callAfter=lambda function: function())
        tools = types.ModuleType("PyObjCTools")
        tools.AppHelper = app_helper
        opened = Mock()
        with (
            patch.dict(sys.modules, {
                "AppKit": appkit, "Foundation": foundation, "objc": objc,
                "PyObjCTools": tools, "PyObjCTools.AppHelper": app_helper,
            }),
            patch.dict(app._MACOS_STATE, {}, clear=True),
        ):
            app._prepare_macos_menu_bar_app(opened)
            handler, selector, event_class, event_id = manager.setEventHandler_andSelector_forEventClass_andEventID_.call_args.args
            self.assertEqual(selector, b"handleReopen:withReplyEvent:")
            self.assertEqual((event_class, event_id), (app._fourcc(b"aevt"), app._fourcc(b"rapp")))
            handler.handleReopen_withReplyEvent_(None, None)
        opened.assert_called_once_with()
        application.setActivationPolicy_.assert_called_once_with(1)


REPOSITORY = Path(__file__).resolve().parents[1]


class PackagingTests(unittest.TestCase):
    def test_linux_packages_install_the_launcher_menu_entry_and_icon(self) -> None:
        stage = (REPOSITORY / "packaging/linux/stage.sh").read_text()
        for target in (
            "/usr/lib/wifi-agent/wifi_agent.py",
            "/usr/lib/wifi-agent/user-services.sh",
            "/usr/bin/wifi-agent",
            "/usr/share/applications/wifi-agent.desktop",
            "/usr/share/icons/hicolor/scalable/apps/wifi-agent.svg",
        ):
            self.assertIn(target, stage)
        self.assertIn("/usr/lib/wifi-agent/wifi_agent.py", (REPOSITORY / "packaging/linux/wifi-agent").read_text())

    def test_desktop_entry_opens_settings_with_the_packaged_icon(self) -> None:
        entry = configparser.ConfigParser(interpolation=None)
        entry.optionxform = str
        entry.read(REPOSITORY / "packaging/linux/wifi-agent.desktop")
        section = entry["Desktop Entry"]
        self.assertEqual(section["Exec"], "wifi-agent setup")
        self.assertEqual(section["Icon"], "wifi-agent")

    def test_linux_packages_depend_on_every_runtime_module(self) -> None:
        control = (REPOSITORY / "packaging/debian/control.in").read_text()
        for package in ("python3-keyring", "python3-psutil", "python3-tk", "python3-jeepney"):
            self.assertIn(package, control)
        pkgbuild = (REPOSITORY / "packaging/arch/PKGBUILD.in").read_text()
        for package in ("'python-keyring'", "'python-psutil'", "'tk'", "'python-jeepney'"):
            self.assertIn(package, pkgbuild)

    def test_macos_package_installs_only_into_applications(self) -> None:
        script = (REPOSITORY / "packaging/macos/build-installer.sh").read_text()
        self.assertIn("BundleIsRelocatable false", script)
        self.assertIn("--component-plist", script)
        self.assertIn("NSLocalNetworkUsageDescription", script)


if __name__ == "__main__":
    unittest.main()
