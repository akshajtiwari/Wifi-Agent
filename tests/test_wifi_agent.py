from __future__ import annotations

import logging
from pathlib import Path
import plistlib
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock, patch
import xml.etree.ElementTree as ET

import wifi_agent as app


def test_logger() -> logging.Logger:
    logger = logging.getLogger("wifi-agent-tests")
    logger.handlers[:] = [logging.NullHandler()]
    return logger


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


class PortalTests(unittest.TestCase):
    def test_namespaced_xml_is_understood(self) -> None:
        success, message = app.PortalClient._response_summary(
            '<r xmlns="urn:test"><status>LIVE</status><message>Signed in</message></r>'
        )
        self.assertTrue(success)
        self.assertIn("Signed in", message)

    def test_keepalive_ack_response_is_successful(self) -> None:
        success, message = app.PortalClient._response_summary("<response><ack>ack</ack></response>")
        self.assertTrue(success)
        self.assertEqual(message, "ack")

    def test_root_ack_is_understood(self) -> None:
        success, message = app.PortalClient._response_summary("<ack>ack</ack>")
        self.assertTrue(success)
        self.assertEqual(message, "ack")

    def test_keepalive_session_expired_ack_is_detected_as_failure(self) -> None:
        success, message = app.PortalClient._response_summary("<response><ack>login</ack></response>")
        self.assertFalse(success)
        self.assertEqual(message, "login")

    def test_keepalive_fail_ack_is_detected_as_failure(self) -> None:
        success, message = app.PortalClient._response_summary("<response><ack>fail</ack></response>")
        self.assertFalse(success)
        self.assertEqual(message, "fail")

    def test_failure_response_is_not_accepted(self) -> None:
        success, _ = app.PortalClient._response_summary(
            "<response><status>ERROR</status><message>Invalid credentials</message></response>"
        )
        self.assertFalse(success)

    def test_portal_message_redacts_password_and_controls(self) -> None:
        client = app.PortalClient(app.validate_config({"username": "student"}), "top-secret")
        self.assertEqual(client._safe_message("Error\nfor top-secret"), "Error for [redacted]")

    def test_connectivity_redirects_are_never_followed(self) -> None:
        handler = app._NoRedirect()
        self.assertIsNone(handler.redirect_request(None, None, 302, "Found", {}, "http://portal.local"))


class InterfaceTests(unittest.TestCase):
    def test_wired_interfaces_excludes_cloudflare_warp_and_vpns(self) -> None:
        self.assertFalse(app._looks_wired("CloudflareWARP"))
        self.assertFalse(app._looks_wired("Tailscale"))
        self.assertFalse(app._looks_wired("WireGuard"))
        self.assertFalse(app._looks_wired("OpenVPN TAP-Windows"))
        self.assertFalse(app._looks_wired("Wi-Fi"))
        self.assertFalse(app._looks_wired("vEthernet (Default Switch)"))

    def test_wired_interfaces_includes_physical_ethernet(self) -> None:
        self.assertTrue(app._looks_wired("Ethernet"))
        self.assertTrue(app._looks_wired("Local Area Connection* 10"))
        self.assertTrue(app._looks_wired("Ethernet 2"))


class MonitorTests(unittest.TestCase):
    def make_monitor(self, client) -> tuple[app.AgentMonitor, dict]:
        config = app.validate_config({"username": "student", "check_interval_seconds": 30})
        client.host = str(config["portal_host"])
        client.port = int(config["portal_port"])
        monitor = app.AgentMonitor(logger=test_logger())
        monitor._load_client = Mock(return_value=(config, client))
        return monitor, config

    def test_offline_reachable_portal_logs_in_and_verifies_internet(self) -> None:
        client = types.SimpleNamespace(login=Mock(return_value=(True, "LIVE")), keep_alive=Mock())
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

    def test_keepalive_session_expiry_triggers_auto_login_even_when_probe_is_online(self) -> None:
        # Simulates Cloudflare WARP masking internet availability while portal session expired
        client = types.SimpleNamespace(
            login=Mock(return_value=(True, "LIVE")),
            keep_alive=Mock(return_value=(False, "login")),
        )
        monitor, _ = self.make_monitor(client)
        with (
            patch.object(app, "wired_interfaces", return_value=["Ethernet"]),
            patch.object(app, "portal_port_open", return_value=True),
            patch.object(app, "internet_available", return_value=True),
            patch.object(app, "write_status"),
            patch.object(monitor.stop_event, "wait", return_value=False),
        ):
            self.assertTrue(monitor.check_once())
        client.keep_alive.assert_called_once_with()
        client.login.assert_called_once_with()
        self.assertEqual(monitor.snapshot.phase, "online")
        self.assertIn("refreshed", monitor.snapshot.message)

    def test_keepalive_successful_ack_maintains_online_without_login(self) -> None:
        client = types.SimpleNamespace(
            login=Mock(),
            keep_alive=Mock(return_value=(True, "ack")),
        )
        monitor, _ = self.make_monitor(client)
        with (
            patch.object(app, "wired_interfaces", return_value=["Ethernet"]),
            patch.object(app, "portal_port_open", return_value=True),
            patch.object(app, "internet_available", return_value=True),
            patch.object(app, "write_status"),
        ):
            self.assertTrue(monitor.check_once())
        client.keep_alive.assert_called_once_with()
        client.login.assert_not_called()
        self.assertEqual(monitor.snapshot.phase, "online")
        self.assertEqual(monitor._keepalive_failures, 0)

    def test_consecutive_keepalive_failures_trigger_auto_login(self) -> None:
        client = types.SimpleNamespace(
            login=Mock(return_value=(True, "LIVE")),
            keep_alive=Mock(return_value=(False, "HTTP response received")),
        )
        monitor, _ = self.make_monitor(client)
        with (
            patch.object(app, "wired_interfaces", return_value=["Ethernet"]),
            patch.object(app, "portal_port_open", return_value=True),
            patch.object(app, "internet_available", return_value=True),
            patch.object(app, "write_status"),
            patch.object(monitor.stop_event, "wait", return_value=False),
        ):
            # First failure logs warning
            monitor.check_once()
            self.assertEqual(client.login.call_count, 0)
            self.assertEqual(monitor._keepalive_failures, 1)
            # Second consecutive failure triggers login recovery
            monitor.check_once()
            self.assertEqual(client.login.call_count, 1)
            self.assertEqual(monitor._keepalive_failures, 0)

    def test_login_failures_use_bounded_backoff(self) -> None:
        client = types.SimpleNamespace(login=Mock(return_value=(False, "DENIED")), keep_alive=Mock())
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

    def test_pause_prevents_network_activity(self) -> None:
        monitor = app.AgentMonitor(logger=test_logger())
        monitor.pause_event.set()
        with patch.object(app, "wired_interfaces") as interfaces, patch.object(app, "write_status"):
            self.assertFalse(monitor.check_once())
        interfaces.assert_not_called()


class StartupTests(unittest.TestCase):
    def test_frozen_application_commands_do_not_reference_source_script(self) -> None:
        executable = Path("/Applications/WiFi Agent.app/Contents/MacOS/WiFi Agent")
        resolved = str(executable.resolve())
        with (
            patch.object(app.sys, "frozen", True, create=True),
            patch.object(app.sys, "executable", str(executable)),
            patch.object(app.sys, "platform", "darwin"),
        ):
            self.assertEqual(app._service_command(), [resolved, "tray"])
            self.assertEqual(app._application_working_directory(), executable.resolve().parent)

    def test_macos_install_at_login_rejects_app_running_from_disk_image(self) -> None:
        with (
            patch.object(app.sys, "frozen", True, create=True),
            patch.object(app.sys, "executable", "/Volumes/WiFi Agent/WiFi Agent.app/Contents/MacOS/WiFi Agent"),
            patch.object(app.sys, "platform", "darwin"),
            patch.object(app, "ensure_dependencies"),
            patch.object(app, "load_config", return_value=app.validate_config({"username": "student"})),
            patch.object(app, "get_password", return_value="secret"),
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


if __name__ == "__main__":
    unittest.main()
