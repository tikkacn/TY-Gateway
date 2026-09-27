import importlib.util
import json
import pathlib
import sys
import tempfile
import types
import unittest
from unittest import mock


SERVICE_PATH = pathlib.Path(__file__).with_name("ty-gateway-update-service.py")
SPEC = importlib.util.spec_from_file_location("ty_gateway_update_service", SERVICE_PATH)
service = importlib.util.module_from_spec(SPEC)
sys.modules.setdefault("pwd", types.SimpleNamespace(getpwnam=lambda _name: types.SimpleNamespace(pw_uid=0, pw_gid=0)))
SPEC.loader.exec_module(service)


class UpdateServiceTests(unittest.TestCase):
    def test_request_protocol_rejects_arbitrary_paths_and_channels(self):
        request = {"action": "apply-local", "channel": "pilot", "upload_id": "a" * 32}
        self.assertEqual(service.validate_request(request), "apply-local")
        for invalid in (
            {**request, "bundle": "/etc/passwd"},
            {**request, "channel": "other"},
            {**request, "upload_id": "../etc/passwd"},
            {**request, "upload_id": 123},
            {"action": "rollback"},
        ):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                service.validate_request(invalid)

    def test_agent_socket_only_accepts_pinned_admin_operations(self):
        command_id = "a" * 32
        self.assertEqual(service.validate_request({"action": "admin-status", "command_id": command_id}, "agent"), "admin-status")
        self.assertEqual(service.validate_request({"action": "admin-apply", "command_id": command_id, "channel": "pilot", "version": "0.8.0"}, "agent"), "admin-apply")
        for invalid in (
            {"action": "apply"},
            {"action": "admin-rollback", "command_id": command_id, "version": "../etc/passwd"},
            {"action": "admin-apply", "command_id": command_id, "channel": "pilot", "version": "0.8.0", "url": "https://evil.test"},
            {"action": "admin-apply", "command_id": "bad", "channel": "stable", "version": "0.8.0"},
        ):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                service.validate_request(invalid, "agent")
        with self.assertRaises(ValueError):
            service.validate_request({"action": "admin-rollback", "command_id": command_id, "version": "0.8.0"}, "local")

    def test_admin_job_is_idempotent_and_requires_final_version(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            command_id = "b" * 32
            with mock.patch.object(service, "STATE", root), mock.patch.object(service, "run_fixed") as run_fixed, mock.patch.object(service, "unit_state", return_value={"active": "unknown", "result": "unknown"}), mock.patch.object(service, "write_job_record", side_effect=lambda path, value: path.write_text(json.dumps(value))):
                controller = service.Controller(local_uid=1000)
                run_fixed.return_value = '{"version":"0.8.0","update_available":true}'
                request = {"action": "admin-apply", "command_id": command_id, "channel": "pilot", "version": "0.8.0"}
                self.assertEqual(controller.handle(request, "agent")["state"], "running")
                self.assertEqual(controller.handle(request, "agent")["state"], "running")
                self.assertEqual(run_fixed.call_count, 2)  # one signed check, one job start
                self.assertEqual(run_fixed.call_args.args[1], "--unit=ty-gateway-update-job-" + command_id[:12] + ".service")
                self.assertEqual(controller.admin_status(command_id)["state"], "running")
                (root / "current.json").write_text('{"format_version":1,"version":"0.8.0"}')
                self.assertEqual(controller.admin_status(command_id)["state"], "succeeded")
                self.assertEqual(controller.handle(request, "agent")["state"], "succeeded")

    def test_corrupt_command_record_does_not_relaunch_installer(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            command_id = "f" * 32
            (root / ("admin-job-" + command_id + ".json")).write_text("not json")
            with mock.patch.object(service, "STATE", root), mock.patch.object(service, "run_fixed") as run_fixed:
                controller = service.Controller(local_uid=1000)
                request = {"action": "admin-apply", "command_id": command_id, "channel": "pilot", "version": "0.8.0"}
                self.assertEqual(controller.handle(request, "agent"), {"state": "failed"})
                run_fixed.assert_not_called()

    def test_stale_release_and_missing_rollback_snapshot_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            with mock.patch.object(service, "STATE", root), mock.patch.object(service, "run_fixed", return_value='{"version":"0.8.1","update_available":true}') as run_fixed:
                controller = service.Controller(local_uid=1000)
                upgrade = {"action": "admin-apply", "command_id": "c" * 32, "channel": "stable", "version": "0.8.0"}
                self.assertEqual(controller.handle(upgrade, "agent"), {"state": "failed"})
                self.assertEqual(run_fixed.call_count, 1)
                rollback = {"action": "admin-rollback", "command_id": "d" * 32, "version": "0.8.0"}
                self.assertEqual(controller.handle(rollback, "agent"), {"state": "failed"})

    def test_remote_rollback_refuses_legacy_snapshot(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            (root / "current.json").write_text(json.dumps({
                "format_version": 1, "version": "0.8.0", "remote_maintenance_protocol": 1,
                "previous": {"format_version": 1, "version": "0.7.3"},
            }))
            with mock.patch.object(service, "STATE", root), mock.patch.object(service, "run_fixed") as run_fixed:
                controller = service.Controller(local_uid=1000)
                request = {"action": "admin-rollback", "command_id": "e" * 32, "version": "0.8.0"}
                self.assertEqual(controller.handle(request, "agent"), {"state": "failed"})
                run_fixed.assert_not_called()

    def test_controller_starts_only_fixed_local_package_command(self):
        with tempfile.TemporaryDirectory() as temporary:
            candidate = pathlib.Path(temporary)
            controller = service.Controller(local_uid=1000)
            with (
                mock.patch.object(controller, "status", return_value={"updating": False}),
                mock.patch.object(service, "stage_offline_upload", return_value=candidate),
                mock.patch.object(service, "run_fixed") as run_fixed,
                mock.patch.object(service, "save_job") as save_job,
            ):
                result = controller.handle({"action": "apply-local", "channel": "pilot", "upload_id": "b" * 32})

            self.assertEqual(result, {"started": True, "channel": "pilot"})
            args = run_fixed.call_args.args
            self.assertEqual(args[0], "/usr/bin/systemd-run")
            self.assertRegex(args[1], r"^--unit=ty-gateway-update-job-[0-9a-f]{12}\.service$")
            self.assertEqual(args[-8:], (
                str(service.UPDATE), "apply-local", "--channel", "pilot",
                "--bundle", str(candidate / "release.json"),
                "--artifact", str(candidate / "ty-gateway-oec-overlay.tar.gz"),
            ))
            self.assertEqual(run_fixed.call_args.kwargs["timeout"], 15)
            self.assertEqual(save_job.call_args.args[1], None)


if __name__ == "__main__":
    unittest.main()
