#!/usr/bin/python3
"""Narrow, separately authorized sockets for signed software maintenance.

The local web process can check/install stable online releases and hand over a
strictly identified local upload for pinned-key verification. It cannot choose
a URL, arbitrary filesystem path, shell command, or downgrade.
"""

import json
import os
import pathlib
import pwd
import re
import secrets
import shutil
import socket
import socketserver
import stat
import struct
import subprocess
import tempfile
import threading
import time

SOCKET = pathlib.Path("/run/ty-gateway-update/control.sock")
AGENT_SOCKET = pathlib.Path("/run/ty-gateway-update/agent.sock")
STATE = pathlib.Path("/var/lib/ty-gateway-update")
UPDATE = pathlib.Path("/usr/local/libexec/ty-gateway-update")
LOCAL_UPLOADS = pathlib.Path("/var/lib/ty-gateway-local/offline-update")
OFFLINE_CANDIDATES = STATE / "offline-candidates"
MAX_REQUEST = 4096
JOB_UNIT = re.compile(r"ty-gateway-update-job-[0-9a-f]{12}\.service\Z")
UPLOAD_ID = re.compile(r"[0-9a-f]{32}\Z")
CANDIDATE_ID = re.compile(r"candidate-[0-9a-f]{8}\Z")
CHANNELS = {"pilot", "stable"}
VERSION = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")
COMMAND_ID = re.compile(r"[0-9a-f]{32}\Z")
MAX_BUNDLE = 32 << 10
MAX_ARTIFACT = 512 << 20


def run_fixed(*args, timeout=30):
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout,
                            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}, check=False)
    if result.returncode:
        raise RuntimeError("软件更新操作未完成；请查看管理员日志。")
    return result.stdout


def saved_json(name):
    filename = STATE / name
    if filename.is_symlink() or not filename.is_file() or filename.stat().st_size > 16384:
        return None
    try:
        value = json.loads(filename.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) and value.get("format_version") == 1 else None
    except (OSError, ValueError):
        return None


def save_job(unit, version, offline_stage=None, command_id=None, operation=None, target_version=None):
    if not JOB_UNIT.fullmatch(unit):
        raise RuntimeError("invalid update job")
    value = {"format_version": 1, "unit": unit, "version": version,
             "started_at": int(time.time())}
    if offline_stage is not None:
        if not CANDIDATE_ID.fullmatch(offline_stage):
            raise RuntimeError("invalid offline candidate")
        value["offline_stage"] = offline_stage
    if command_id is not None:
        if not COMMAND_ID.fullmatch(command_id) or operation not in ("apply", "rollback") or not VERSION.fullmatch(target_version or ""):
            raise RuntimeError("invalid administrator update job")
        value.update(command_id=command_id, operation=operation, target_version=target_version)
        write_job_record(STATE / ("admin-job-" + command_id + ".json"), value)
    write_job_record(STATE / "job.json", value)


def write_job_record(destination, value):
    fd, name = tempfile.mkstemp(prefix=".job-", dir=STATE)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            json.dump(value, out)
            out.write("\n")
            out.flush()
            os.fsync(out.fileno())
        os.replace(name, destination)
        directory = os.open(STATE, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def unit_state(unit):
    result = subprocess.run(["/bin/systemctl", "show", "--no-pager", "-p", "ActiveState", "-p", "Result", unit],
                            capture_output=True, text=True, timeout=5, check=False)
    if result.returncode:
        return {"active": "unknown", "result": "unknown"}
    fields = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
    return {"active": fields.get("ActiveState", "unknown"), "result": fields.get("Result", "unknown")}


def validate_request(request, role="local"):
    if not isinstance(request, dict) or not isinstance(request.get("action"), str):
        raise ValueError("请求无效。")
    action = request["action"]
    if role == "agent":
        expected = ({"action", "command_id"} if action == "admin-status" else
                    {"action", "command_id", "channel", "version"} if action == "admin-apply" else
                    {"action", "command_id", "version"} if action == "admin-rollback" else set())
        if not expected or set(request) != expected or any(not isinstance(value, str) for value in request.values()):
            raise ValueError("请求无效。")
        if not COMMAND_ID.fullmatch(request["command_id"]):
            raise ValueError("请求无效。")
        if action == "admin-apply" and request["channel"] not in CHANNELS:
            raise ValueError("请求无效。")
        if action != "admin-status" and (not VERSION.fullmatch(request["version"]) or len(request["version"]) > 32):
            raise ValueError("请求无效。")
        return action
    if role != "local":
        raise ValueError("请求无效。")
    expected = {"action", "channel", "upload_id"} if action == "apply-local" else {"action"}
    if action not in {"status", "check", "apply", "apply-local"} or set(request) != expected:
        raise ValueError("请求无效。")
    if any(not isinstance(value, str) for value in request.values()):
        raise ValueError("请求无效。")
    if action == "apply-local" and (request["channel"] not in CHANNELS or
                                      not UPLOAD_ID.fullmatch(request["upload_id"])):
        raise ValueError("请求无效。")
    return action


def private_directory(path, owner_uid):
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != owner_uid or info.st_mode & 0o077:
        raise ValueError("offline update directory is unsafe")


def copy_upload_file(source, destination, owner_uid, limit):
    info = source.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner_uid or
            info.st_mode & 0o077 or info.st_nlink != 1 or info.st_size <= 0 or info.st_size > limit):
        raise ValueError("offline update file is unsafe")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    source_fd = os.open(source, flags)
    try:
        opened = os.fstat(source_fd)
        if (opened.st_dev != info.st_dev or opened.st_ino != info.st_ino or
                not stat.S_ISREG(opened.st_mode) or opened.st_uid != owner_uid or
                opened.st_mode & 0o077 or opened.st_nlink != 1 or opened.st_size != info.st_size):
            raise ValueError("offline update file changed during upload")
        target_fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            count = 0
            with os.fdopen(source_fd, "rb", closefd=False) as incoming, os.fdopen(target_fd, "wb") as outgoing:
                while True:
                    chunk = incoming.read(1024 * 1024)
                    if not chunk:
                        break
                    count += len(chunk)
                    if count > limit:
                        raise ValueError("offline update file exceeds its limit")
                    outgoing.write(chunk)
                if count != info.st_size:
                    raise ValueError("offline update file changed during copy")
                outgoing.flush()
                os.fsync(outgoing.fileno())
        except Exception:
            try:
                os.unlink(destination)
            except FileNotFoundError:
                pass
            raise
    finally:
        os.close(source_fd)


def stage_offline_upload(upload_id, local_uid):
    if not isinstance(upload_id, str) or not UPLOAD_ID.fullmatch(upload_id):
        raise ValueError("offline upload id is invalid")
    local_state = LOCAL_UPLOADS.parent
    private_directory(local_state, local_uid)
    private_directory(LOCAL_UPLOADS, local_uid)
    incoming = LOCAL_UPLOADS / upload_id
    private_directory(incoming, local_uid)

    OFFLINE_CANDIDATES.mkdir(mode=0o700, exist_ok=True)
    private_directory(OFFLINE_CANDIDATES, 0)
    candidate = pathlib.Path(tempfile.mkdtemp(prefix="candidate-", dir=OFFLINE_CANDIDATES))
    try:
        private_directory(candidate, 0)
        copy_upload_file(incoming / "release.json", candidate / "release.json", local_uid, MAX_BUNDLE)
        copy_upload_file(incoming / "ty-gateway-oec-overlay.tar.gz",
                         candidate / "ty-gateway-oec-overlay.tar.gz", local_uid, MAX_ARTIFACT)
        directory_fd = os.open(candidate, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        return candidate
    except Exception:
        shutil.rmtree(candidate, ignore_errors=True)
        raise


def cleanup_candidate(name):
    if not isinstance(name, str) or not CANDIDATE_ID.fullmatch(name):
        return
    path = OFFLINE_CANDIDATES / name
    try:
        private_directory(OFFLINE_CANDIDATES, 0)
        private_directory(path, 0)
        shutil.rmtree(path)
    except FileNotFoundError:
        return


class Controller:
    def __init__(self, local_uid):
        self.lock = threading.Lock()
        self.local_uid = local_uid

    def status(self):
        current = saved_json("current.json")
        pending = saved_json("pending.json")
        last = saved_json("job.json")
        unit = last.get("unit") if last else None
        if unit and not JOB_UNIT.fullmatch(unit):
            unit = None
        job = unit_state(unit) if unit else None
        if job is not None and last and last.get("offline_stage"):
            job["mode"] = "offline"
        active = job is not None and job["active"] in ("active", "activating", "deactivating", "reloading")
        if job is not None and not active and job.get("active") != "unknown":
            cleanup_candidate(last.get("offline_stage") if last else None)
        return {"version": current.get("version") if current else None,
                "channel": current.get("channel") if current else None,
                "updating": pending is not None or active,
                "job": job}

    def admin_status(self, command_id):
        record_path = STATE / ("admin-job-" + command_id + ".json")
        last = saved_json(record_path.name)
        if last is None:
            # A damaged record must not turn into permission to execute the
            # same command a second time.
            return {"state": "failed"} if record_path.exists() or record_path.is_symlink() else {"state": "absent"}
        if last.get("command_id") != command_id:
            return {"state": "failed"}
        started_at = last.get("started_at")
        if type(started_at) not in (int, float) or started_at <= 0:
            return {"state": "failed"}
        if last.get("operation") not in ("apply", "rollback"):
            return {"state": "failed"}
        if last.get("target_version") is None:
            return {"state": "failed"}
        unit = last.get("unit")
        target = last.get("target_version")
        if not isinstance(unit, str) or not JOB_UNIT.fullmatch(unit) or not isinstance(target, str) or not VERSION.fullmatch(target):
            return {"state": "failed"}
        job = unit_state(unit)
        current = saved_json("current.json")
        pending = saved_json("pending.json")
        if (pending is not None and pending.get("version") == target) or job["active"] in ("active", "activating", "deactivating", "reloading"):
            result = "running"
        elif job["result"] == "success" and current and current.get("version") == target:
            result = "succeeded"
        elif job["result"] == "success":
            result = "failed"
        elif job["result"] not in ("success", "unknown"):
            result = "failed"
        elif current and current.get("version") == target:
            # The updater writes current.json only after its health checks.
            result = "succeeded"
        elif time.time() - started_at > 1800:
            result = "failed"
        else:
            result = "running"
        return {"state": result, "target_version": target, "current_version": current.get("version") if current else None}

    def handle(self, request, role="local"):
        action = request.get("action")
        if role == "agent":
            command_id = request["command_id"]
            prior = self.admin_status(command_id)
            if action == "admin-status":
                return prior
            if prior["state"] != "absent":
                return prior
            with self.lock:
                prior = self.admin_status(command_id)
                if prior["state"] != "absent":
                    return prior
                if self.status()["updating"]:
                    raise ValueError("已有软件更新在进行。")
                current = saved_json("current.json")
                if action == "admin-apply":
                    channel, version = request["channel"], request["version"]
                    candidate = json.loads(run_fixed(str(UPDATE), "check", "--channel", channel, timeout=30))
                    if candidate.get("version") != version or not candidate.get("update_available"):
                        return {"state": "failed"}  # stale or non-upgrade approval
                    operation, target = "apply", version
                    argv = (str(UPDATE), "apply-online", "--channel", channel, "--expect-version", version)
                elif action == "admin-rollback":
                    if not current or current.get("version") != request["version"]:
                        return {"state": "failed"}
                    previous = current.get("previous")
                    if not isinstance(previous, dict) or not VERSION.fullmatch(previous.get("version", "")):
                        return {"state": "failed"}
                    # A legacy Agent cannot acknowledge the command after its
                    # files are restored. Require a snapshot made by a release
                    # that already supports the remote maintenance protocol.
                    if previous.get("remote_maintenance_protocol") != 1:
                        return {"state": "failed"}
                    if previous["version"] == current["version"]:
                        return {"state": "failed"}
                    operation, target = "rollback", previous["version"]
                    argv = (str(UPDATE), "rollback")
                else:
                    raise ValueError("不支持的软件更新操作。")
                # A stable unit name keeps a retry from launching a second
                # installer if the root process dies after systemd-run starts
                # but before the durable job record is written.
                unit = "ty-gateway-update-job-" + command_id[:12] + ".service"
                run_fixed("/usr/bin/systemd-run", "--unit=" + unit,
                          "--description=TY Gateway administrator signed maintenance",
                          "--property=Type=exec", "--property=RuntimeMaxSec=1800", *argv, timeout=15)
                save_job(unit, target, command_id=command_id, operation=operation, target_version=target)
                return {"state": "running", "target_version": target}
        if action == "status":
            return self.status()
        if action == "check":
            with self.lock:
                if self.status()["updating"]:
                    raise ValueError("设备正在升级，请稍后再检查。")
                result = run_fixed(str(UPDATE), "check", "--channel", "stable", timeout=30)
                value = json.loads(result)
                return {"version": value["version"], "update_available": bool(value["update_available"])}
        if action == "apply":
            with self.lock:
                if self.status()["updating"]:
                    raise ValueError("已有软件更新在进行。")
                candidate = json.loads(run_fixed(str(UPDATE), "check", "--channel", "stable", timeout=30))
                if not candidate.get("update_available"):
                    return {"started": False, "message": "已经是当前稳定版。"}
                unit = "ty-gateway-update-job-" + secrets.token_hex(6) + ".service"
                run_fixed("/usr/bin/systemd-run", "--unit=" + unit, "--description=TY Gateway signed update",
                          "--property=Type=exec", "--property=RuntimeMaxSec=1800",
                          str(UPDATE), "apply-online", "--channel", "stable", timeout=15)
                save_job(unit, candidate["version"])
                return {"started": True, "version": candidate["version"]}
        if action == "apply-local":
            channel = request.get("channel")
            if channel not in CHANNELS:
                raise ValueError("请选择有效的软件版本通道。")
            with self.lock:
                if self.status()["updating"]:
                    raise ValueError("已有软件更新在进行。")
                candidate = stage_offline_upload(request.get("upload_id"), self.local_uid)
                unit = "ty-gateway-update-job-" + secrets.token_hex(6) + ".service"
                try:
                    run_fixed("/usr/bin/systemd-run", "--unit=" + unit,
                              "--description=TY Gateway signed offline update",
                              "--property=Type=exec", "--property=RuntimeMaxSec=1800",
                              str(UPDATE), "apply-local", "--channel", channel,
                              "--bundle", str(candidate / "release.json"),
                              "--artifact", str(candidate / "ty-gateway-oec-overlay.tar.gz"), timeout=15)
                    save_job(unit, None, candidate.name)
                except Exception:
                    cleanup_candidate(candidate.name)
                    raise
                return {"started": True, "channel": channel}
        raise ValueError("不支持的软件更新操作。")


def main():
    if os.geteuid() != 0:
        raise RuntimeError("root service required")
    group_uid = pwd.getpwnam("tylocal").pw_uid
    group_gid = pwd.getpwnam("tylocal").pw_gid
    agent_uid = pwd.getpwnam("tygateway").pw_uid
    agent_gid = pwd.getpwnam("tygateway").pw_gid
    SOCKET.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    if SOCKET.parent.is_symlink() or not SOCKET.parent.is_dir():
        raise RuntimeError("update socket directory is unsafe")
    os.chown(SOCKET.parent, 0, group_gid)
    # Traverse-only for other users; the two sockets have separate group ACLs.
    os.chmod(SOCKET.parent, 0o711)
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    if STATE.is_symlink() or not STATE.is_dir() or STATE.stat().st_uid != 0 or STATE.stat().st_mode & 0o077:
        raise RuntimeError("update state directory is unsafe")
    for socket_path in (SOCKET, AGENT_SOCKET):
        if socket_path.exists() or socket_path.is_symlink():
            socket_path.unlink()
    controller = Controller(group_uid)

    def handler_for(role, allowed_uid):
        class Handler(socketserver.StreamRequestHandler):
            def handle(self):
                self.request.settimeout(300)
                credentials = self.request.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
                _, peer_uid, _ = struct.unpack("3i", credentials)
                if peer_uid not in (0, allowed_uid):
                    return
                try:
                    raw = self.rfile.readline(MAX_REQUEST + 1)
                    if len(raw) > MAX_REQUEST:
                        raise ValueError("请求过大。")
                    request = json.loads(raw)
                    validate_request(request, role)
                    response = controller.handle(request, role)
                except (ValueError, RuntimeError, KeyError, OSError, subprocess.TimeoutExpired):
                    response = {"error": "软件更新请求未完成，请稍后重试或联系管理员。"}
                except Exception:
                    response = {"error": "软件更新服务暂时不可用。"}
                self.wfile.write((json.dumps(response) + "\n").encode())
        return Handler

    class Server(socketserver.ThreadingUnixStreamServer):
        daemon_threads = True

    with Server(str(SOCKET), handler_for("local", group_uid)) as server, Server(str(AGENT_SOCKET), handler_for("agent", agent_uid)) as agent_server:
        os.chown(SOCKET, 0, group_gid)
        os.chmod(SOCKET, 0o660)
        os.chown(AGENT_SOCKET, 0, agent_gid)
        os.chmod(AGENT_SOCKET, 0o660)
        agent_thread = threading.Thread(target=agent_server.serve_forever, kwargs={"poll_interval": 0.5}, daemon=True)
        agent_thread.start()
        try:
            server.serve_forever(poll_interval=0.5)
        finally:
            agent_server.shutdown()
            agent_thread.join(timeout=5)


if __name__ == "__main__":
    main()
