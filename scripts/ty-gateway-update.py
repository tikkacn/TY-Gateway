#!/usr/bin/python3
"""Apply a pinned-key TY Gateway release with a durable software rollback.

This root-only command accepts only the fixed release origin through
ty-release-fetch, or a local archive whose signed bundle verifies against the
same pinned key. It never imports device identity or subscription data.
"""

import argparse
import fcntl
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time

STATE_DIR = pathlib.Path("/var/lib/ty-gateway-update")
CACHE_DIR = pathlib.Path("/var/cache/ty-gateway/releases")
FETCH = pathlib.Path("/usr/local/bin/ty-release-fetch")
KEY = pathlib.Path("/etc/ty-gateway/release-public.pem")
HEALTH_UNITS = (
    "ty-gateway-local.service", "ty-gateway-agent.service",
    "ty-gateway-network.service", "dae.service", "ty-frpc-rescue.service",
)


def private_directory(path):
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if not path.is_dir() or path.is_symlink() or info.st_uid != 0 or info.st_mode & 0o077:
        raise RuntimeError(f"unsafe updater directory: {path}")


def read_state(path):
    if not path.exists():
        return None
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 16384:
        raise RuntimeError("updater state file is unsafe")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or value.get("format_version") != 1:
        raise RuntimeError("updater state format is invalid")
    return value


def save_state(path, value):
    data = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    fd, name = tempfile.mkstemp(prefix=".update-state-", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as out:
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        os.replace(name, path)
        sync_directory(path.parent)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def remove_state(path):
    path.unlink(missing_ok=True)
    sync_directory(path.parent)


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def version_parts(version):
    if not isinstance(version, str) or len(version) > 32:
        raise RuntimeError("release version is invalid")
    parts = version.split(".")
    if len(parts) != 3 or any(not p.isascii() or not p.isdecimal() or (len(p) > 1 and p[0] == "0") for p in parts):
        raise RuntimeError("release version is invalid")
    values = tuple(int(p) for p in parts)
    if any(p > 0xFFFFFFFF for p in values):
        raise RuntimeError("release version is invalid")
    return values


def fetch(command, channel, bundle=None, artifact=None):
    argv = [str(FETCH), command, "-json", "-channel", channel, "-public-key", str(KEY)]
    if command != "check":
        argv += ["-output-dir", str(CACHE_DIR)]
    if command == "stage-local":
        argv += ["-bundle", str(bundle), "-artifact", str(artifact)]
    result = subprocess.run(argv, capture_output=True, text=True, timeout=1800, check=False)
    if result.returncode:
        raise RuntimeError("release download or signature validation failed")
    value = json.loads(result.stdout)
    if value.get("channel") != channel or not version_parts(value.get("version")):
        raise RuntimeError("release downloader returned an invalid version")
    return value


def active_units():
    result = set()
    for unit in HEALTH_UNITS:
        status = subprocess.run(["/bin/systemctl", "is-active", "--quiet", unit],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        if status.returncode == 0:
            result.add(unit)
    return result


def backup_from_report(report):
    if report.is_symlink() or not report.is_file():
        raise RuntimeError("installer did not provide a backup report")
    path = pathlib.Path(report.read_text(encoding="utf-8").strip())
    expected = STATE_DIR / "backups"
    if path.parent != expected or not path.name.startswith("ty-gateway-overlay.") or path.is_symlink():
        raise RuntimeError("installer backup path is invalid")
    if not path.is_dir() or not (path / "restore.sh").is_file():
        raise RuntimeError("installer backup is incomplete")
    return path


def restore(report):
    # The report is written before the first package mutation. If the process
    # died earlier, there is no device state to restore.
    if not report.is_file() or report.read_text(encoding="utf-8").strip() in ("", "rolled_back"):
        return False
    backup = backup_from_report(report)
    result = subprocess.run(["/bin/bash", str(backup / "restore.sh"), str(backup)],
                            timeout=180, check=False)
    if result.returncode:
        raise RuntimeError(f"software restoration needs administrator attention; backup: {backup}")
    return True


def recover_pending():
    pending_file = STATE_DIR / "pending.json"
    pending = read_state(pending_file)
    if pending is None:
        return False
    report = pathlib.Path(pending.get("report", ""))
    if report.parent != STATE_DIR or not report.name.startswith(".backup-report-"):
        raise RuntimeError("pending updater report path is invalid")
    current = read_state(STATE_DIR / "current.json")
    if current is not None and current.get("version") == pending.get("version") and report.is_file():
        try:
            backup = backup_from_report(report)
        except RuntimeError:
            backup = None
        if backup is not None and current.get("backup_dir") == str(backup):
            report.unlink(missing_ok=True)
            remove_state(pending_file)
            return False
    restored = restore(report)
    report.unlink(missing_ok=True)
    remove_state(pending_file)
    return restored


def apply_release(args):
    if read_state(STATE_DIR / "pending.json") is not None:
        raise RuntimeError("interrupted update must be recovered before another update")
    current = read_state(STATE_DIR / "current.json")
    if args.command == "apply-local":
        candidate = fetch("stage-local", args.channel, args.bundle, args.artifact)
    else:
        candidate = fetch("stage", args.channel)
    target_version = version_parts(candidate["version"])
    if args.expect_version and candidate["version"] != args.expect_version:
        raise RuntimeError("signed release version changed after administrator approval")
    if current is not None and target_version <= version_parts(current["version"]) and not args.allow_downgrade:
        raise RuntimeError("release is not newer than the installed version")
    staged = pathlib.Path(candidate.get("staged", ""))
    installer = staged / "install-oec-overlay.sh"
    if not staged.is_dir() or staged.is_symlink() or not installer.is_file() or installer.is_symlink():
        raise RuntimeError("verified installer staging is unavailable")
    required_free = max(256 << 20, int(candidate["size"]) * 2)
    if shutil.disk_usage(STATE_DIR).free < required_free:
        raise RuntimeError("insufficient free space for a recoverable software update")
    before = active_units()
    fd, report_name = tempfile.mkstemp(prefix=".backup-report-", dir=STATE_DIR)
    os.fchmod(fd, 0o600)
    os.close(fd)
    report = pathlib.Path(report_name)
    pending_file = STATE_DIR / "pending.json"
    save_state(pending_file, {"format_version": 1, "version": candidate["version"],
                              "channel": args.channel, "report": str(report), "started_at": int(time.time())})
    environment = dict(os.environ, TY_OVERLAY_KEEP_BACKUP="1", TY_OVERLAY_BACKUP_REPORT=str(report))
    try:
        install = subprocess.run(["/bin/bash", str(installer)], env=environment,
                                 timeout=600, check=False)
        if install.returncode:
            raise RuntimeError("software installer failed")
        backup = backup_from_report(report)
        # Existing active services must remain active, including the rescue
        # tunnel and DAE when the user had enabled it before the update.
        for _ in range(6):
            missing = before - active_units()
            if not missing:
                break
            time.sleep(2)
        if missing:
            raise RuntimeError("service health check failed: " + ", ".join(sorted(missing)))
        save_state(STATE_DIR / "current.json", {
            "format_version": 1, "version": candidate["version"], "channel": args.channel,
            "backup_dir": str(backup), "installed_at": int(time.time()), "previous": current,
            "remote_maintenance_protocol": 1,
        })
    except Exception:
        # A second restore is harmless if the installer already rolled back;
        # if restoration fails, pending.json survives for boot-time recovery.
        try:
            recover_pending()
        except Exception:
            raise RuntimeError("update failed and recovery remains pending; use the rescue connection") from None
        raise
    report.unlink(missing_ok=True)
    remove_state(pending_file)
    print(json.dumps({"status": "installed", "version": candidate["version"], "channel": args.channel}))


def rollback():
    current = read_state(STATE_DIR / "current.json")
    if current is None or not current.get("backup_dir"):
        raise RuntimeError("there is no installed release snapshot to restore")
    backup = pathlib.Path(current["backup_dir"])
    expected = STATE_DIR / "backups"
    if backup.parent != expected or not backup.name.startswith("ty-gateway-overlay."):
        raise RuntimeError("saved rollback path is invalid")
    before = active_units()
    result = subprocess.run(["/bin/bash", str(backup / "restore.sh"), str(backup)], timeout=180, check=False)
    if result.returncode:
        raise RuntimeError("rollback failed; backup remains available for administrator recovery")
    missing = before - active_units()
    for _ in range(6):
        if not missing:
            break
        time.sleep(2)
        missing = before - active_units()
    if missing:
        raise RuntimeError("rollback restored files but service health needs administrator attention: " + ", ".join(sorted(missing)))
    previous = current.get("previous")
    if previous is None:
        remove_state(STATE_DIR / "current.json")
    else:
        save_state(STATE_DIR / "current.json", previous)
    print(json.dumps({"status": "restored", "version": previous.get("version") if previous else None}))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("check", "apply-online", "apply-local"):
        sub = commands.add_parser(name)
        sub.add_argument("--channel", choices=("pilot", "stable"), default="pilot")
        if name != "check":
            sub.add_argument("--allow-downgrade", action="store_true")
            sub.add_argument("--expect-version", default="")
        if name == "apply-local":
            sub.add_argument("--bundle", type=pathlib.Path, required=True)
            sub.add_argument("--artifact", type=pathlib.Path, required=True)
    for name in ("status", "rollback", "recover"):
        commands.add_parser(name)
    args = parser.parse_args(argv)
    if os.geteuid() != 0:
        parser.error("root privileges are required")
    private_directory(STATE_DIR)
    private_directory(CACHE_DIR)
    lock = STATE_DIR / "operation.lock"
    with lock.open("a+b") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if args.command == "status":
            print(json.dumps({"current": read_state(STATE_DIR / "current.json"),
                              "pending": read_state(STATE_DIR / "pending.json") is not None}))
        elif args.command == "recover":
            print(json.dumps({"restored": recover_pending()}))
        elif args.command == "rollback":
            if read_state(STATE_DIR / "pending.json") is not None:
                raise RuntimeError("recover the interrupted update first")
            rollback()
        elif args.command == "check":
            candidate = fetch("check", args.channel)
            current = read_state(STATE_DIR / "current.json")
            candidate["update_available"] = (current is None or
                                             version_parts(candidate["version"]) > version_parts(current["version"]))
            print(json.dumps(candidate))
        else:
            apply_release(args)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as exc:
        print(f"TY Gateway update failed: {exc}", file=sys.stderr)
        sys.exit(1)
