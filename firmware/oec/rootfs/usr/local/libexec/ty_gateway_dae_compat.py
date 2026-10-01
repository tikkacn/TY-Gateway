#!/usr/bin/env python3
"""One-shot DAE ingress compatibility check, invoked by systemd as root.

Linux before 6.6 rejects SO_REUSEPORT sockets in TC bpf_sk_assign. DAE 2.1.1
enables that flag on its transparent ingress listeners. Duplicate only verified
DAE listener descriptors through pidfd_getfd; never change outbound sockets,
configuration, node selection, forwarding sysctls or the installed DAE binary.
"""
import argparse
import contextlib
import ctypes
import errno
import os
from pathlib import Path
import platform
import re
import socket
import sys
import time

DAE_BINARY = Path('/usr/bin/dae')
SO_COOKIE = 57
IP_TRANSPARENT = 19
IPV6_TRANSPARENT = 75
EXPECTED_ROLES = {'tcp4', 'tcp6', 'udp'}


class CompatibilityError(RuntimeError):
    pass


class ListenersNotReady(CompatibilityError):
    pass


def needs_compatibility(release):
    match = re.match(r'^(\d+)\.(\d+)(?:\.|-|$)', release)
    if not match:
        raise CompatibilityError('cannot identify kernel version safely')
    return tuple(map(int, match.groups())) < (6, 6)


def syscall(number, *args):
    if platform.machine().lower() not in ('aarch64', 'arm64', 'x86_64', 'amd64'):
        raise CompatibilityError('unsupported architecture for pidfd inspection')
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    result = libc.syscall(ctypes.c_long(number), *(ctypes.c_long(arg) for arg in args))
    if result < 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))
    return result


def verify_process(pid):
    if pid <= 1 or not os.path.samefile(f'/proc/{pid}/exe', DAE_BINARY):
        raise CompatibilityError('refusing to inspect a process other than installed DAE')
    status = Path(f'/proc/{pid}/status').read_text()
    uid = re.search(r'^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)', status, re.M)
    if not uid or any(int(value) != 0 for value in uid.groups()):
        raise CompatibilityError('DAE process must be root-owned')


def listener_role(sock):
    if sock.family not in (socket.AF_INET, socket.AF_INET6):
        return None
    address = sock.getsockname()
    if address[0] not in ('0.0.0.0', '::') or not 1 <= address[1] <= 65535:
        return None
    transparent = False
    for level, option in ((socket.SOL_IP, IP_TRANSPARENT),
                          (socket.IPPROTO_IPV6, IPV6_TRANSPARENT)):
        try:
            transparent |= bool(sock.getsockopt(level, option))
        except OSError:
            pass
    if not transparent:
        return None
    kind = sock.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE)
    if kind == socket.SOCK_STREAM and sock.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN):
        role = 'tcp4' if sock.family == socket.AF_INET else 'tcp6'
    elif kind == socket.SOCK_DGRAM:
        try:
            sock.getpeername()
        except OSError as exc:
            if exc.errno != errno.ENOTCONN:
                return None
        else:
            return None
        role = 'udp'
    else:
        return None
    return role, address[1]


def choose_listeners(candidates):
    """Require exactly one coherent ingress triplet before changing any socket."""
    by_port = {}
    for cookie, (role, port, sock) in candidates.items():
        by_port.setdefault(port, {}).setdefault(role, []).append((cookie, sock))
    complete = [roles for roles in by_port.values() if set(roles) == EXPECTED_ROLES]
    if not complete:
        raise ListenersNotReady('waiting for DAE transparent TCP4/TCP6/UDP listeners')
    if len(complete) != 1 or any(len(sockets) != 1 for sockets in complete[0].values()):
        raise CompatibilityError('ambiguous DAE ingress sockets; no socket was changed')
    return {role: sockets[0][1] for role, sockets in complete[0].items()}


@contextlib.contextmanager
def ingress_sockets(pid):
    verify_process(pid)
    pidfd = syscall(434, pid, 0)  # pidfd_open; pins the process, avoiding PID reuse.
    with contextlib.ExitStack() as stack:
        stack.callback(os.close, pidfd)
        verify_process(pid)
        candidates = {}
        entries = list(Path(f'/proc/{pid}/fd').iterdir())
        if len(entries) > 8192:
            raise CompatibilityError('DAE descriptor count exceeds inspection limit')
        for entry in entries:
            try:
                if not os.readlink(entry).startswith('socket:['):
                    continue
                fd = syscall(438, pidfd, int(entry.name), 0)  # pidfd_getfd
            except OSError as exc:
                if exc.errno in (errno.ENOENT, errno.EBADF):
                    continue  # Descriptor closed concurrently; retry the snapshot if necessary.
                raise
            try:
                sock = socket.socket(fileno=fd)
            except BaseException:
                os.close(fd)
                raise
            stack.enter_context(sock)
            role = listener_role(sock)
            if role is None:
                continue
            cookie = int.from_bytes(sock.getsockopt(socket.SOL_SOCKET, SO_COOKIE, 8), sys.byteorder)
            if cookie not in candidates:
                candidates[cookie] = (*role, sock)
        yield choose_listeners(candidates)


def fix_listeners(listeners, check_only=False):
    before = {role: sock.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT)
              for role, sock in listeners.items()}
    if check_only:
        if any(before.values()):
            raise CompatibilityError('DAE ingress compatibility is not applied')
        return 0
    changed = []
    try:
        for role, sock in listeners.items():
            if before[role]:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 0)
                changed.append(role)
            if sock.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT) != 0:
                raise CompatibilityError('DAE ingress compatibility verification failed')
    except BaseException:
        for role in changed:
            listeners[role].setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, before[role])
        raise
    return len(changed)


def apply(pid, check_only=False, timeout=15):
    if not needs_compatibility(platform.release()):
        return 'kernel supports reuseport assignment; compatibility adjustment skipped'
    if os.geteuid() != 0:
        raise CompatibilityError('root privileges are required')
    deadline = time.monotonic() + timeout
    while True:
        try:
            with ingress_sockets(pid) as listeners:
                changed = fix_listeners(listeners, check_only)
            return f'legacy kernel ingress verified; listeners=3 changed={changed}'
        except ListenersNotReady:
            if time.monotonic() >= deadline:
                raise CompatibilityError('DAE ingress listeners were not ready before timeout')
            time.sleep(0.25)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('pid', type=int, help='DAE MAINPID provided by systemd')
    parser.add_argument('--check', action='store_true', help='verify without changing sockets')
    args = parser.parse_args()
    try:
        print('TY DAE compatibility: ' + apply(args.pid, args.check), flush=True)
    except (CompatibilityError, OSError) as exc:
        print(f'TY DAE compatibility failed: {exc}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
