"""Evaluator-owned isolation probe. Standard library only; no repository code is involved.

Runs INSIDE the freshly created sandbox, with exactly the policy and mounts a real check gets, and
prints ONE ``::ASSURE-PROBE-v1 <json>`` line of raw OBSERVATIONS (no verdict). The host compares
those observations with what the policy requires and refuses to execute anything if any control
is missing. It only reads local files and attempts a few harmless local writes; it never sends
network traffic outside the container.

Part of the identity bound by the owner's signed request (with collect.py).
"""

from __future__ import annotations

import errno
import json
import os
import socket
import stat
import subprocess
import sys

PREFIX = b"::ASSURE-PROBE-v1 "
MOUNTS = ("/candidate", "/oracle", "/toolchain", "/entry")
HOST_PATHS = (
    "/var/run/docker.sock", "/run/docker.sock", "/run/user", "/run/dbus", "/run/systemd/private",
    "/home/kensei", "/home/sahil", "/root/.ssh", "/root/.aws", "/root/.config", "/hermes",
)


def attempt(action):
    """errno of a failed action, 0 when it succeeded, -1 when it failed without an errno."""
    try:
        action()
    except OSError as exc:
        return exc.errno or -1
    except Exception:  # noqa: BLE001 - an unexpected failure is recorded, never raised
        return -1
    return 0


def try_create(directory):
    target = os.path.join(directory, "_assure_probe")

    def create():
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(fd)

    code = attempt(create)
    if code == 0:  # contained nothing: clean up so frozen inputs stay pristine
        attempt(lambda: os.unlink(target))
    return code


def try_exec_in_tmp():
    target = "/tmp/_assure_exec"
    with open(target, "w") as stream:
        stream.write("#!/bin/sh\nexit 0\n")
    os.chmod(target, 0o755)
    try:
        subprocess.run([target], check=False, capture_output=True, timeout=10)
        code = 0
    except PermissionError as exc:
        code = exc.errno or errno.EACCES
    except OSError as exc:
        code = exc.errno or -1
    finally:
        attempt(lambda: os.unlink(target))
    return code


def status_fields():
    wanted = {"CapEff", "CapBnd", "CapPrm", "NoNewPrivs", "Seccomp"}
    found = {}
    with open("/proc/self/status") as stream:
        for line in stream:
            key, _, value = line.partition(":")
            if key in wanted:
                found[key] = value.strip()
    return found


def cgroup_values():
    values = {}
    for name in ("memory.max", "memory.swap.max", "pids.max", "cpu.max"):
        try:
            with open("/sys/fs/cgroup/" + name) as stream:
                values[name] = stream.read().strip()
        except OSError as exc:
            values[name] = f"unreadable:{exc.errno}"
    return values


def mount_options():
    options = {}
    with open("/proc/self/mountinfo") as stream:
        for line in stream:
            parts = line.split()
            if len(parts) < 7:
                continue
            mountpoint, per_mount = parts[4], parts[5].split(",")
            separator = parts.index("-") if "-" in parts else len(parts)
            super_options = parts[separator + 3].split(",") if len(parts) > separator + 3 else []
            options[mountpoint] = {"mount": per_mount, "super": super_options}
    return {point: options.get(point) for point in ("/", "/tmp", *MOUNTS)}


def network():
    interfaces = []
    with open("/proc/net/dev") as stream:
        for line in stream.read().splitlines()[2:]:
            interfaces.append(line.split(":", 1)[0].strip())
    default_route = False
    try:
        with open("/proc/net/route") as stream:
            for line in stream.read().splitlines()[1:]:
                fields = line.split()
                if len(fields) > 1 and fields[1] == "00000000":
                    default_route = True
    except OSError:
        pass
    loopback = attempt(lambda: socket.create_connection(("127.0.0.1", 9), timeout=1).close())
    return {"interfaces": sorted(interfaces), "default_route": default_route,
            "loopback_connect_errno": loopback}


def main():
    observed = {
        "uid": os.getuid(),
        "gid": os.getgid(),
        "groups": sorted(os.getgroups()),
        "status": status_fields(),
        "cgroup": cgroup_values(),
        "network": network(),
        "mount_options": mount_options(),
        "write_errno": {path: try_create(path) for path in ("/", *MOUNTS)},
        "tmp_write_errno": try_create("/tmp"),
        "tmp_exec_errno": try_exec_in_tmp(),
        "sys_write_errno": attempt(lambda: open("/sys/fs/cgroup/cgroup.procs", "w").close()),
        "proc_sys_write_errno": attempt(lambda: open("/proc/sys/kernel/hostname", "w").close()),
        "host_paths_present": sorted(path for path in HOST_PATHS if os.path.lexists(path)),
        "home_entries": sorted(os.listdir("/home")) if os.path.isdir("/home") else None,
        "pids": sorted(int(name) for name in os.listdir("/proc") if name.isdigit()),
        "env_names": sorted(os.environ),
        "dev_entries": sorted(os.listdir("/dev")),
        "python": sys.version.split()[0],
        "kernel": os.uname().release,
        "root_mode": stat.S_IMODE(os.stat("/").st_mode),
    }
    sys.stdout.buffer.write(PREFIX + json.dumps(observed, sort_keys=True).encode() + b"\n")
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
