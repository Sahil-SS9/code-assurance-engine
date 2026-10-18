"""Evaluator-owned collector entry point. Standard library only.

Identity-bound: the owner's signed request pins the digest of this file (with probe.py). It is
mounted read-only into the sandbox at /entry and runs INSIDE the isolated container.

Protocol (see hermes_code_assurance.collector):
  1. print ``::ASSURE-NONCE-v1 <fresh random nonce>`` as the very first output;
  2. run the check argv (everything after ``--``) as a child, capturing its stdout+stderr;
     the child never receives the nonce (not in its environment, argv or inherited descriptors);
  3. when the child exits, kill whatever is left of its process group;
  4. read the junit file (regular file only, never a symlink or FIFO, size-capped);
  5. print ONE ``::ASSURE-RESULT-v1 <nonce> <json>`` line and exit with the child's own status.

Usage:  python -B collect.py --junit /tmp/result.xml [--deadline SECONDS] -- <check argv...>

``--deadline`` is a backstop: the host enforces the real timeout, but if the host driver itself dies
the container still stops its check at the deadline instead of running unbounded.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import selectors
import signal
import stat
import subprocess
import sys
import time

CHILD_OUTPUT_CAP = 512 * 1024
JUNIT_CAP = 1024 * 1024
DRAIN_GRACE_SECONDS = 1.0
NONCE_PREFIX = b"::ASSURE-NONCE-v1 "
RESULT_PREFIX = b"::ASSURE-RESULT-v1 "


def _read_junit(path):
    """(bytes|None, problem|None). Absent is not a problem; unsafe is reported, never followed."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except FileNotFoundError:
        return None, None
    except OSError as exc:
        return None, "junit path cannot be opened safely (%s)" % (exc.strerror or exc)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            return None, "junit path is not a regular file"
        if info.st_size > JUNIT_CAP:
            return None, "junit file is larger than the cap"
        data = b""
        while len(data) <= JUNIT_CAP:
            block = os.read(fd, 65536)
            if not block:
                break
            data += block
        if len(data) > JUNIT_CAP:
            return None, "junit file is larger than the cap"
        return data, None
    finally:
        os.close(fd)


def _kill_group(pgid):
    try:
        os.killpg(pgid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


def _run_child(argv, deadline=None):
    """Run the check; return (exit_code|None, signal|None, captured, total_bytes, deadline_hit)."""
    try:
        proc = subprocess.Popen(
            argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            start_new_session=True, close_fds=True,
        )
    except OSError as exc:
        message = ("collector could not start the check: %s\n" % (exc.strerror or exc)).encode()
        return 127, None, message, len(message), False
    fd = proc.stdout.fileno() if proc.stdout is not None else -1
    if fd < 0:
        return 127, None, b"collector could not capture the check output\n", 0, False
    selector = selectors.DefaultSelector()
    selector.register(fd, selectors.EVENT_READ)
    captured = bytearray()
    total = 0
    exited_at = None
    started = time.monotonic()
    deadline_hit = False
    while True:
        if deadline is not None and not deadline_hit and time.monotonic() - started > deadline:
            deadline_hit = True  # backstop: the host normally enforces the deadline first
            _kill_group(proc.pid)
        if selector.select(timeout=0.2):
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            total += len(chunk)
            room = CHILD_OUTPUT_CAP - len(captured)
            if room > 0:
                captured += chunk[:room]
        if proc.poll() is not None:
            if exited_at is None:
                exited_at = time.monotonic()
                _kill_group(proc.pid)
            elif time.monotonic() - exited_at > DRAIN_GRACE_SECONDS:
                break
    returncode = proc.wait()
    _kill_group(proc.pid)
    if returncode < 0:
        return None, -returncode, bytes(captured), total, deadline_hit
    return returncode, None, bytes(captured), total, deadline_hit


def main(argv):
    if "--" not in argv or "--junit" not in argv[: argv.index("--")]:
        sys.stderr.write("usage: collect.py --junit PATH [--deadline SECONDS] -- CHECK_ARGV...\n")
        return 64
    split = argv.index("--")
    options, child = argv[:split], argv[split + 1:]
    junit_path = options[options.index("--junit") + 1]
    deadline = None
    if "--deadline" in options:
        try:
            deadline = float(options[options.index("--deadline") + 1])
        except (ValueError, IndexError):
            sys.stderr.write("--deadline needs a number of seconds\n")
            return 64
    if not child:
        sys.stderr.write("no check command supplied\n")
        return 64

    nonce = os.urandom(16).hex().encode()
    out = sys.stdout.buffer
    out.write(NONCE_PREFIX + nonce + b"\n")
    out.flush()

    exit_code, sig, captured, total, deadline_hit = _run_child(child, deadline)
    junit_bytes, problem = _read_junit(junit_path)
    junit = junit_bytes or b""
    header = {
        "v": 1,
        "exit_code": exit_code,
        "signal": sig,
        "child_output_b64": base64.b64encode(captured).decode(),
        "child_output_bytes": total,
        "child_output_sha256": hashlib.sha256(captured).hexdigest(),
        "child_output_truncated": total > CHILD_OUTPUT_CAP,
        "junit_present": junit_bytes is not None,
        "junit_b64": base64.b64encode(junit).decode(),
        "junit_bytes": len(junit),
        "junit_sha256": hashlib.sha256(junit).hexdigest(),
        "junit_problem": problem,
        "deadline_exceeded": deadline_hit,
    }
    out.write(RESULT_PREFIX + nonce + b" " + json.dumps(header, sort_keys=True).encode() + b"\n")
    out.flush()
    if exit_code is not None:
        return exit_code
    return 128 + (sig or 0)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
