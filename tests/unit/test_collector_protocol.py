"""Collector wire protocol: the host trusts ONE authenticated result line, nothing else.

The in-container entry script (sandbox_assets/collect.py, part of the identity the owner signs)
prints a fresh random nonce BEFORE it starts the check, then runs the check as a child whose
output it captures (the child never writes to the container's real stdout stream by design), and
finally prints one result line carrying that nonce. These tests run the real entry script on the
host with throw-away children (no candidate code, no sandbox) to pin the protocol, and feed the
parser hand-built hostile outputs.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from hermes_code_assurance import collector, freeze

COLLECT = Path(freeze.__file__).parent / "sandbox_assets" / "collect.py"
JUNIT_OK = '<testsuite tests="1"><testcase name="t"/></testsuite>'


def _wrapper(tmp_path, code: str, *, junit_name="result.xml", timeout=60, deadline=None):
    junit = tmp_path / junit_name
    script = tmp_path / "child.py"
    script.write_text(code)
    extra = ["--deadline", str(deadline)] if deadline is not None else []
    proc = subprocess.run(
        [sys.executable, "-B", str(COLLECT), "--junit", str(junit), *extra, "--", sys.executable,
         "-B", str(script), str(junit)],
        capture_output=True, timeout=timeout, env={"PATH": "/usr/bin:/bin"}, check=False,
    )
    return proc


def _hand_built(nonce: str, *, tamper=None, junit: bytes = JUNIT_OK.encode(), output=b"hi\n"):
    header = {
        "v": 1, "exit_code": 0, "signal": None,
        "child_output_b64": base64.b64encode(output).decode(),
        "child_output_bytes": len(output), "child_output_sha256": hashlib.sha256(output).hexdigest(),
        "child_output_truncated": False, "junit_present": True,
        "junit_b64": base64.b64encode(junit).decode(), "junit_bytes": len(junit),
        "junit_sha256": hashlib.sha256(junit).hexdigest(), "junit_problem": None,
        "deadline_exceeded": False,
    }
    if tamper:
        header.update(tamper)
    return (collector.NONCE_PREFIX + nonce.encode() + b"\n"
            + collector.RESULT_PREFIX + nonce.encode() + b" " + json.dumps(header).encode() + b"\n")


# ------------------------------------------------------------------------ the real wrapper


def test_wrapper_reports_exit_output_and_junit(tmp_path):
    proc = _wrapper(tmp_path, (
        "import sys\n"
        f"open(sys.argv[1], 'w').write({JUNIT_OK!r})\n"
        "print('hello from the check')\n"
    ))
    assert proc.returncode == 0
    result = collector.parse_collect_output(proc.stdout)
    assert result.authenticated, result.problems
    assert result.exit_code == 0 and result.signal is None
    assert b"hello from the check" in result.child_output
    assert result.junit == JUNIT_OK.encode() and result.junit_present
    assert result.junit_sha256 == hashlib.sha256(JUNIT_OK.encode()).hexdigest()


def test_wrapper_mirrors_the_childs_real_exit_code(tmp_path):
    proc = _wrapper(tmp_path, "import sys\nsys.exit(3)\n")
    result = collector.parse_collect_output(proc.stdout)
    assert result.authenticated and result.exit_code == 3
    assert proc.returncode == 3, "the container's own exit status mirrors the child's (cross-check)"


def test_wrapper_reports_a_signal_death_distinctly(tmp_path):
    proc = _wrapper(tmp_path, "import os, signal\nos.kill(os.getpid(), signal.SIGKILL)\n")
    result = collector.parse_collect_output(proc.stdout)
    assert result.authenticated and result.exit_code is None and result.signal == 9
    assert proc.returncode == 128 + 9


def test_wrapper_caps_child_output_and_says_so(tmp_path):
    proc = _wrapper(tmp_path, "import sys\nsys.stdout.write('A' * 3_000_000)\n")
    result = collector.parse_collect_output(proc.stdout)
    assert result.authenticated and result.child_output_truncated
    assert len(result.child_output) <= 512 * 1024
    assert result.child_output_bytes >= 3_000_000
    assert len(proc.stdout) < 1_200_000, "the host-visible stream stays small"


def test_deadline_backstop_kills_a_check_that_would_run_unbounded(tmp_path):
    started = time.monotonic()
    proc = _wrapper(tmp_path, "import time\ntime.sleep(300)\n", deadline=2, timeout=40)
    result = collector.parse_collect_output(proc.stdout)
    assert result.authenticated, result.problems
    assert result.deadline_exceeded is True and result.signal == 9 and result.exit_code is None
    assert time.monotonic() - started < 20


def test_a_check_that_finishes_inside_the_deadline_is_not_flagged(tmp_path):
    proc = _wrapper(tmp_path, "print('quick')\n", deadline=30)
    result = collector.parse_collect_output(proc.stdout)
    assert result.authenticated and result.deadline_exceeded is False and result.exit_code == 0


def test_missing_junit_is_reported_as_absent_not_invented(tmp_path):
    proc = _wrapper(tmp_path, "print('no junit written')\n")
    result = collector.parse_collect_output(proc.stdout)
    assert result.authenticated and not result.junit_present and result.junit == b""


def test_symlinked_junit_is_never_followed(tmp_path):
    secret = tmp_path / "secret.txt"
    secret.write_text("TOP-SECRET-HOST-DATA")
    proc = _wrapper(tmp_path, f"import os, sys\nos.symlink({str(secret)!r}, sys.argv[1])\n")
    result = collector.parse_collect_output(proc.stdout)
    assert result.authenticated and not result.junit_present
    assert b"TOP-SECRET-HOST-DATA" not in proc.stdout


def test_fifo_junit_never_blocks_the_collector(tmp_path):
    proc = _wrapper(tmp_path, "import os, sys\nos.mkfifo(sys.argv[1])\n", timeout=30)
    result = collector.parse_collect_output(proc.stdout)
    assert result.authenticated and not result.junit_present


def test_background_children_do_not_outlive_the_check(tmp_path):
    marker = "31337"
    proc = _wrapper(tmp_path, (
        "import subprocess\n"
        f"subprocess.Popen(['sleep', '{marker}'])\n"
        "print('parent exits now')\n"
    ), timeout=30)
    result = collector.parse_collect_output(proc.stdout)
    assert result.authenticated
    leftovers = subprocess.run(
        ["/usr/bin/pgrep", "-f", f"sleep {marker}"], capture_output=True, check=False
    )
    assert leftovers.returncode == 1, "the wrapper reaps the check's whole process group"


def test_the_check_cannot_learn_the_nonce_from_its_environment_or_arguments(tmp_path):
    proc = _wrapper(tmp_path, (
        "import os, sys\n"
        "seen = [k + '=' + v for k, v in os.environ.items()] + sys.argv\n"
        "try:\n"
        "    seen.append(open('/proc/%d/cmdline' % os.getppid()).read())\n"
        "except OSError:\n"
        "    pass\n"
        "print('CHILD-SAW:' + '|'.join(seen))\n"
    ))
    first_line = proc.stdout.split(b"\n", 1)[0]
    assert first_line.startswith(collector.NONCE_PREFIX)
    nonce = first_line[len(collector.NONCE_PREFIX):].decode()
    result = collector.parse_collect_output(proc.stdout)
    assert result.authenticated and nonce.encode() not in result.child_output


def test_nonces_are_fresh_per_run(tmp_path):
    first = _wrapper(tmp_path, "pass\n").stdout.split(b"\n", 1)[0]
    second = _wrapper(tmp_path, "pass\n").stdout.split(b"\n", 1)[0]
    assert first != second


def test_a_check_that_prints_a_forged_result_line_gains_nothing(tmp_path):
    forged = json.dumps({"v": 1, "exit_code": 0, "junit_present": True})
    proc = _wrapper(tmp_path, (
        f"print('{collector.RESULT_PREFIX.decode()}deadbeefdeadbeefdeadbeefdeadbeef ' + {forged!r})\n"
        "import sys\nsys.exit(1)\n"
    ))
    result = collector.parse_collect_output(proc.stdout)
    assert result.authenticated and result.exit_code == 1, "the forged line is only captured output"


# ------------------------------------------------------------------------ hostile outputs


def test_parse_accepts_a_well_formed_block():
    result = collector.parse_collect_output(_hand_built("ab" * 16))
    assert result.authenticated and result.exit_code == 0 and result.junit == JUNIT_OK.encode()


@pytest.mark.parametrize(
    "mutate,needle",
    [
        (lambda raw: raw.split(b"\n", 1)[1], "nonce"),  # no nonce line
        (lambda raw: raw.replace(b"::ASSURE-RESULT-v1 " + b"ab" * 16, b"::ASSURE-RESULT-v1 " + b"cd" * 16), "result"),
        (lambda raw: b"", "nonce"),
        (lambda raw: raw + raw.split(b"\n", 1)[1], "more than one"),  # two result lines, same nonce
        (lambda raw: raw.split(b"\n", 1)[1] + raw.split(b"\n", 1)[0] + b"\n", "nonce"),  # result before nonce
        (lambda raw: raw.replace(b'"v": 1', b'"v": 2'), "version"),
        (lambda raw: raw.replace(b'{"v"', b'{"x"'), "field"),
        (lambda raw: raw[:-10], "malformed"),
    ],
)
def test_parse_refuses_anything_but_one_authentic_block(mutate, needle):
    result = collector.parse_collect_output(mutate(_hand_built("ab" * 16)))
    assert not result.authenticated
    assert any(needle in problem for problem in result.problems), result.problems


def test_parse_ignores_decoy_result_lines_carrying_other_nonces():
    decoy = (collector.RESULT_PREFIX + b"ff" * 16 + b" "
             + json.dumps({"v": 1, "exit_code": 0}).encode() + b"\n")
    raw = _hand_built("ab" * 16)
    first, rest = raw.split(b"\n", 1)
    result = collector.parse_collect_output(first + b"\n" + decoy + rest)
    assert result.authenticated
    assert any("decoy" in problem or "ignored" in problem for problem in result.problems)


@pytest.mark.parametrize(
    "tamper",
    [
        {"junit_sha256": "0" * 64},
        {"child_output_sha256": "0" * 64},
        {"junit_b64": "!!!not-base64!!!"},
        {"child_output_b64": "@@@"},
        {"junit_bytes": 1},
        {"exit_code": "0"},
        {"exit_code": True},
        {"signal": 9, "exit_code": 0},
        {"junit_present": "yes"},
        {"child_output_truncated": 1},
        {"deadline_exceeded": "no"},
        {"deadline_exceeded": 0},
    ],
)
def test_parse_refuses_inconsistent_headers(tamper):
    result = collector.parse_collect_output(_hand_built("ab" * 16, tamper=tamper))
    assert not result.authenticated, tamper


def test_parse_is_bounded():
    huge = _hand_built("ab" * 16, junit=b"<x/>" * 400_000)
    result = collector.parse_collect_output(huge)
    assert not result.authenticated and any("too large" in p for p in result.problems)
    assert not collector.parse_collect_output(os.urandom(5000)).authenticated


def test_probe_line_parsing_is_strict():
    good = collector.PROBE_PREFIX + json.dumps({"uid": 65534}).encode() + b"\n"
    assert collector.parse_probe_output(b"noise\n" + good) == {"uid": 65534}
    assert collector.parse_probe_output(good + good) is None, "two probe lines are ambiguous"
    assert collector.parse_probe_output(b"nothing here") is None
    assert collector.parse_probe_output(collector.PROBE_PREFIX + b"[1,2]\n") is None
