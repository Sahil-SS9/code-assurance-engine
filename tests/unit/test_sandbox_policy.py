"""Sandbox policy, container launch arguments and probe evaluation (no Docker needed).

These are the pure pieces of the rootless-Docker backend: what the container is allowed to be,
and how the host judges what the in-container probe observed. The real-container behaviour is
exercised in tests/platform/test_rootless_docker_backend.py.
"""

from __future__ import annotations

import copy
import errno

import pytest

from hermes_code_assurance import sandbox
from hermes_code_assurance.sandbox import SandboxInputs, SandboxPolicy

IMAGE = "python@sha256:" + "a" * 64


def _policy(**over) -> SandboxPolicy:
    return SandboxPolicy(image=IMAGE, **over)


def _inputs(tmp_path):
    attempt = tmp_path / "attempt"
    attempt.mkdir(mode=0o700)
    paths = {}
    for name in ("candidate", "oracle", "toolchain", "entry"):
        paths[name] = attempt / name
        paths[name].mkdir(mode=0o755)
    return SandboxInputs(**paths)


# ------------------------------------------------------------------------ policy


def test_policy_requires_a_digest_pinned_image():
    for bad in ("python", "python:3.14", "python@sha256:abc", "PYTHON@sha256:" + "a" * 64, ""):
        with pytest.raises(ValueError):
            SandboxPolicy(image=bad)
    assert _policy().image == IMAGE


@pytest.mark.parametrize(
    "field,value",
    [("timeout_seconds", 0), ("timeout_seconds", 601), ("output_limit_bytes", 10),
     ("memory_mb", 8), ("memory_mb", 100_000), ("pids", 1), ("pids", 5000), ("cpus", 0),
     ("cpus", 64), ("tmpfs_mb", 0)],
)
def test_policy_rejects_out_of_range_limits(field, value):
    with pytest.raises(ValueError):
        SandboxPolicy(image=IMAGE, **{field: value})


def test_policy_digest_binds_every_limit_and_the_image():
    base = _policy().digest()
    assert base == _policy().digest()
    assert len(base) == 64
    variants = [
        _policy(timeout_seconds=61), _policy(output_limit_bytes=1_000_000), _policy(memory_mb=256),
        _policy(pids=32), _policy(cpus=2), _policy(tmpfs_mb=32),
        SandboxPolicy(image="python@sha256:" + "b" * 64),
    ]
    assert len({v.digest() for v in variants} | {base}) == len(variants) + 1


def test_policy_limits_are_the_signed_limits_object():
    assert _policy(timeout_seconds=7).limits() == {
        "timeout_seconds": 7, "output_limit_bytes": 2097152, "memory_mb": 512, "pids": 64, "cpus": 1,
    }


def test_policy_description_is_the_full_fixed_containment_contract():
    description = _policy().description()
    assert description["network"] == "none" and description["user"] == "65534:65534"
    assert description["root_filesystem"] == "read-only"
    assert description["capabilities"] == "none" and description["no_new_privileges"] is True
    assert description["mounts"] == {
        "/candidate": "ro", "/oracle": "ro", "/toolchain": "ro", "/entry": "ro",
    }
    assert description["environment"]["PYTHONPATH"] == "/candidate:/toolchain"


# ------------------------------------------------------------------------ inputs


def test_inputs_must_be_private_resolved_siblings(tmp_path):
    inputs = _inputs(tmp_path)
    inputs.validate()


def test_inputs_reject_relative_symlinked_missing_and_unsafe_paths(tmp_path):
    inputs = _inputs(tmp_path)
    bad_relative = SandboxInputs(candidate=type(inputs.candidate)("candidate"), oracle=inputs.oracle,
                                 toolchain=inputs.toolchain, entry=inputs.entry)
    with pytest.raises(sandbox.SandboxUnavailable):
        bad_relative.validate()
    link = tmp_path / "attempt" / "link"
    link.symlink_to(inputs.oracle)
    with pytest.raises(sandbox.SandboxUnavailable):
        SandboxInputs(candidate=inputs.candidate, oracle=link, toolchain=inputs.toolchain,
                      entry=inputs.entry).validate()
    with pytest.raises(sandbox.SandboxUnavailable):
        SandboxInputs(candidate=inputs.candidate, oracle=tmp_path / "attempt" / "nope",
                      toolchain=inputs.toolchain, entry=inputs.entry).validate()
    odd = tmp_path / "attempt" / "bad,name"
    odd.mkdir()
    with pytest.raises(sandbox.SandboxUnavailable):
        SandboxInputs(candidate=odd, oracle=inputs.oracle, toolchain=inputs.toolchain,
                      entry=inputs.entry).validate()


def test_inputs_must_share_one_private_attempt_directory(tmp_path):
    inputs = _inputs(tmp_path)
    other = tmp_path / "elsewhere"
    other.mkdir(mode=0o755)
    with pytest.raises(sandbox.SandboxUnavailable):
        SandboxInputs(candidate=other, oracle=inputs.oracle, toolchain=inputs.toolchain,
                      entry=inputs.entry).validate()
    inputs.candidate.parent.chmod(0o755)
    with pytest.raises(sandbox.SandboxUnavailable):
        inputs.validate()


# ------------------------------------------------------------------------ launch arguments


def _argv(tmp_path, command=("python", "-B", "-c", "print(1)")):
    inputs = _inputs(tmp_path)
    return sandbox.create_argv(_policy(), inputs, "assure-abc", list(command),
                               attempt_id="att-0123456789ab"), inputs


def test_create_argv_carries_every_containment_control(tmp_path):
    argv, _ = _argv(tmp_path)
    assert argv[0] == "create"
    for flag in ("--network=none", "--read-only", "--cap-drop=ALL", "--pull=never", "--init",
                 "--security-opt=no-new-privileges", "--user=65534:65534", "--pids-limit=64",
                 "--memory=512m", "--memory-swap=512m", "--cpus=1", "--log-driver=none"):
        assert flag in argv, flag
    assert any(a.startswith("--tmpfs") or a == "--tmpfs" for a in argv)
    tmpfs = argv[argv.index("--tmpfs") + 1]
    assert "noexec" in tmpfs and "nosuid" in tmpfs and "nodev" in tmpfs and "size=64m" in tmpfs


def test_create_argv_never_loosens_anything(tmp_path):
    argv, _ = _argv(tmp_path)
    joined = " ".join(argv)
    for forbidden in ("--privileged", "--cap-add", "--network=host", "--net=host", "--pid=host",
                      "--ipc=host", "--uts=host", "--device", "docker.sock", "unconfined", " -v ",
                      "--volume", "--userns=host", "--add-host", "--publish", " -p "):
        assert forbidden not in joined, forbidden
    assert "--rm" not in argv, "the engine removes and verifies removal itself"


def test_create_argv_mounts_exactly_four_frozen_read_only_inputs(tmp_path):
    argv, inputs = _argv(tmp_path)
    mounts = [argv[i + 1] for i, a in enumerate(argv) if a == "--mount"]
    assert len(mounts) == 4
    for spec in mounts:
        assert spec.startswith("type=bind,src=")
        assert ",readonly" in spec and "bind-recursive=disabled" in spec
    destinations = sorted(spec.split("dst=")[1].split(",")[0] for spec in mounts)
    assert destinations == ["/candidate", "/entry", "/oracle", "/toolchain"]
    sources = sorted(spec.split("src=")[1].split(",")[0] for spec in mounts)
    assert sources == sorted(str(p) for p in (inputs.candidate, inputs.oracle, inputs.toolchain,
                                              inputs.entry))


def test_create_argv_environment_is_a_fixed_constant_set(tmp_path):
    argv, _ = _argv(tmp_path)
    names = sorted(argv[i + 1].split("=", 1)[0] for i, a in enumerate(argv) if a == "--env")
    assert names == sorted([
        "HOME", "LANG", "PYTEST_DISABLE_PLUGIN_AUTOLOAD", "PYTHONDONTWRITEBYTECODE",
        "PYTHONHASHSEED", "PYTHONPATH", "PYTHONUNBUFFERED", "TMPDIR",
    ])
    assert "--workdir" in argv and argv[argv.index("--workdir") + 1] == "/candidate"


def test_create_argv_puts_the_image_then_the_command_as_separate_elements(tmp_path):
    command = ["python", "-c", "print('a b; rm -rf /')", "$(whoami)"]
    argv, _ = _argv(tmp_path, command)
    assert argv[argv.index(IMAGE) + 1:] == command, "no shell, no splitting, no interpolation"
    assert argv.count(IMAGE) == 1


def test_create_argv_labels_the_attempt_for_recovery(tmp_path):
    argv, _ = _argv(tmp_path)
    assert "hermes.code-assurance.attempt=att-0123456789ab" in argv


def test_container_names_are_deterministic_and_safe():
    one = sandbox.container_name("att-0123456789ab")
    assert one == sandbox.container_name("att-0123456789ab")
    assert one != sandbox.container_name("att-0123456789ac")
    assert one.startswith("assure-") and len(one) <= 40
    assert all(c.isalnum() or c == "-" for c in one)


def test_collector_command_wraps_the_check_without_a_shell():
    check = ["python", "-B", "-m", "pytest", "/oracle/tests"]
    assert sandbox.collector_command(check) == [
        "python", "-B", "/entry/collect.py", "--junit", "/tmp/result.xml", "--", *check,
    ]


def test_collector_command_carries_the_deadline_backstop_when_given():
    command = sandbox.collector_command(["python", "-c", "pass"], deadline_seconds=65)
    assert command[:8] == ["python", "-B", "/entry/collect.py", "--junit", "/tmp/result.xml",
                           "--deadline", "65", "--"]
    assert command[8:] == ["python", "-c", "pass"]


def test_policy_digest_binds_the_deadline_backstop():
    description = _policy().description()
    assert "--deadline" in description["collector_command"]
    assert description["collector_command"][description["collector_command"].index("--deadline") + 1] \
        == str(_policy().timeout_seconds + sandbox.DEADLINE_GRACE_SECONDS)
    assert _policy(timeout_seconds=61).digest() != _policy().digest()


# ------------------------------------------------------------------------ probe judgement


def _good(policy: SandboxPolicy) -> dict:
    ro = {"mount": ["ro", "relatime"], "super": ["ro"]}
    rw = {"mount": ["rw", "nosuid", "nodev", "noexec"], "super": ["rw", "size=65536k"]}
    return {
        "uid": 65534, "gid": 65534, "groups": [65534],
        "status": {"CapEff": "0000000000000000", "CapBnd": "0000000000000000",
                   "CapPrm": "0000000000000000", "NoNewPrivs": "1", "Seccomp": "2"},
        "cgroup": {"memory.max": str(policy.memory_mb * 1024 * 1024), "memory.swap.max": "0",
                   "pids.max": str(policy.pids), "cpu.max": f"{policy.cpus * 100000} 100000"},
        "network": {"interfaces": ["lo"], "default_route": False, "loopback_connect_errno": 111},
        "mount_options": {"/": ro, "/tmp": rw, "/candidate": ro, "/oracle": ro,
                          "/toolchain": ro, "/entry": ro},
        "write_errno": {"/": errno.EROFS, "/candidate": errno.EROFS, "/oracle": errno.EROFS,
                        "/toolchain": errno.EROFS, "/entry": errno.EROFS},
        "tmp_write_errno": 0, "tmp_exec_errno": errno.EACCES,
        "sys_write_errno": errno.EROFS, "proc_sys_write_errno": errno.EROFS,
        "host_paths_present": [], "home_entries": [], "pids": [1, 7],
        "env_names": ["HOME", "HOSTNAME", "LANG", "PATH", "PYTHONDONTWRITEBYTECODE", "PYTHONPATH",
                      "PYTHON_SHA256", "PYTHON_VERSION", "TMPDIR"],
        "dev_entries": ["null", "zero"], "python": "3.14.8", "kernel": "7.0.0", "root_mode": 0o755,
    }


def _failed(observed: dict, policy: SandboxPolicy | None = None) -> set[str]:
    checks = sandbox.evaluate_probe(observed, policy or _policy())
    return {c["name"] for c in checks if not c["ok"]}


def test_a_fully_contained_observation_passes_every_check():
    checks = sandbox.evaluate_probe(_good(_policy()), _policy())
    assert checks and all(c["ok"] for c in checks), [c for c in checks if not c["ok"]]
    assert {"unprivileged-user", "no-capabilities", "no-new-privileges", "seccomp-filter-active",
            "memory-limit", "swap-disabled", "pids-limit", "cpu-limit", "no-network",
            "root-read-only", "inputs-read-only", "tmp-bounded-noexec", "no-host-control-paths",
            "home-empty", "own-pid-namespace", "scrubbed-environment",
            "no-kernel-control-writes"} <= {c["name"] for c in checks}
    for check in checks:
        assert {"name", "ok", "expected", "observed"} <= set(check)


def _mutate(path, value):
    observed = _good(_policy())
    node = observed
    for key in path[:-1]:
        node = node[key]
    node[path[-1]] = value
    return observed


MUTATIONS = [
    (("uid",), 0, "unprivileged-user"),
    (("gid",), 0, "unprivileged-user"),
    (("groups",), [0], "unprivileged-user"),
    (("status", "CapBnd"), "00000000a80425fb", "no-capabilities"),
    (("status", "CapEff"), "0000000000000001", "no-capabilities"),
    (("status", "NoNewPrivs"), "0", "no-new-privileges"),
    (("status", "Seccomp"), "0", "seccomp-filter-active"),
    (("cgroup", "memory.max"), "max", "memory-limit"),
    (("cgroup", "memory.swap.max"), "max", "swap-disabled"),
    (("cgroup", "pids.max"), "max", "pids-limit"),
    (("cgroup", "cpu.max"), "max 100000", "cpu-limit"),
    (("network", "interfaces"), ["eth0", "lo"], "no-network"),
    (("network", "default_route"), True, "no-network"),
    (("write_errno", "/"), 0, "root-read-only"),
    (("mount_options", "/"), {"mount": ["rw"], "super": ["rw"]}, "root-read-only"),
    (("write_errno", "/candidate"), 0, "inputs-read-only"),
    (("write_errno", "/oracle"), errno.EACCES, "inputs-read-only"),
    (("mount_options", "/toolchain"), {"mount": ["rw"], "super": ["rw"]}, "inputs-read-only"),
    (("write_errno", "/entry"), 0, "inputs-read-only"),
    (("tmp_write_errno",), errno.EROFS, "tmp-bounded-noexec"),
    (("tmp_exec_errno",), 0, "tmp-bounded-noexec"),
    (("mount_options", "/tmp"), {"mount": ["rw"], "super": ["rw"]}, "tmp-bounded-noexec"),
    (("host_paths_present",), ["/var/run/docker.sock"], "no-host-control-paths"),
    (("home_entries",), ["kensei"], "home-empty"),
    (("pids",), list(range(1, 40)), "own-pid-namespace"),
    (("env_names",), ["PATH", "ANTHROPIC_API_KEY"], "scrubbed-environment"),
    (("env_names",), ["PATH", "HERMES_HOME"], "scrubbed-environment"),
    (("env_names",), ["PATH", "DOCKER_HOST"], "scrubbed-environment"),
    (("env_names",), ["PATH", "SOME_UNLISTED_NAME"], "scrubbed-environment"),
    (("sys_write_errno",), 0, "no-kernel-control-writes"),
    (("proc_sys_write_errno",), 0, "no-kernel-control-writes"),
]


@pytest.mark.parametrize("path,value,expected", MUTATIONS,
                         ids=[f"{'.'.join(p)}={v!r}"[:60] for p, v, _ in MUTATIONS])
def test_each_missing_control_fails_its_named_check(path, value, expected):
    failed = _failed(_mutate(path, value))
    assert expected in failed, failed


def test_missing_or_malformed_observations_fail_closed():
    for observed in ({}, {"uid": 65534}, None, "text", []):
        failed = _failed(copy.deepcopy(observed) if observed is not None else {})
        assert failed, "an observation that does not prove containment can never pass"
    broken = _good(_policy())
    broken["cgroup"] = "not-a-dict"
    assert "memory-limit" in _failed(broken)


def test_limits_are_compared_with_the_policy_not_with_defaults():
    smaller = _policy(memory_mb=128, pids=16, cpus=2)
    observed = _good(_policy())  # observed limits are those of the DEFAULT policy
    assert {"memory-limit", "pids-limit", "cpu-limit"} <= _failed(observed, smaller)
    assert not _failed(_good(smaller), smaller)
