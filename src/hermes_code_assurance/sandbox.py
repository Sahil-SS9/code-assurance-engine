"""Execution isolation: a rootless-Docker backend that is verified before every run, no fallback.

A worktree, a temporary directory or a same-user subprocess is NOT a sandbox, and neither is the
word "rootless". This backend therefore does three things before any check may run:

1. preflight  - the Docker daemon behind the explicit rootless socket really is rootless and the
                pinned image (by digest) is already present locally (nothing is ever pulled);
2. attest     - an evaluator-owned probe runs inside a container created with EXACTLY the policy and
                mounts a real check gets, and the HOST judges its raw observations against the
                policy (user, capabilities, cgroup limits, network, read-only mounts, environment,
                host paths, PID namespace ...). Any missing control raises SandboxUnavailable;
3. run        - create / start / bounded collect / inspect / force-remove / read-back-removal, with a
                real deadline, an output cap and cancellation that removes the whole container (and
                therefore every descendant process) before returning or re-raising.

The legacy ``IsolationBackend`` stays as the default: it still refuses by name.
"""

from __future__ import annotations

import errno
import json
import os
import re
import selectors
import shutil
import stat
import subprocess
import tempfile
import time
import weakref
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from .collector import parse_probe_output
from .jsonio import canonical_json, sha256_hex

IMAGE_RE = re.compile(r"^[a-z0-9][a-z0-9._/-]{0,127}@sha256:[0-9a-f]{64}$")
MOUNT_POINTS = {
    "candidate": "/candidate", "oracle": "/oracle", "toolchain": "/toolchain", "entry": "/entry",
}
CONTAINER_USER = "65534:65534"
_FSIZE_BYTES = 64 * 1024 * 1024
_NAME_RE = re.compile(r"^assure-[a-z0-9-]{1,40}$")
_ATTEMPT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_ENV = {
    "HOME": "/tmp",
    "LANG": "C.UTF-8",
    "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
    "PYTHONDONTWRITEBYTECODE": "1",
    "PYTHONHASHSEED": "0",
    "PYTHONPATH": "/candidate:/toolchain",
    "PYTHONUNBUFFERED": "1",
    "TMPDIR": "/tmp",
}
_IMAGE_ENV_NAMES = frozenset({"PATH", "HOSTNAME", "PYTHON_VERSION", "PYTHON_SHA256", "LC_CTYPE"})
_SECRETISH = re.compile(
    r"(KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|HERMES|DOCKER|SSH|AWS|GITHUB|ANTHROPIC|OPENAI)",
    re.IGNORECASE,
)
JUNIT_PATH = "/tmp/result.xml"
DEADLINE_GRACE_SECONDS = 5


class SandboxUnavailable(RuntimeError):
    """Execution was requested but no verified OS isolation backend is configured."""


class IsolationBackend:
    verified: bool = False

    def request_run(self, *, check_id: str, argv: list[str], cwd: str, env: list[str]):
        raise SandboxUnavailable(
            "no verified OS isolation backend is configured: execution refused "
            "(Phase-0 blocker: native containment not attested)"
        )


def refundless_stub_backend() -> IsolationBackend:
    """Stdlib-only default backend — always unverified, always refuses."""
    return IsolationBackend()


# ------------------------------------------------------------------------------ policy


@dataclass(frozen=True)
class SandboxPolicy:
    """Everything about the container that the owner's signature covers (via ``digest``)."""

    image: str
    timeout_seconds: int = 60
    output_limit_bytes: int = 2 * 1024 * 1024
    memory_mb: int = 512
    pids: int = 64
    cpus: int = 1
    tmpfs_mb: int = 64

    def __post_init__(self):
        if not isinstance(self.image, str) or not IMAGE_RE.fullmatch(self.image):
            raise ValueError("image must be pinned by digest, e.g. python@sha256:<64 hex>")
        ranges = {
            "timeout_seconds": (1, 600), "output_limit_bytes": (1024, 16 * 1024 * 1024),
            "memory_mb": (64, 4096), "pids": (8, 512), "cpus": (1, 4), "tmpfs_mb": (8, 512),
        }
        for name, (low, high) in ranges.items():
            value = getattr(self, name)
            if type(value) is not int or not low <= value <= high:
                raise ValueError(f"{name} must be an integer in {low}..{high}")

    def limits(self) -> dict:
        return {
            "timeout_seconds": self.timeout_seconds, "output_limit_bytes": self.output_limit_bytes,
            "memory_mb": self.memory_mb, "pids": self.pids, "cpus": self.cpus,
        }

    def description(self) -> dict:
        return {
            "v": 1,
            "image": self.image,
            "network": "none",
            "user": CONTAINER_USER,
            "root_filesystem": "read-only",
            "capabilities": "none",
            "no_new_privileges": True,
            "seccomp": "runtime-default",
            "init": True,
            "pull": "never",
            "log_driver": "none",
            "memory_swap": "equal-to-memory",
            "ulimits": {"nofile": "256:256", "fsize": f"{_FSIZE_BYTES}:{_FSIZE_BYTES}"},
            "mounts": {point: "ro" for point in MOUNT_POINTS.values()},
            "tmpfs": {"/tmp": f"rw,nosuid,nodev,noexec,size={self.tmpfs_mb}m,mode=1777"},
            "environment": dict(_ENV),
            "limits": self.limits(),
            "tmpfs_mb": self.tmpfs_mb,
            "collector_command": collector_command(
                ["<check argv>"], deadline_seconds=self.timeout_seconds + DEADLINE_GRACE_SECONDS
            ),
            "workdir": "/candidate",
        }

    def digest(self) -> str:
        return sha256_hex(canonical_json(self.description()))


@dataclass(frozen=True)
class SandboxInputs:
    """Four frozen directories, siblings inside one private attempt directory."""

    candidate: Path
    oracle: Path
    toolchain: Path
    entry: Path

    def paths(self) -> dict[str, Path]:
        return {"candidate": self.candidate, "oracle": self.oracle,
                "toolchain": self.toolchain, "entry": self.entry}

    def validate(self) -> None:
        parents = set()
        for label, path in self.paths().items():
            path = Path(path)
            if not path.is_absolute():
                raise SandboxUnavailable(f"{label} input must be an absolute path")
            if any(ch in str(path) for ch in (",", "\n", "\r", "\x00")):
                raise SandboxUnavailable(f"{label} input path contains an unsafe character")
            if path.is_symlink() or not path.is_dir():
                raise SandboxUnavailable(f"{label} input must be a real directory, not a symlink")
            if os.path.realpath(path) != str(path):
                raise SandboxUnavailable(f"{label} input path is not fully resolved")
            parents.add(path.parent)
        if len(parents) != 1:
            raise SandboxUnavailable("sandbox inputs must be siblings in one attempt directory")
        parent = parents.pop()
        info = os.lstat(parent)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) & 0o077):
            raise SandboxUnavailable("the attempt directory must be private (0700) and ours")


def container_name(attempt_id: str) -> str:
    if not isinstance(attempt_id, str) or not _ATTEMPT_RE.fullmatch(attempt_id):
        raise ValueError("attempt id must match [A-Za-z0-9][A-Za-z0-9_.-]{0,63}")
    return "assure-" + sha256_hex(attempt_id.encode())[:24]


def collector_command(check_argv: Sequence[str], *, deadline_seconds: int | None = None) -> list[str]:
    """The in-container command: the evaluator's collector wraps the check (no shell anywhere)."""
    result = ["python", "-B", f"{MOUNT_POINTS['entry']}/collect.py", "--junit", JUNIT_PATH]
    if deadline_seconds is not None:
        if type(deadline_seconds) is not int or deadline_seconds < 1:
            raise ValueError("deadline_seconds must be a positive integer")
        result += ["--deadline", str(deadline_seconds)]
    return [*result, "--", *check_argv]


def create_argv(policy: SandboxPolicy, inputs: SandboxInputs, name: str,
                command: Sequence[str], *, attempt_id: str) -> list[str]:
    """Arguments for ``docker create`` (after the global --host). Every control is explicit."""
    inputs.validate()
    if not _NAME_RE.fullmatch(name):
        raise ValueError("invalid container name")
    if not _ATTEMPT_RE.fullmatch(attempt_id):
        raise ValueError("invalid attempt id")
    if (not command or any(not isinstance(arg, str) or "\x00" in arg for arg in command)):
        raise ValueError("command must be a non-empty argv of NUL-free strings")
    argv = [
        "create", "--init", "--name", name, "--pull=never",
        "--label", f"hermes.code-assurance.attempt={attempt_id}",
        "--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges",
        f"--pids-limit={policy.pids}", f"--memory={policy.memory_mb}m",
        f"--memory-swap={policy.memory_mb}m", f"--cpus={policy.cpus}", f"--user={CONTAINER_USER}",
        "--ulimit", "nofile=256:256", "--ulimit", f"fsize={_FSIZE_BYTES}:{_FSIZE_BYTES}",
        "--log-driver=none",
        "--tmpfs", f"/tmp:rw,nosuid,nodev,noexec,size={policy.tmpfs_mb}m,mode=1777",
    ]
    for label, path in inputs.paths().items():
        argv += ["--mount",
                 f"type=bind,src={path},dst={MOUNT_POINTS[label]},readonly,bind-recursive=disabled"]
    argv += ["--workdir", MOUNT_POINTS["candidate"]]
    for key, value in sorted(_ENV.items()):
        argv += ["--env", f"{key}={value}"]
    return [*argv, policy.image, *command]


# ------------------------------------------------------------------------------ probe judgement


def _dict(value) -> dict:
    return value if isinstance(value, dict) else {}


def _mount_has(options, flag: str) -> bool:
    if not isinstance(options, dict):
        return False
    return flag in (options.get("mount") or []) or flag in (options.get("super") or [])


def evaluate_probe(observed: dict, policy: SandboxPolicy) -> list[dict]:
    """Judge the probe's raw observations against the policy. Anything unproven fails."""
    obs = _dict(observed)
    status = _dict(obs.get("status"))
    cgroup = _dict(obs.get("cgroup"))
    net = _dict(obs.get("network"))
    mounts = _dict(obs.get("mount_options"))
    writes = _dict(obs.get("write_errno"))
    checks: list[dict] = []

    def add(name: str, ok: bool, expected, got) -> None:
        checks.append({"name": name, "ok": bool(ok), "expected": expected, "observed": got})

    groups = obs.get("groups") if isinstance(obs.get("groups"), list) else None
    add("unprivileged-user",
        obs.get("uid") == 65534 and obs.get("gid") == 65534
        and groups is not None and set(groups) <= {65534},
        "uid=gid=65534, no supplementary groups",
        {"uid": obs.get("uid"), "gid": obs.get("gid"), "groups": obs.get("groups")})
    zero = "0000000000000000"
    add("no-capabilities",
        all(status.get(k) == zero for k in ("CapEff", "CapBnd", "CapPrm")),
        "effective, permitted and bounding capability sets all empty",
        {k: status.get(k) for k in ("CapEff", "CapPrm", "CapBnd")})
    add("no-new-privileges", status.get("NoNewPrivs") == "1", "NoNewPrivs=1",
        status.get("NoNewPrivs"))
    add("seccomp-filter-active", status.get("Seccomp") == "2", "Seccomp=2 (filter)",
        status.get("Seccomp"))
    memory_limit = str(policy.memory_mb * 1024 * 1024)
    add("memory-limit", cgroup.get("memory.max") == memory_limit, f"memory.max={memory_limit}",
        cgroup.get("memory.max"))
    add("swap-disabled", cgroup.get("memory.swap.max") == "0", "memory.swap.max=0",
        cgroup.get("memory.swap.max"))
    add("pids-limit", cgroup.get("pids.max") == str(policy.pids), f"pids.max={policy.pids}",
        cgroup.get("pids.max"))
    cpu = f"{policy.cpus * 100000} 100000"
    add("cpu-limit", cgroup.get("cpu.max") == cpu, f"cpu.max={cpu}", cgroup.get("cpu.max"))
    add("no-network",
        net.get("interfaces") == ["lo"] and net.get("default_route") is False,
        "loopback only, no default route",
        {"interfaces": net.get("interfaces"), "default_route": net.get("default_route")})
    add("root-read-only",
        _mount_has(mounts.get("/"), "ro") and writes.get("/") == errno.EROFS,
        "root mount ro and a write fails with EROFS",
        {"mount": mounts.get("/"), "write_errno": writes.get("/")})
    add("inputs-read-only",
        all(_mount_has(mounts.get(p), "ro") and writes.get(p) == errno.EROFS
            for p in MOUNT_POINTS.values()),
        "every frozen input is a read-only mount (write fails with EROFS)",
        {p: {"ro": _mount_has(mounts.get(p), "ro"), "write_errno": writes.get(p)}
         for p in MOUNT_POINTS.values()})
    tmp = mounts.get("/tmp")
    add("tmp-bounded-noexec",
        obs.get("tmp_write_errno") == 0
        and obs.get("tmp_exec_errno") in (errno.EACCES, errno.EPERM)
        and all(_mount_has(tmp, flag) for flag in ("noexec", "nosuid", "nodev")),
        "/tmp is writable (size-bounded tmpfs) but noexec,nosuid,nodev",
        {"write_errno": obs.get("tmp_write_errno"), "exec_errno": obs.get("tmp_exec_errno"),
         "mount": tmp})
    add("no-host-control-paths", obs.get("host_paths_present") == [],
        "no docker/dbus/systemd sockets or host home/credential paths", obs.get("host_paths_present"))
    add("home-empty", obs.get("home_entries") in ([], None), "no home directories visible",
        obs.get("home_entries"))
    pids = obs.get("pids") if isinstance(obs.get("pids"), list) else None
    add("own-pid-namespace", pids is not None and 1 in pids and len(pids) <= 6,
        "a private PID namespace (init plus the probe only)", pids)
    names = obs.get("env_names") if isinstance(obs.get("env_names"), list) else None
    allowed = set(_ENV) | _IMAGE_ENV_NAMES
    add("scrubbed-environment",
        names is not None and set(names) <= allowed
        and not any(_SECRETISH.search(str(n)) for n in names),
        "only the fixed constants plus the image's own PATH/Python names", names)
    sys_write, proc_write = obs.get("sys_write_errno"), obs.get("proc_sys_write_errno")
    add("no-kernel-control-writes",
        isinstance(sys_write, int) and sys_write != 0 and isinstance(proc_write, int)
        and proc_write != 0,
        "cgroup and /proc/sys control files cannot be written",
        {"cgroup": sys_write, "proc_sys": proc_write})
    return checks


# ------------------------------------------------------------------------------ results


@dataclass(frozen=True)
class IsolationAttestation:
    ok: bool
    policy_digest: str
    image: str
    image_id: str
    checks: list
    probe_output_sha256: str
    python: str
    kernel: str
    sha256: str

    def as_dict(self) -> dict:
        return {
            "ok": self.ok, "policy_digest": self.policy_digest, "image": self.image,
            "image_id": self.image_id, "checks": self.checks,
            "probe_output_sha256": self.probe_output_sha256, "python": self.python,
            "kernel": self.kernel, "sha256": self.sha256,
        }


@dataclass(frozen=True)
class ProcessObservation:
    container_id: str
    name: str
    exit_code: int | None
    timed_out: bool
    truncated: bool
    oom_killed: bool
    runtime_error: str
    output: bytes
    output_sha256: str
    started_at: str
    finished_at: str
    duration_seconds: float
    container_removed: bool
    cleanup_verified: bool
    launch_digest: str
    problems: list[str] = field(default_factory=list)


# ------------------------------------------------------------------------------ the backend


class RootlessDockerBackend(IsolationBackend):
    """Runs a frozen check inside a rootless-Docker container. See the module docstring."""

    collector_id = "rootless-docker-collector-v1"

    def __init__(self, *, docker: str = "/usr/bin/docker", socket_path: str | None = None):
        self.docker = docker
        self.socket_path = socket_path or f"/run/user/{os.geteuid()}/docker.sock"
        self.host = f"unix://{self.socket_path}"
        self._config = tempfile.mkdtemp(prefix="assure-docker-")
        os.chmod(self._config, 0o700)
        weakref.finalize(self, shutil.rmtree, self._config, True)
        self._env = {"PATH": "/usr/bin:/bin", "HOME": self._config, "DOCKER_CONFIG": self._config}
        self._attested_policy: str | None = None

    @property
    def verified(self) -> bool:  # type: ignore[override]
        return self._attested_policy is not None

    def request_run(self, *, check_id: str, argv: list[str], cwd: str, env: list[str]):
        raise SandboxUnavailable("use RootlessDockerBackend.run_check through the gated runner")

    # -- docker plumbing --------------------------------------------------------------
    def _docker(self, *args: str, timeout: float = 30.0) -> subprocess.CompletedProcess:
        command = [self.docker, "--host", self.host, *args]
        try:
            return subprocess.run(command, capture_output=True, timeout=timeout, env=self._env,
                                  stdin=subprocess.DEVNULL, check=False)
        except FileNotFoundError as exc:
            raise SandboxUnavailable(f"docker CLI not found at {self.docker}") from exc
        except subprocess.TimeoutExpired as exc:
            raise SandboxUnavailable(f"docker did not answer within {timeout:.0f}s") from exc

    def _require_socket(self) -> None:
        try:
            info = os.stat(self.socket_path)
        except OSError as exc:
            raise SandboxUnavailable(
                f"rootless Docker socket not found at {self.socket_path}: execution refused"
            ) from exc
        if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.geteuid():
            raise SandboxUnavailable("the Docker socket is not a socket owned by this user")

    # -- verification -----------------------------------------------------------------
    def preflight(self, policy: SandboxPolicy) -> dict:
        """Rootless daemon + locally present pinned image. Never pulls, never falls back."""
        self._require_socket()
        info = self._docker("info", "--format", "{{json .SecurityOptions}}", timeout=30)
        if info.returncode:
            raise SandboxUnavailable("Docker daemon not reachable: "
                                     + info.stderr.decode(errors="replace")[:200])
        try:
            options = json.loads(info.stdout)
        except ValueError as exc:
            raise SandboxUnavailable("Docker security options are unreadable") from exc
        if not any(str(option).split(",")[0] == "name=rootless" for option in options):
            raise SandboxUnavailable("Docker is not running in rootless mode: execution refused")
        inspected = self._docker("image", "inspect", policy.image)
        if inspected.returncode:
            raise SandboxUnavailable(
                "the pinned image is not present locally and nothing is ever pulled: " + policy.image
            )
        try:
            image = json.loads(inspected.stdout)[0]
        except (ValueError, IndexError) as exc:
            raise SandboxUnavailable("image inspection is unreadable") from exc
        digest = policy.image.split("@", 1)[1]
        if image.get("Id") != digest and policy.image not in (image.get("RepoDigests") or []):
            raise SandboxUnavailable("the local image does not match the pinned digest")
        return {"rootless": True, "image_id": image.get("Id", ""),
                "repo_digests": image.get("RepoDigests") or []}

    def attest(self, policy: SandboxPolicy, inputs: SandboxInputs) -> IsolationAttestation:
        """Run the evaluator's probe under the real policy and judge it on the host."""
        inputs.validate()
        pre = self.preflight(policy)
        probe_id = "probe-" + os.urandom(6).hex()
        observation = self._run_container(
            policy, inputs, ["python", "-B", f"{MOUNT_POINTS['entry']}/probe.py"], probe_id
        )
        if observation.timed_out or observation.truncated or observation.exit_code != 0:
            raise SandboxUnavailable("the isolation probe did not complete cleanly: "
                                     + (observation.runtime_error or f"exit {observation.exit_code}"))
        if not observation.cleanup_verified:
            raise SandboxUnavailable("the probe container could not be verified removed")
        observed = parse_probe_output(observation.output)
        if observed is None:
            raise SandboxUnavailable("the isolation probe produced no usable observation")
        checks = evaluate_probe(observed, policy)
        failed = [c["name"] for c in checks if not c["ok"]]
        if failed:
            raise SandboxUnavailable("isolation attestation failed: " + ", ".join(failed))
        record = {"policy": policy.digest(), "image_id": pre["image_id"], "checks": checks}
        attestation = IsolationAttestation(
            ok=True, policy_digest=policy.digest(), image=policy.image, image_id=pre["image_id"],
            checks=checks, probe_output_sha256=observation.output_sha256,
            python=str(observed.get("python", "")), kernel=str(observed.get("kernel", "")),
            sha256=sha256_hex(canonical_json(record)),
        )
        self._attested_policy = policy.digest()
        return attestation

    # -- running ----------------------------------------------------------------------
    def run_check(self, *, policy: SandboxPolicy, inputs: SandboxInputs,
                  check_argv: Sequence[str], attempt_id: str,
                  attestation: IsolationAttestation) -> ProcessObservation:
        if (not isinstance(attestation, IsolationAttestation) or not attestation.ok
                or attestation.policy_digest != policy.digest()):
            raise SandboxUnavailable("no valid isolation attestation for this exact policy")
        return self._run_container(
            policy, inputs,
            collector_command(check_argv, deadline_seconds=policy.timeout_seconds + DEADLINE_GRACE_SECONDS),
            attempt_id,
        )

    def leftovers(self, attempt_id: str) -> list[str]:
        """Container ids carrying this attempt's label (should always be empty afterwards)."""
        result = self._docker("ps", "-a", "-q", "--filter",
                              f"label=hermes.code-assurance.attempt={attempt_id}")
        return [line for line in result.stdout.decode().split() if line]

    def _build_create(self, policy, inputs, name, command, attempt_id) -> list[str]:
        return create_argv(policy, inputs, name, command, attempt_id=attempt_id)

    def _run_container(self, policy: SandboxPolicy, inputs: SandboxInputs, command: Sequence[str],
                       attempt_id: str) -> ProcessObservation:
        name = container_name(attempt_id)
        arguments = self._build_create(policy, inputs, name, command, attempt_id)
        launch_digest = sha256_hex(canonical_json([self.docker, "--host", self.host, *arguments]))
        if self._docker("container", "inspect", name).returncode == 0:
            raise SandboxUnavailable("a container for this attempt already exists; refusing to "
                                     "reuse it (ambiguous earlier attempt)")
        created = self._docker(*arguments)
        container_id = created.stdout.decode(errors="replace").strip()
        if created.returncode or not re.fullmatch(r"[0-9a-f]{64}", container_id):
            raise SandboxUnavailable("container create failed: "
                                     + created.stderr.decode(errors="replace")[:300])
        started = time.monotonic()
        try:
            collected = self._collect(container_id, policy)
            state = self._final_state(container_id)
        except BaseException:
            self._remove(container_id)
            raise
        verified = self._remove(container_id)
        output, timed_out, truncated = collected
        problems = []
        if not verified:
            problems.append("container removal could not be read back; attempt is ambiguous")
        return ProcessObservation(
            container_id=container_id, name=name, exit_code=state.get("ExitCode"),
            timed_out=timed_out, truncated=truncated, oom_killed=bool(state.get("OOMKilled")),
            runtime_error=str(state.get("Error") or ""), output=output,
            output_sha256=sha256_hex(output), started_at=str(state.get("StartedAt") or ""),
            finished_at=str(state.get("FinishedAt") or ""),
            duration_seconds=round(time.monotonic() - started, 3), container_removed=verified,
            cleanup_verified=verified, launch_digest=launch_digest, problems=problems,
        )

    def _collect(self, container_id: str, policy: SandboxPolicy) -> tuple[bytes, bool, bool]:
        """Stream the attached output with a real deadline and a byte cap."""
        process = subprocess.Popen(
            [self.docker, "--host", self.host, "start", "-a", container_id],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
            env=self._env,
        )
        data = bytearray()
        timed_out = truncated = False
        deadline = time.monotonic() + policy.timeout_seconds
        try:
            assert process.stdout is not None
            fd = process.stdout.fileno()
            with selectors.DefaultSelector() as selector:
                selector.register(fd, selectors.EVENT_READ)
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        timed_out = True
                        break
                    if not selector.select(min(remaining, 0.25)):
                        if process.poll() is not None:
                            break
                        continue
                    chunk = os.read(fd, 65536)
                    if not chunk:
                        break
                    room = policy.output_limit_bytes - len(data)
                    data += chunk[:max(room, 0)]
                    if len(chunk) > room:
                        truncated = True
                        break
            if timed_out or truncated:
                # Close the attached `docker start -a` stream before asking the daemon to kill.
                # With a malicious output flood the client can otherwise keep the daemon's
                # attach path busy and make cleanup itself appear to hang.
                if process.poll() is None:
                    process.terminate()
                self._docker("kill", container_id, timeout=20)
        finally:
            if process.poll() is None:
                process.kill()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                pass
            if process.stdout is not None:
                process.stdout.close()
        return bytes(data), timed_out, truncated

    def _final_state(self, container_id: str) -> dict:
        deadline = time.monotonic() + 20
        state: dict = {}
        while time.monotonic() < deadline:
            result = self._docker("inspect", "--format", "{{json .State}}", container_id)
            if result.returncode == 0:
                try:
                    state = json.loads(result.stdout)
                except ValueError:
                    state = {}
                if state.get("Status") in ("exited", "dead"):
                    return state
            time.sleep(0.1)
        return state

    def _remove(self, container_id: str) -> bool:
        """Force-remove (kills every descendant with the container) and read the removal back."""
        try:
            self._docker("rm", "-f", container_id, timeout=30)
            gone = self._docker("container", "inspect", container_id, timeout=15)
        except SandboxUnavailable:
            return False
        return gone.returncode != 0 and b"No such" in gone.stderr
