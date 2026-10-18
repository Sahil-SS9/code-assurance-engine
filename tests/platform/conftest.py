"""Shared fixtures for the platform lane: real rootless Docker, the pinned local image, real frozen
inputs. Nothing here installs, pulls or builds anything: if the prerequisites are absent the
platform tests SKIP with the reason (a skip is never a pass).
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

from hermes_code_assurance import freeze
from hermes_code_assurance import owner_execution as owner_exec
from hermes_code_assurance.sandbox import (
    RootlessDockerBackend,
    SandboxInputs,
    SandboxPolicy,
    SandboxUnavailable,
)

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "first_check"
PINNED_IMAGE = os.environ.get(
    "ASSURE_TEST_IMAGE",
    "python@sha256:48b13b003dda20b16f9442b8475aa05fe21bf6579a8c881db92ffb4d8fd20f83",
)
SITE_PACKAGES = Path(pytest.__file__).resolve().parent.parent

# The reviewed check argv the evaluator runs inside the sandbox — single source in
# owner_execution so the contract, the staging helper and the operator script cannot drift.
JOURNEY_CHECK_ARGV = list(owner_exec.JOURNEY_CHECK_ARGV)
PYTEST_ARGV = JOURNEY_CHECK_ARGV

def build_inputs(tmp_path: Path, candidate_src: Path, *, name: str = "attempt",
                 entry: Path | None = None) -> SandboxInputs:
    attempt = tmp_path / name
    attempt.mkdir(mode=0o700)
    candidate = freeze.freeze_directory(candidate_src, attempt / "candidate")
    oracle = freeze.freeze_directory(FIXTURES / "oracle", attempt / "oracle")
    toolchain = freeze.freeze_directory(SITE_PACKAGES, attempt / "toolchain",
                                        names=owner_exec.TOOLCHAIN_PACKAGES)
    if entry is None:
        entry_tree = freeze.freeze_entry(attempt / "entry")
    else:
        shutil.copytree(entry, attempt / "entry")
        os.chmod(attempt / "entry", 0o755)
        entry_tree = freeze.FrozenTree(attempt / "entry", "", 0, 0)
    return SandboxInputs(candidate=candidate.path, oracle=oracle.path, toolchain=toolchain.path,
                         entry=entry_tree.path)


def docker_ready() -> str | None:
    """None when the platform lane can run, else the reason it cannot."""
    backend = RootlessDockerBackend()
    try:
        backend.preflight(SandboxPolicy(image=PINNED_IMAGE))
    except SandboxUnavailable as exc:
        return str(exc)
    return None


@pytest.fixture(scope="session")
def backend():
    reason = docker_ready()
    if reason:
        pytest.skip(f"rootless Docker / pinned image not available: {reason}")
    return RootlessDockerBackend()


@pytest.fixture(scope="session")
def policy():
    return SandboxPolicy(image=PINNED_IMAGE, timeout_seconds=60)


@pytest.fixture
def passing_inputs(tmp_path):
    return build_inputs(tmp_path, FIXTURES / "candidate_pass")


@pytest.fixture(scope="session")
def attest_for(backend, tmp_path_factory):
    """attest_for(policy) -> a REAL attestation for that exact policy (cached by policy digest).

    The attestation is bound to the policy digest, so each limit variant is attested for real
    with the probe; a digest is never edited to make a policy 'match'."""
    cache: dict = {}

    def get(policy):
        digest = policy.digest()
        if digest not in cache:
            root = tmp_path_factory.mktemp("attest")
            inputs = build_inputs(root, FIXTURES / "candidate_pass")
            cache[digest] = backend.attest(policy, inputs)
        return cache[digest]

    return get


@pytest.fixture(scope="session")
def attestation(attest_for, policy):
    return attest_for(policy)


@pytest.fixture(autouse=True)
def _no_leaked_containers(request):
    yield
    if "backend" not in request.fixturenames:
        return
    backend = request.getfixturevalue("backend")
    listing = backend._docker("ps", "-a", "-q", "--filter", "label=hermes.code-assurance.attempt")
    leaked = [line for line in listing.stdout.decode().split() if line]
    for container in leaked:
        backend._docker("rm", "-f", container)
    assert not leaked, f"containers leaked by this test: {leaked}"


def host_processes_matching(marker: str) -> list[str]:
    ps = subprocess.run(["/usr/bin/ps", "-eo", "pid,args"], capture_output=True, text=True,
                        check=False)
    return [line for line in ps.stdout.splitlines() if marker in line and "ps -eo" not in line]


def mode_of(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)
