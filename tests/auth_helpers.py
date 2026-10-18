"""Test-only helpers for the owner-authority tests.

FIXTURE KEYS ONLY: every key made here is an EPHEMERAL evaluator key generated with the system
openssl in a disposable directory. It proves verification mechanics. It is never an owner, is
never enrolled anywhere real, and must never authorise a real run.
"""

from __future__ import annotations

import base64
import hashlib
import json
import shutil
import subprocess
from pathlib import Path

OPENSSL = shutil.which("openssl")


def require_openssl():
    import pytest

    if OPENSSL is None:  # an environment gap, reported as a skip with its reason (never a pass)
        pytest.skip("openssl is the independent Ed25519 oracle and is not installed")


def _openssl(args, **kwargs):
    assert OPENSSL is not None, "require_openssl() must run first"
    return subprocess.run(
        [OPENSSL, *args], check=True, capture_output=True, env={"PATH": "/usr/bin:/bin"}, **kwargs
    )


class FixtureKey:
    """EPHEMERAL evaluator key (openssl). Not an owner."""

    def __init__(self, workdir: Path, name: str = "fixture"):
        require_openssl()
        self.pem = Path(workdir) / f"{name}.pem"
        _openssl(["genpkey", "-algorithm", "ED25519", "-out", str(self.pem)])
        der = _openssl(["pkey", "-in", str(self.pem), "-pubout", "-outform", "DER"]).stdout
        assert len(der) == 44, "unexpected SPKI length for an Ed25519 public key"
        self.public = der[-32:]
        self.key_id = hashlib.sha256(self.public).hexdigest()

    def sign(self, message: bytes) -> bytes:
        msg = self.pem.with_suffix(".msg")
        msg.write_bytes(message)
        return _openssl(["pkeyutl", "-sign", "-rawin", "-inkey", str(self.pem), "-in", str(msg)]).stdout

    def sign_b64(self, message: bytes) -> str:
        return base64.b64encode(self.sign(message)).decode()


def _raw_secret_der(secret: bytes, workdir: Path) -> Path:
    prefix = bytes.fromhex("302e020100300506032b657004220420")  # PKCS#8 Ed25519 wrapper
    der = Path(workdir) / "raw-secret.der"
    der.write_bytes(prefix + secret)
    return der


def openssl_sign_with_raw_secret(secret: bytes, message: bytes, workdir: Path) -> bytes:
    """Sign with a raw RFC 8032 secret via PKCS#8 DER — used to check recalled RFC vectors."""
    require_openssl()
    der = _raw_secret_der(secret, workdir)
    msg = Path(workdir) / "raw-secret.msg"
    msg.write_bytes(message)
    return _openssl(
        ["pkeyutl", "-sign", "-rawin", "-keyform", "DER", "-inkey", str(der), "-in", str(msg)]
    ).stdout


def openssl_public_from_raw_secret(secret: bytes, workdir: Path) -> bytes:
    """Derive the public key of a raw RFC 8032 secret with OpenSSL (independent of this engine)."""
    require_openssl()
    der = _raw_secret_der(secret, workdir)
    spki = _openssl(["pkey", "-inform", "DER", "-in", str(der), "-pubout", "-outform", "DER"]).stdout
    return spki[-32:]


def write_trust_file(path: Path, keys: dict[str, bytes], *, mode: int = 0o644) -> Path:
    """Write an owner-keys trust file (public keys only)."""
    body = {
        "schema": "code-assurance-owner-keys-v1",
        "keys": [
            {
                "owner": owner,
                "public_key_b64": base64.b64encode(public).decode(),
                "key_id": hashlib.sha256(public).hexdigest(),
            }
            for owner, public in keys.items()
        ],
    }
    path.write_text(json.dumps(body, sort_keys=True, indent=2) + "\n")
    path.chmod(mode)
    return path


def make_operation(**overrides) -> dict:
    """A complete, valid operation (the exact scope an owner would sign)."""
    operation = {
        "schema_version": 1,
        "owner": "sahil",
        "route": "cli",
        "data_root": "/state/plugin-data/code-assurance-engine",
        "assessment_id": "a" * 64,
        "attempt": 1,
        "attempt_id": "att-0123456789ab",
        "check_id": "calc-oracle",
        "candidate_digest": "b" * 64,
        "contract_id": "c" * 64,
        "oracle_digest": "d" * 64,
        "toolchain_digest": "e" * 64,
        "collector_digest": "f" * 64,
        "image": "python@sha256:" + "1" * 64,
        "isolation_policy_digest": "2" * 64,
        "argv": ["python", "-B", "-m", "pytest", "/oracle/tests", "-p", "no:cacheprovider"],
        "env_digest": "3" * 64,
        "limits": {
            "timeout_seconds": 60,
            "output_limit_bytes": 2097152,
            "memory_mb": 512,
            "pids": 64,
            "cpus": 1,
        },
        "network": "none",
    }
    operation.update(overrides)
    return operation
