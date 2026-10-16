"""Independent reference-builder handoff: approved SPEC only, quarantined output.

This is a deterministic *demo* builder, not a general-purpose AI model or
a guarantee of code correctness. Host never executes returned source code.
The Docker daemon and reference image are trusted parts of the threat model.
"""
from __future__ import annotations

import hashlib
import json
import re
import secrets
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Callable

from . import sandbox, vault

KIND = "PHICLEANROOM_REFERENCE_BUILDER_V1"
MAX_STDOUT = 64 * 1024
MAX_FILE = 16 * 1024
MAX_ARTIFACTS = 4
FILE_NAME = re.compile(r"^[a-z][a-z0-9_-]{0,50}\.(?:py|md|txt)$")
FORBIDDEN_NAMES = frozenset({"requirements.txt", "dockerfile", "setup.py", "conftest.py"})


class BuilderError(ValueError):
    """Fail closed on untrusted output, stale authorization or runner failures."""


def _json_unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for name, value in pairs:
        if name in obj:
            raise BuilderError("duplicate JSON field: " + name)
        obj[name] = value
    return obj


def _digest(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def validate_artifacts(stdout: str, approved_sha: str) -> list[dict[str, str]]:
    """Only bytes and paths are validated; no source is executed or accepted as correct."""
    if not isinstance(stdout, str) or len(stdout.encode("utf-8")) > MAX_STDOUT:
        raise BuilderError("builder stdout exceeds 64 KiB")
    try:
        doc = json.loads(stdout, object_pairs_hook=_json_unique)
    except (ValueError, TypeError) as exc:
        raise BuilderError("builder output is not valid single-object JSON") from exc
    required = {"kind", "schema_version", "spec_sha256", "generator", "status",
                "authority", "artifacts"}
    if not isinstance(doc, dict) or set(doc) != required:
        raise BuilderError("builder output contains missing/unknown envelope fields")
    if type(doc["schema_version"]) is not int or doc["schema_version"] != 1:
        raise BuilderError("unsupported builder contract version")
    if doc["kind"] != KIND or doc["generator"] != "reference-exact-title-v1":
        raise BuilderError("unknown builder output kind/provider")
    if doc["spec_sha256"] != approved_sha:
        raise BuilderError("builder output does not match approved SPEC SHA-256")
    if doc["status"] != "UNVERIFIED_CANDIDATE" or doc["authority"] != "NONE":
        raise BuilderError("builder may not claim verification, approval or release")
    items = doc["artifacts"]
    if not isinstance(items, list) or not 1 <= len(items) <= MAX_ARTIFACTS:
        raise BuilderError("builder must return 1-4 bounded artifacts")
    found: set[str] = set()
    result = []
    for item in items:
        if not isinstance(item, dict) or set(item) != {"path", "content", "sha256"}:
            raise BuilderError("artifact must have only path, content and sha256")
        name = item["path"]
        if not isinstance(name, str) or FILE_NAME.fullmatch(name) is None or name in FORBIDDEN_NAMES:
            raise BuilderError("unsafe artifact filename")
        if name in found:
            raise BuilderError("duplicate artifact name")
        found.add(name)
        content = item["content"]
        if not isinstance(content, str) or not content or len(content.encode("utf-8")) > MAX_FILE:
            raise BuilderError("artifact content is empty or too large")
        if not isinstance(item["sha256"], str) or _digest(content) != item["sha256"]:
            raise BuilderError("artifact SHA-256 does not match returned bytes")
        result.append({"path": name, "content": content, "sha256": item["sha256"]})
    # For this strictly constrained reference builder, only one artifact is supported.
    if [item["path"] for item in result] != ["search.py"]:
        raise BuilderError("reference builder is restricted to one search.py output")
    return result


def reference_argv(image: str, packet: Path, name: str, docker: str = "docker") -> list[str]:
    """Extend existing locked-down Docker probe policy, changing only fixed script."""
    argv = sandbox.docker_argv(image, packet, name, docker)
    if argv[-1] != "/app/probe.py":
        raise BuilderError("unexpected Docker entrypoint contract")
    argv[-1] = "/app/reference_builder.py"
    return argv


def _outside(candidate: Path, sensitive: Path) -> bool:
    value, boundary = candidate.resolve(), sensitive.resolve()
    return value != boundary and boundary not in value.parents and value not in boundary.parents


def run_builder(
    vault_path: Path, stage: str, image: str, output_dir: Path | None = None,
    receipt_path: Path | None = None, *, execute: bool = False,
    acknowledge_docker_risk: bool = False, docker: str = "docker",
    timeout: int = 60,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> dict[str, Any]:
    """Human-approved stage -> isolated reference builder -> untrusted quarantined files.

    No source code is ever read by this host function except the builder's
    newly returned candidate, and no generated code is executed here.
    """
    sandbox._image(image)
    if not isinstance(stage, str) or sandbox.STAGE_SHA.fullmatch(stage) is None:
        raise BuilderError("invalid reviewed stage SHA-256")
    if type(timeout) is not int or not 5 <= timeout <= 120:
        raise BuilderError("timeout must be 5-120 seconds")
    if execute and not acknowledge_docker_risk:
        raise BuilderError("explicit --acknowledge-docker-risk is required")
    if execute and (output_dir is None or receipt_path is None):
        raise BuilderError("executing a builder requires --out and --receipt")
    if output_dir is not None:
        if not _outside(output_dir, vault_path):
            raise BuilderError("output directory must be separate from Vault")
        if output_dir.exists() or output_dir.is_symlink():
            raise BuilderError("output directory must not already exist")
    if receipt_path is not None:
        if not _outside(receipt_path, vault_path):
            raise BuilderError("receipt must be separate from Vault")
        if receipt_path.exists() or receipt_path.is_symlink():
            raise BuilderError("receipt already exists")
    if output_dir is not None and receipt_path is not None and not _outside(receipt_path, output_dir):
        raise BuilderError("receipt must be outside artifact directory")

    with tempfile.TemporaryDirectory(prefix="phicleanroom-build-spec-") as folder:
        packet = Path(folder) / "packet"
        checked_sha = vault.export_packet(vault_path, stage, packet)
        if sorted(p.name for p in packet.iterdir()) != ["SPEC.md"]:
            raise BuilderError("builder packet must contain only SPEC.md")
        spec_sha = sandbox._spec_digest(packet / "SPEC.md")
        if checked_sha != spec_sha:
            raise BuilderError("reviewed specification digest mismatch")
        name = "phicleanroom-" + secrets.token_hex(8)
        argv = reference_argv(image, packet, name, docker)
        receipt: dict[str, Any] = {
            "schema_version": 1, "kind": "INDEPENDENT_BUILDER_RECEIPT",
            "status": "PLAN_ONLY", "stage_sha256": stage,
            "spec_sha256": spec_sha, "image_id": image,
            "authority": "NONE", "builder": "reference-exact-title-v1",
            "container_policy": sandbox.policy(), "artifacts": [],
            "note": "Demo builder output requires independent verification and human release approval.",
        }
        if not execute:
            return receipt
        try:
            completed = runner(argv, capture_output=True, text=True, timeout=timeout, check=False)
        except subprocess.TimeoutExpired as exc:
            raise BuilderError("Docker reference builder timed out") from exc
        except (OSError, subprocess.SubprocessError) as exc:
            raise BuilderError("Docker builder unavailable: " + str(exc)) from exc
        finally:
            try:
                runner([docker, "rm", "-f", name], capture_output=True, text=True,
                       timeout=15, check=False)
            except (OSError, subprocess.SubprocessError):
                pass
        if completed.returncode != 0:
            raise BuilderError("Docker builder exited nonzero: " + completed.stderr[-300:])
        artifacts = validate_artifacts(completed.stdout, spec_sha)
        # Writes only NEW, PATH-VALIDATED, QUARANTINED files after complete validation.
        # Do not execute them as part of this command.
        assert output_dir is not None and receipt_path is not None
        output_dir.mkdir(parents=True, exist_ok=False)
        for artifact in artifacts:
            with (output_dir / artifact["path"]).open("x", encoding="utf-8", newline="\n") as file:
                file.write(artifact["content"])
        receipt["artifacts"] = [
            {"path": artifact["path"], "sha256": artifact["sha256"]}
            for artifact in artifacts
        ]
        receipt["status"] = "QUARANTINED_UNVERIFIED"
        receipt_path.parent.mkdir(parents=True, exist_ok=True)
        with receipt_path.open("x", encoding="utf-8", newline="\n") as handle:
            json.dump(receipt, handle, indent=2, sort_keys=True)
            handle.write("\n")
        return receipt
