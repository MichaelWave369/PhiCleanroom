"""Human-approved SPEC.md -> restricted Docker *probe*, never a code builder.

The engine is privileged host software; this container configuration is
defense-in-depth, not a VM or a hard adversarial multi-tenant boundary.
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

from . import vault

IMAGE_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
STAGE_SHA = re.compile(r"^[0-9a-f]{64}$")
PROBE_KIND = "PHICLEANROOM_ISOLATION_PROBE_V1"
MAX_SPEC_BYTES = 512 * 1024


class SandboxError(ValueError):
    """Fail-closed runner policy or execution failure."""


def _image(image: str) -> None:
    if not isinstance(image, str) or IMAGE_ID.fullmatch(image) is None:
        raise SandboxError("image must be a locally pinned sha256:<64 lowercase hex> Docker image ID")


def policy() -> dict[str, Any]:
    return {
        "network": "none", "root_filesystem": "read-only", "capabilities": "drop ALL",
        "no_new_privileges": True, "uid_gid": "65532:65532", "memory": "256m",
        "cpus": "1", "pids_limit": 64, "temporary_mount": "/tmp:16m,noexec,nosuid",
        "input": "/approved/SPEC.md (read-only)", "outputs": "JSON stdout only",
        "docker_socket_mounted": False,
    }


def docker_argv(image: str, packet: Path, name: str, docker: str = "docker") -> list[str]:
    """Use Docker's argv interface, never a host shell or freeform commands."""
    _image(image)
    if not re.fullmatch(r"phicleanroom-[0-9a-f]{16}", name):
        raise SandboxError("invalid ephemeral container name")
    if not isinstance(docker, str) or not docker.strip() or "\x00" in docker:
        raise SandboxError("invalid Docker executable")
    return [
        docker, "run", "--rm", "--pull=never", "--name", name,
        "--network", "none", "--read-only", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges", "--user", "65532:65532",
        "--pids-limit", "64", "--memory", "256m", "--cpus", "1",
        "--tmpfs", "/tmp:rw,nosuid,noexec,size=16m",
        "--env", "PYTHONDONTWRITEBYTECODE=1",
        "--mount", "type=bind,src=" + str(packet.resolve()) + ",dst=/approved,readonly",
        "--workdir", "/", "--entrypoint", "python3", image, "/app/probe.py",
    ]


def _spec_digest(path: Path) -> str:
    if not path.is_file() or path.is_symlink():
        raise SandboxError("approved SPEC.md is missing or symlinked")
    raw = path.read_bytes()
    if not raw or len(raw) > MAX_SPEC_BYTES:
        raise SandboxError("SPEC.md must be 1-524288 bytes")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SandboxError("SPEC.md must be UTF-8") from exc
    if not text.startswith("# APPROVED BEHAVIORAL SPECIFICATION\n") or "\n## " not in text:
        raise SandboxError("SPEC.md does not match the approved behavior-only format")
    return hashlib.sha256(raw).hexdigest()


def validate_probe_output(stdout: str, expected_sha: str) -> dict[str, Any]:
    if len(stdout.encode("utf-8")) > 16 * 1024:
        raise SandboxError("probe response is too large")
    try:
        obj = json.loads(stdout)
    except (ValueError, TypeError) as exc:
        raise SandboxError("probe must return one valid JSON object") from exc
    required = {
        "kind", "spec_sha256", "network_reachable", "forbidden_paths_visible",
        "root_writable", "status",
    }
    if not isinstance(obj, dict) or set(obj) != required:
        raise SandboxError("probe returned unexpected fields")
    if obj["kind"] != PROBE_KIND or obj["spec_sha256"] != expected_sha:
        raise SandboxError("probe kind or approved spec digest mismatch")
    for key in ("network_reachable", "forbidden_paths_visible", "root_writable"):
        if type(obj[key]) is not bool or obj[key]:
            raise SandboxError("probe isolation check failed: " + key)
    if obj["status"] != "PASS":
        raise SandboxError("probe reported failure")
    return obj


def probe(
    vault_path: Path,
    stage: str,
    image: str,
    receipt_path: Path | None = None,
    *,
    execute: bool = False,
    acknowledge_docker_risk: bool = False,
    docker: str = "docker",
    timeout: int = 60,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> dict[str, Any]:
    """Check stage approval and optionally launch a restricted one-use container.

    Without --execute, no Docker process starts. Only freshly exported SPEC.md
    is mounted, never investigator originals or arbitrary user-supplied files.
    """
    _image(image)
    if not isinstance(stage, str) or STAGE_SHA.fullmatch(stage) is None:
        raise SandboxError("stage must be a lowercase 64-character SHA-256")
    if type(timeout) is not int or not 5 <= timeout <= 120:
        raise SandboxError("timeout must be 5-120 seconds")
    if execute and not acknowledge_docker_risk:
        raise SandboxError("Docker execution requires --acknowledge-docker-risk")
    if execute and receipt_path is None:
        raise SandboxError("executed probes require --receipt")
    if receipt_path is not None:
        target, root = receipt_path.resolve(), vault_path.resolve()
        if target == root or root in target.parents:
            raise SandboxError("receipt cannot be inside the investigator vault")
        if receipt_path.exists() or receipt_path.is_symlink():
            raise SandboxError("receipt exists; cannot overwrite")
    with tempfile.TemporaryDirectory(prefix="phicleanroom-spec-") as temp:
        packet = Path(temp) / "packet"
        # Reuses the verified frozen-stage, digest, and human-review policy.
        approved_sha = vault.export_packet(vault_path, stage, packet)
        files = list(packet.iterdir())
        if len(files) != 1 or files[0].name != "SPEC.md":
            raise SandboxError("approved builder packet must contain only SPEC.md")
        spec_sha = _spec_digest(packet / "SPEC.md")
        if spec_sha != approved_sha:
            raise SandboxError("approved spec SHA-256 mismatch")
        name = "phicleanroom-" + secrets.token_hex(8)
        command = docker_argv(image, packet, name, docker=docker)
        result: dict[str, Any] = {
            "schema_version": 1, "kind": "SANDBOX_PROBE_RECEIPT",
            "stage_sha256": stage, "spec_sha256": spec_sha, "image_id": image,
            "policy": policy(), "authority": "NONE",
            "status": "PLANNED_ONLY" if not execute else "NOT_VERIFIED",
            "note": "Boundary probe only. Not a builder, security attestation, or release approval.",
        }
        if execute:
            try:
                completed = runner(command, capture_output=True, text=True, timeout=timeout, check=False)
            except subprocess.TimeoutExpired as exc:
                raise SandboxError("Docker probe timed out; cleanup attempted") from exc
            except (OSError, subprocess.SubprocessError) as exc:
                raise SandboxError("Docker unavailable: " + str(exc)) from exc
            finally:
                # Client timeout should not leave a named container running.
                try:
                    runner([docker, "rm", "-f", name], capture_output=True, text=True,
                           timeout=15, check=False)
                except (OSError, subprocess.SubprocessError):
                    pass
            if completed.returncode != 0:
                raise SandboxError("Docker probe failed (exit " + str(completed.returncode) + "): " +
                                   completed.stderr[-300:])
            result["probe"] = validate_probe_output(completed.stdout, spec_sha)
            result["status"] = "PROBE_PASS"
        if receipt_path is not None:
            receipt_path.parent.mkdir(parents=True, exist_ok=True)
            with receipt_path.open("x", encoding="utf-8", newline="\n") as handle:
                json.dump(result, handle, sort_keys=True, indent=2)
                handle.write("\n")
        return result
