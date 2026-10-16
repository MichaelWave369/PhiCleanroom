"""Independent, synthetic reference-verifier contract, separate from the builder.

Host checks approved Vault stage, immutable builder receipt and artifact
digests. Only SPEC.md plus one quarantined source file enter a *different*
pinned, restricted Docker verifier. Generated code never runs on host here.

This is one known reference behavior, not arbitrary-code secure certification.
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

KIND = "PHICLEANROOM_REFERENCE_VERIFIER_V1"
REQUIRED_CHECKS = ("exact_title", "description_exclusion", "substring_exclusion",
                   "no_match", "case_sensitive", "duplicate_titles", "missing_title")
REQUIRED_MUTANTS = ("always_empty", "always_all", "substring_title")
MAX_RESULT_BYTES = 32768
MAX_SOURCE_BYTES = 16384


class VerifyError(ValueError):
    """Verification is blocked; never interpret this as a pass."""


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _distinct(candidate: Path, other: Path) -> bool:
    a, b = candidate.resolve(), other.resolve()
    return a != b and a not in b.parents and b not in a.parents


def _load_receipt(path: Path, stage: str, spec_sha: str, source_sha: str) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink() or path.stat().st_size > 16384:
        raise VerifyError("missing, unsafe or oversize builder receipt")
    doc = vault.load_json(path)
    needed = {"schema_version", "kind", "status", "stage_sha256", "spec_sha256",
              "image_id", "authority", "builder", "container_policy", "artifacts", "note"}
    if not isinstance(doc, dict) or set(doc) != needed:
        raise VerifyError("builder receipt fields do not match contract")
    if type(doc["schema_version"]) is not int or doc["schema_version"] != 1:
        raise VerifyError("invalid builder receipt version")
    if (doc["kind"] != "INDEPENDENT_BUILDER_RECEIPT" or
        doc["status"] != "QUARANTINED_UNVERIFIED" or doc["authority"] != "NONE" or
        doc["builder"] != "reference-exact-title-v1" or
        doc["stage_sha256"] != stage or doc["spec_sha256"] != spec_sha):
        raise VerifyError("builder receipt not bound to approved stage/spec or forged authority")
    if not isinstance(doc["artifacts"], list) or doc["artifacts"] != [
        {"path": "search.py", "sha256": source_sha}
    ]:
        raise VerifyError("builder receipt not bound to exact quarantined source bytes")
    sandbox._image(doc["image_id"])
    if doc["container_policy"] != sandbox.policy() or not isinstance(doc["note"], str):
        raise VerifyError("builder receipt policy differs from restricted worker policy")
    return doc


def validate_result(output: str, stage: str, spec_sha: str, source_sha: str) -> dict[str, Any]:
    """Never trust stdout without checking whole contract and all check/mutant outcomes."""
    if not isinstance(output, str) or len(output.encode("utf-8")) > MAX_RESULT_BYTES:
        raise VerifyError("verifier response too large")
    try:
        doc = json.loads(output, object_pairs_hook=lambda pairs: _unique(pairs))
    except (TypeError, ValueError) as exc:
        raise VerifyError("verifier returned malformed or duplicate-key JSON") from exc
    needed = {"schema_version", "kind", "stage_sha256", "spec_sha256", "source_sha256",
              "suite", "checks", "mutants", "status", "authority"}
    if not isinstance(doc, dict) or set(doc) != needed:
        raise VerifyError("verifier response has missing/unknown fields")
    if type(doc["schema_version"]) is not int or doc["schema_version"] != 1:
        raise VerifyError("verifier schema invalid")
    if doc["kind"] != KIND or doc["suite"] != "reference-exact-title-acceptance-v1":
        raise VerifyError("verifier suite is not independently pinned")
    if (doc["stage_sha256"], doc["spec_sha256"], doc["source_sha256"]) != (
        stage, spec_sha, source_sha
    ):
        raise VerifyError("verifier report hash binding mismatch")
    if doc["authority"] != "NONE":
        raise VerifyError("verifier claimed unauthorized authority")
    if doc["status"] != "CHECKS_PASS_MUTANTS_KILLED":
        raise VerifyError("source unverified: mandatory checks or mutation controls failed")
    checks = doc["checks"]
    mutants = doc["mutants"]
    if not isinstance(checks, list) or len(checks) != len(REQUIRED_CHECKS):
        raise VerifyError("mandatory acceptance checks missing")
    if not isinstance(mutants, list) or len(mutants) != len(REQUIRED_MUTANTS):
        raise VerifyError("mutation controls missing")
    for expected, result in zip(REQUIRED_CHECKS, checks):
        if not isinstance(result, dict) or set(result) != {"id", "status"}:
            raise VerifyError("bad acceptance result fields")
        if result != {"id": expected, "status": "PASS"}:
            raise VerifyError("acceptance check did not pass: " + expected)
    original_hashes = set()
    for expected, result in zip(REQUIRED_MUTANTS, mutants):
        if not isinstance(result, dict) or set(result) != {"id", "status", "source_sha256", "failed_check"}:
            raise VerifyError("mutation result lacks provenance fields")
        if result["id"] != expected or result["status"] != "KILLED_ASSERTION":
            raise VerifyError("a required genuine source mutation survived or crashed")
        if not isinstance(result["source_sha256"], str) or re.fullmatch(r"[0-9a-f]{64}", result["source_sha256"]) is None:
            raise VerifyError("mutation digest malformed")
        if result["source_sha256"] == source_sha or result["source_sha256"] in original_hashes:
            raise VerifyError("mutant source was unchanged or duplicated")
        original_hashes.add(result["source_sha256"])
        if result["failed_check"] not in REQUIRED_CHECKS:
            raise VerifyError("mutation must fail a pinned acceptance assertion")
    return doc


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise VerifyError("duplicate result key " + key)
        result[key] = value
    return result


def verifier_argv(image: str, packet: Path, name: str, stage: str, docker: str = "docker") -> list[str]:
    if not isinstance(stage, str) or sandbox.STAGE_SHA.fullmatch(stage) is None:
        raise VerifyError("invalid stage metadata")
    cmd = sandbox.docker_argv(image, packet, name, docker)
    if cmd[-1] != "/app/probe.py":
        raise VerifyError("unexpected underlying Docker entrypoint")
    cmd[-1] = "/app/verify_worker.py"
    cmd[cmd.index("--workdir"):cmd.index("--workdir")] = [
        "--env", "PHICLEANROOM_STAGE_SHA=" + stage,
    ]
    return cmd


def verify(
    vault_path: Path, stage: str, artifact_dir: Path, build_receipt: Path,
    image: str, receipt_path: Path | None = None, *,
    execute: bool = False, acknowledge_docker_risk: bool = False,
    docker: str = "docker", timeout: int = 70,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> dict[str, Any]:
    """Approve no release: independently check pinned source + mutation controls."""
    sandbox._image(image)
    if not isinstance(stage, str) or sandbox.STAGE_SHA.fullmatch(stage) is None:
        raise VerifyError("invalid stage digest")
    if type(timeout) is not int or not 5 <= timeout <= 120:
        raise VerifyError("timeout must be 5-120 seconds")
    if execute and not acknowledge_docker_risk:
        raise VerifyError("execution requires --acknowledge-docker-risk")
    if execute and receipt_path is None:
        raise VerifyError("verification execution requires separate --receipt")
    if not artifact_dir.is_dir() or artifact_dir.is_symlink() or sorted(p.name for p in artifact_dir.iterdir()) != ["search.py"]:
        raise VerifyError("expected a quarantine directory with only search.py")
    source_path = artifact_dir / "search.py"
    if source_path.is_symlink() or not source_path.is_file():
        raise VerifyError("untrusted source is missing or a symlink")
    raw = source_path.read_bytes()
    if not raw or len(raw) > MAX_SOURCE_BYTES:
        raise VerifyError("source must be nonempty and <= 16 KiB")
    try:
        raw.decode("utf-8")
    except UnicodeError as exc:
        raise VerifyError("quarantine source must be UTF-8") from exc
    source_sha = _sha(raw)
    if build_receipt.resolve() == source_path.resolve():
        raise VerifyError("builder receipt cannot be source")
    if receipt_path is not None:
        if receipt_path.exists() or receipt_path.is_symlink():
            raise VerifyError("verifier receipt already exists")
        for protected in (vault_path, artifact_dir):
            if not _distinct(receipt_path, protected):
                raise VerifyError("verifier receipt must stay outside Vault and quarantine")
        if receipt_path.resolve() == build_receipt.resolve():
            raise VerifyError("verifier cannot overwrite builder receipt")
    with tempfile.TemporaryDirectory(prefix="phicleanroom-verify-") as temp:
        approved = Path(temp) / "approved"
        spec_sha = vault.export_packet(vault_path, stage, approved)
        if sorted(p.name for p in approved.iterdir()) != ["SPEC.md"]:
            raise VerifyError("Vault packet must contain SPEC.md only")
        if sandbox._spec_digest(approved / "SPEC.md") != spec_sha:
            raise VerifyError("approved specification was changed")
        _load_receipt(build_receipt, stage, spec_sha, source_sha)
        # A separate temp packet is used for verifier only, never for builder.
        packet = Path(temp) / "verification-input"
        packet.mkdir()
        (packet / "SPEC.md").write_bytes((approved / "SPEC.md").read_bytes())
        (packet / "search.py").write_bytes(raw)
        if _sha((packet / "search.py").read_bytes()) != source_sha:
            raise VerifyError("copied source changed before Docker launch")
        response: dict[str, Any] = {
            "schema_version": 1, "kind": "INDEPENDENT_VERIFICATION_RECEIPT",
            "stage_sha256": stage, "spec_sha256": spec_sha,
            "source_sha256": source_sha, "verifier_image_id": image,
            "suite": "reference-exact-title-acceptance-v1",
            "status": "PLAN_ONLY", "authority": "NONE",
            "checks": [], "mutants": [],
            "note": "One synthetic known contract. No release authority, model assessment or proof of hostile-code containment.",
        }
        if not execute:
            return response
        name = "phicleanroom-" + secrets.token_hex(8)
        argv = verifier_argv(image, packet, name, stage, docker)
        try:
            completed = runner(argv, capture_output=True, text=True, timeout=timeout, check=False)
        except subprocess.TimeoutExpired as exc:
            raise VerifyError("verifier timed out, no successful receipt") from exc
        except (OSError, subprocess.SubprocessError) as exc:
            raise VerifyError("verifier Docker unavailable: " + str(exc)) from exc
        finally:
            try:
                runner([docker, "rm", "-f", name], capture_output=True, text=True,
                       timeout=15, check=False)
            except (OSError, subprocess.SubprocessError):
                pass
        if completed.returncode != 0:
            raise VerifyError("verifier failed: " + completed.stderr[-300:])
        result = validate_result(completed.stdout, stage, spec_sha, source_sha)
        response.update({"status": "REFERENCE_CHECKS_PASS", "checks": result["checks"],
                         "mutants": result["mutants"]})
        assert receipt_path is not None
        receipt_path.parent.mkdir(parents=True, exist_ok=True)
        with receipt_path.open("x", encoding="utf-8", newline="\n") as out:
            json.dump(response, out, indent=2, sort_keys=True)
            out.write("\n")
        return response
