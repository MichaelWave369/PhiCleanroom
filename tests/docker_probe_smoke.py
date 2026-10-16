"""Actual Docker-boundary CI smoke with synthetic approved evidence."""
import json
import sys
import tempfile
from pathlib import Path
from phicleanroom import sandbox, vault

def main(image: str) -> None:
    with tempfile.TemporaryDirectory(prefix="phicleanroom-smoke-") as temp:
        root = Path(temp)
        private = root / "investigator-vault"
        vault.init_vault(private)
        snapshot = root / "snapshot.json"
        evidence = root / "observation.json"
        snapshot.write_text('{"owned_demo":"yes","version":1}', encoding="utf-8")
        evidence.write_text('{"query":"test","matched":true}', encoding="utf-8")
        snapshot_sha = vault.ingest(private, snapshot)
        evidence_sha = vault.ingest(private, evidence)
        candidate = {
            "schema_version": 2, "feature": "Owned synthetic search",
            "authorization": {
                "scope": "Synthetic CI-only example", "basis": "Created by test author",
                "approved_by": "Test fixture owner",
            },
            "snapshot_sha256": snapshot_sha,
            "rules": [{
                "id": "R1", "behavior": "An exact title query finds its matching item.",
                "evidence": [{
                    "id": "E1", "kind": "test", "provenance": "VERIFIED",
                    "summary": "Synthetic test fixture, not external investigation",
                    "artifact_sha256": evidence_sha,
                }],
            }],
        }
        stage = vault.stage(private, candidate)
        vault.review(private, stage, "R1", "approve", "test fixture owner",
                     "Synthetic CI fixture only")
        receipt = root / "probe-receipt.json"
        result = sandbox.probe(private, stage, image, receipt,
                               execute=True, acknowledge_docker_risk=True, timeout=50)
        assert result["status"] == "PROBE_PASS", result
        assert result["authority"] == "NONE", result
        saved = json.loads(receipt.read_text(encoding="utf-8"))
        assert saved["spec_sha256"] == result["spec_sha256"]
        for key in ("network_reachable", "forbidden_paths_visible", "root_writable"):
            assert saved["probe"][key] is False, key
        print("DOCKER PROBE PASS: spec-only, no network, no host mounts, read-only root")
        print("SPEC SHA-256:", result["spec_sha256"])

if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Usage: docker_probe_smoke.py sha256:<image ID>")
    main(sys.argv[1])
