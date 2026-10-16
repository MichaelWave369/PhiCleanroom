"""Actual Docker integration: approved synthetic stage -> independent builder -> verifier."""
import hashlib
import json
import sys
import tempfile
from pathlib import Path

from phicleanroom import builder, vault, verifier

RULE = "An exact title query finds its matching item."


def main(builder_image: str, verifier_image: str) -> None:
    with tempfile.TemporaryDirectory(prefix="phicleanroom-verifier-smoke-") as folder:
        root = Path(folder)
        private = root / "investigator-vault"
        vault.init_vault(private)
        snapshot = root / "owned-snapshot.json"
        evidence = root / "owned-observation.json"
        snapshot.write_text('{"synthetic":true,"version":1}', encoding="utf-8")
        evidence.write_text('{"query":"Buy milk","result":["Buy milk"]}', encoding="utf-8")
        snap_hash = vault.ingest(private, snapshot)
        evidence_hash = vault.ingest(private, evidence)
        candidate = {
            "schema_version": 2, "feature": "Synthetic exact title search",
            "authorization": {
                "scope": "First-party CI fixture", "basis": "Created for isolated CI integration",
                "approved_by": "Fixture owner",
            },
            "snapshot_sha256": snap_hash,
            "rules": [{
                "id": "R1", "behavior": RULE,
                "evidence": [{
                    "id": "E1", "kind": "test", "provenance": "VERIFIED",
                    "summary": "Synthetic test-owned observation", "artifact_sha256": evidence_hash,
                }],
            }],
        }
        stage = vault.stage(private, candidate)
        vault.review(private, stage, "R1", "approve", "fixture owner",
                     "Test-owned synthetic specification only")
        quarantine = root / "quarantine"
        build_receipt = root / "builder.json"
        build = builder.run_builder(
            private, stage, builder_image, quarantine, build_receipt,
            execute=True, acknowledge_docker_risk=True, timeout=60)
        assert build["authority"] == "NONE"
        assert build["status"] == "QUARANTINED_UNVERIFIED"
        assert sorted(p.name for p in quarantine.iterdir()) == ["search.py"]
        verify_receipt = root / "verify.json"
        verified = verifier.verify(
            private, stage, quarantine, build_receipt, verifier_image,
            verify_receipt, execute=True, acknowledge_docker_risk=True, timeout=80)
        assert verified["status"] == "REFERENCE_CHECKS_PASS"
        assert verified["authority"] == "NONE"
        assert len(verified["checks"]) == 7
        assert all(row["status"] == "PASS" for row in verified["checks"])
        assert [row["id"] for row in verified["mutants"]] == [
            "always_empty", "always_all", "substring_title"
        ]
        assert all(row["status"] == "KILLED_ASSERTION" for row in verified["mutants"])
        assert verified["source_sha256"] == hashlib.sha256((quarantine / "search.py").read_bytes()).hexdigest()
        assert json.loads(verify_receipt.read_text())["source_sha256"] == verified["source_sha256"]
        # Mutate quarantined bytes and prove old builder receipt cannot bless them.
        (quarantine / "search.py").write_text("def search(items, query):\n    return []\n")
        try:
            verifier.verify(private, stage, quarantine, build_receipt,
                            verifier_image, root / "tampered-receipt.json",
                            execute=True, acknowledge_docker_risk=True)
        except verifier.VerifyError:
            pass
        else:
            raise AssertionError("tampered source reused stale receipt")
        assert not (root / "tampered-receipt.json").exists()
        print("REAL DOCKER INDEPENDENT VERIFICATION PASS")
        print("7 acceptance checks passed; 3 AST-mutated candidates killed by assertions")
        print("Tampered candidate blocked from reusing old builder receipt")
        print("No automatic release, no approval authority")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("Usage: docker_verifier_smoke.py <builder-image-id> <verifier-image-id>")
    main(sys.argv[1], sys.argv[2])
