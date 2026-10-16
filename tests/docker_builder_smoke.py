"""Real container integration: synthetic, human-reviewed input -> quarantined demo code."""
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

from phicleanroom import builder, vault

RULE = "An exact title query finds its matching item."


def main(image: str) -> None:
    with tempfile.TemporaryDirectory(prefix="phicleanroom-builder-ci-") as folder:
        root = Path(folder)
        private = root / "private-vault"
        vault.init_vault(private)
        snapshot = root / "snapshot.json"
        evidence = root / "observation.json"
        snapshot.write_text('{"owned_synthetic_demo":true,"version":1}', encoding="utf-8")
        evidence.write_text('{"query":"Buy milk","expected":["Buy milk"]}', encoding="utf-8")
        snapshot_hash = vault.ingest(private, snapshot)
        evidence_hash = vault.ingest(private, evidence)
        candidate = {
            "schema_version": 2, "feature": "Owned synthetic title lookup",
            "authorization": {"scope": "Synthetic CI demo",
                              "basis": "Created in the test suite",
                              "approved_by": "Fixture owner"},
            "snapshot_sha256": snapshot_hash,
            "rules": [{
                "id": "R1", "behavior": RULE,
                "evidence": [{
                    "id": "E1", "kind": "test", "provenance": "VERIFIED",
                    "summary": "Synthetic CI-only evidence",
                    "artifact_sha256": evidence_hash,
                }],
            }],
        }
        stage = vault.stage(private, candidate)
        vault.review(private, stage, "R1", "approve", "fixture owner",
                     "Synthetic owned CI behavior only")
        output = root / "unverified"
        receipt = root / "build-receipt.json"
        report = builder.run_builder(
            private, stage, image, output, receipt, execute=True,
            acknowledge_docker_risk=True, timeout=60)
        assert report["status"] == "QUARANTINED_UNVERIFIED"
        assert report["authority"] == "NONE"
        source = output / "search.py"
        assert source.is_file()
        digest = hashlib.sha256(source.read_bytes()).hexdigest()
        assert digest == report["artifacts"][0]["sha256"]
        # Test the example output *separately* in this CI-only synthetic fixture.
        # Do not import/run unknown output automatically in the builder command.
        process = subprocess.run(
            [sys.executable, "-I", "-c",
             "import importlib.util, sys;"
             "p=sys.argv[1];"
             "s=importlib.util.spec_from_file_location('demo',p);"
             "m=importlib.util.module_from_spec(s);s.loader.exec_module(m);"
             "items=[{'title':'Buy milk','description':'carton'},"
             "{'title':'Pack bags','description':'milk'}];"
             "assert m.search(items,'Buy milk')==[items[0]];"
             "assert m.search(items,'carton')==[];"
             "assert m.search(items,'No match')==[]",
             str(source)],
            capture_output=True, text=True, timeout=10, check=False)
        assert process.returncode == 0, process.stderr
        saved = json.loads(receipt.read_text(encoding="utf-8"))
        assert saved["spec_sha256"] == report["spec_sha256"]
        assert len(list(output.iterdir())) == 1
        assert "evidence" not in source.read_text().lower()
        print("REFERENCE BUILDER DOCKER PASS: spec-only -> quarantined code -> synthetic CI check")
        print("STILL UNVERIFIED/NO RELEASE:", report["status"], report["authority"])


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Usage: docker_builder_smoke.py sha256:<image-id>")
    main(sys.argv[1])
