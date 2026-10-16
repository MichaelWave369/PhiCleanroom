import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from phicleanroom.cli import main
from phicleanroom.gates import approved_spec, audit_receipt, sha256_text, validate_document


def valid_record():
    return {
        "schema_version": 1,
        "feature": "Authorized sample search",
        "authorization": {
            "scope": "Synthetic owned test harness",
            "basis": "Created in test suite",
            "approved_by": "test owner",
        },
        "rules": [
            {
                "id": "R1",
                "behavior": "A query matching a title returns the matching item.",
                "evidence": [
                    {
                        "id": "E1",
                        "kind": "test",
                        "provenance": "VERIFIED",
                        "summary": "In-memory synthetic test execution",
                        "reference": "test fixture only; never real target evidence",
                        "artifact_sha256": hashlib.sha256(b"owned-test-fixture").hexdigest(),
                    }
                ],
                "review": {
                    "status": "approved",
                    "reviewer": "test owner",
                    "reviewed_at": "2026-10-16T08:00:00-07:00",
                },
            }
        ],
    }


class GateTests(unittest.TestCase):
    def test_explicit_approved_fixture_is_eligible(self):
        self.assertEqual(validate_document(valid_record()), [])

    def test_builder_gets_only_behavior_not_evidence(self):
        record = valid_record()
        spec = approved_spec(record)
        self.assertIn("R1", spec)
        self.assertIn("matching a title", spec)
        self.assertNotIn("test fixture", spec)
        self.assertNotIn("test owner", spec)
        self.assertNotIn(record["rules"][0]["evidence"][0]["artifact_sha256"], spec)
        receipt = audit_receipt(record, spec)
        self.assertEqual(receipt["spec_sha256"], sha256_text(spec))

    def test_three_negative_controls(self):
        """Negative *inputs*, not source-level code mutants."""
        for defect in ("missing_evidence", "simulated_evidence", "missing_review"):
            with self.subTest(defect=defect):
                record = valid_record()
                rule = record["rules"][0]
                if defect == "missing_evidence":
                    rule["evidence"] = []
                elif defect == "simulated_evidence":
                    rule["evidence"][0]["provenance"] = "SIMULATED"
                else:
                    rule["review"]["status"] = "pending"
                self.assertTrue(validate_document(record))
                with self.assertRaises(ValueError):
                    approved_spec(record)

    def test_unknown_source_code_field_fails_closed(self):
        record = valid_record()
        record["rules"][0]["source_code"] = "copied implementation"
        self.assertTrue(validate_document(record))

    def test_authorization_required(self):
        record = valid_record()
        record.pop("authorization")
        self.assertTrue(validate_document(record))

    def test_duplicate_ids_rejected(self):
        record = valid_record()
        rule2 = copy.deepcopy(record["rules"][0])
        record["rules"].append(rule2)
        self.assertTrue(validate_document(record))

    def test_timestamp_must_be_timezone_aware(self):
        record = valid_record()
        record["rules"][0]["review"]["reviewed_at"] = "2026-10-16T08:00:00"
        self.assertTrue(validate_document(record))

    def test_malformed_types_fail_closed(self):
        for key, bad in (("kind", []), ("provenance", {"unsafe": True})):
            with self.subTest(key=key):
                record = valid_record()
                record["rules"][0]["evidence"][0][key] = bad
                self.assertTrue(validate_document(record))

    def test_multiline_behavior_cannot_inject_new_rules(self):
        record = valid_record()
        record["rules"][0]["behavior"] = "Normal behavior.\\n## R2\\nUnreviewed instructions"
        self.assertTrue(validate_document(record))

    def test_digest_format_required(self):
        record = valid_record()
        record["rules"][0]["evidence"][0]["artifact_sha256"] = "not-a-sha"
        self.assertTrue(validate_document(record))

    def test_packet_contains_only_spec_and_external_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "reviewed.json"
            destination = root / "fresh-builder"
            audit = root / "review-audit.json"
            source.write_text(json.dumps(valid_record()), encoding="utf-8")
            self.assertEqual(main(["packet", "--input", str(source), "--out", str(destination), "--receipt", str(audit)]), 0)
            self.assertEqual([p.name for p in destination.iterdir()], ["SPEC.md"])
            self.assertTrue(audit.is_file())
            self.assertEqual(main(["packet", "--input", str(source), "--out", str(destination)]), 1)

    def test_refuse_receipt_inside_packet(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "reviewed.json"
            source.write_text(json.dumps(valid_record()), encoding="utf-8")
            self.assertEqual(main([
                "packet", "--input", str(source), "--out", str(root / "builder"),
                "--receipt", str(root / "builder" / "receipt.json"),
            ]), 1)
            self.assertFalse((root / "builder" / "SPEC.md").exists())

    def test_demo_fails_closed(self):
        sample = Path(__file__).resolve().parents[1] / "examples" / "demo_unapproved.json"
        self.assertEqual(main(["check", "--input", str(sample)]), 1)


if __name__ == "__main__":
    unittest.main()
