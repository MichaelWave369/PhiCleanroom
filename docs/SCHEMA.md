# Reviewed spec JSON v1

The input is intentionally strict: unknown keys are rejected to reduce accidental transmission of original material. Rejection is not a substitute for a reviewer checking the text for source-derived expression.

```json
{
  "schema_version": 1,
  "feature": "Descriptive feature name",
  "authorization": {
    "scope": "Target application/feature owner-authorized scope",
    "basis": "Operator's documented authority to examine the target",
    "approved_by": "Human authorizer"
  },
  "rules": [
    {
      "id": "R1",
      "behavior": "When a user queries by title, matching items are returned.",
      "evidence": [
        {
          "id": "E1",
          "kind": "test",
          "provenance": "VERIFIED",
          "summary": "Reproducible observation of the title match case",
          "reference": "Private investigator record, not a source-code pointer",
          "artifact_sha256": "<64-character lowercase SHA-256 of real evidence artifact>"
        }
      ],
      "review": {
        "status": "approved",
        "reviewer": "Named human reviewer",
        "reviewed_at": "2026-10-16T08:00:00-07:00"
      }
    }
  ]
}
```

Use a real digest, artifact, and authorized reviewer. The CLI checks digest **format**, not the bytes of the underlying artifact. Do not use the example as production evidence.

The builder packet contains the feature name, rule IDs, and behavior descriptions only. Reference paths, evidence text, review metadata, artifact digests, original code and snippets are never placed in that packet. For stronger privacy, the feature name and approved behavioral text must be manually sanitized too.

## CLI outcomes

- exit **0**: eligible record / packet written;
- exit **1**: denied for gate or isolation-path policy reasons;
- exit **2**: input or I/O error.

Use `--receipt` outside the packet directory to capture a standalone audit record. This is an ordinary JSON file; external anchoring or append-only storage will be required for tamper resistance.

`check` does not attest that evidence bytes exist, are fresh, or were correctly interpreted. Until M2, a human must independently verify that.
