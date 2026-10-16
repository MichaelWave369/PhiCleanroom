# Evidence Vault v2: operator guide

The v2 vault enforces artifact digests and binds human-entered review decisions to a frozen candidate digest. Keep vault contents on the **investigator side**, outside the builder's context. The supplied snapshot file is the investigator's version manifest, not automatic proof of the running target version.

## 1. Initialize and ingest

Requires Python 3.10+. These commands run locally with no model keys and no network API calls.

    python -m pip install -e .
    phicleanroom vault --vault ./local-evidence-vault init

Create or obtain two **authorized** files:
- a snapshot manifest identifying the investigated target build, platform, version, and observation context;
- a reproducible evidence artifact, such as a sanitized test result or behavioral observation.

Ingest both independently:

    phicleanroom vault --vault ./local-evidence-vault ingest --file ./snapshot.json
    phicleanroom vault --vault ./local-evidence-vault ingest --file ./observed-result.json

The command prints a SHA-256 digest for each exact file. Only those ingested digest values may appear in the staged candidate. Originals remain where they are; ingestion copies bytes into the private vault.

## 2. Create the frozen candidate

Make a JSON file named candidate.json using the following fields and your actual digests:

    {
      "schema_version": 2,
      "feature": "Authorized search feature",
      "authorization": {
        "scope": "Owned or authorized test application",
        "basis": "Operator's recorded permission",
        "approved_by": "Human authorizer"
      },
      "snapshot_sha256": "YOUR_REAL_64_CHARACTER_SNAPSHOT_DIGEST",
      "rules": [{
        "id": "R1",
        "behavior": "Searching a title term returns the matching item.",
        "evidence": [{
          "id": "E1",
          "kind": "test",
          "provenance": "VERIFIED",
          "summary": "Reproducible result from the pinned snapshot",
          "artifact_sha256": "YOUR_REAL_64_CHARACTER_EVIDENCE_DIGEST"
        }]
      }]
    }

Actual SHA-256 strings must replace both placeholders. The program does not automatically decide that an artifact deserves VERIFIED. That provenance designation and the meaning of the snapshot manifest are human review obligations.

    phicleanroom vault --vault ./local-evidence-vault stage --input ./candidate.json

Staging **rehashes the stored evidence and snapshot**, verifies both appear in the ledger, and freezes candidate.json as a canonical content digest. Keep the printed STAGED SHA-256.

## 3. Preview and record review

    phicleanroom vault --vault ./local-evidence-vault preview --stage STAGED_SHA

Review the actual evidence files separately, not merely the summary shown in the preview. Inspect the behavioral text for copied code, protected expression, secrets, or unnecessary investigator metadata. Ensure the observed source snapshot still matches the approved target.

Then the human reviewer deliberately records one decision per rule:

    phicleanroom vault --vault ./local-evidence-vault review --stage STAGED_SHA --rule R1 --decision approve --reviewer "Human reviewer" --note "Checked against owned test result"

Other decisions are 'return' and 'reject', which require a nonempty reason. The latest decision wins, so a later return revokes an earlier approval. Changing one byte in the candidate creates a new stage digest and requires new approvals.

**This is a recorded decision, not authenticated consent.** Anyone with write access to the local vault can impersonate a reviewer by passing their name. Do not treat a model or script that issues --decision approve as a substitute for real human inspection.

## 4. Verify, then export only approved behavior

    phicleanroom vault --vault ./local-evidence-vault verify
    phicleanroom vault --vault ./local-evidence-vault status --stage STAGED_SHA
    phicleanroom vault --vault ./local-evidence-vault packet --stage STAGED_SHA --out ./fresh-builder-packet --receipt ./review-receipt.json

Packet refuses unapproved rules, a non-VERIFIED rule, missing or altered stored evidence, a mismatched stage, a nonempty output folder, or a receipt inside the builder directory.

The packet folder contains only SPEC.md. This **does not** prevent a builder running on the same machine/account from reading the original app or other files. True isolation requires a separately configured permission boundary, container, VM, or remote worker with verified limited access.

Record the printed LEDGER HEAD in a *separate*, independently controlled location if you want a future audit to detect complete rewrites of the local event log.

## Failure behavior

- Every ingest, stage, review, and export takes an exclusive, cross-platform filesystem lock.
- An abandoned .lock file blocks writes; investigate interrupted operations before manually removing it.
- The event ledger chains SHA-256 digests and is checked on every command. Rewriting and recalculating the entire ledger remains possible without external anchoring.
- SHA-256 proves byte equality, not truth, provenance, authorization or good faith.
- Large evidence and sensitive binary artifacts belong in the investigator vault, never in the builder packet or public Git repository.
- The v1 metadata-only packet command now requires --legacy-unverified to emphasize its limitations.

## Follow-on boundaries

Future milestones: verified live target snapshots; authenticated reviewer identities; durable external audit-head anchoring; an independent security boundary for the builder; an actual source-level mutation runner; Anti-M verified-DONE release controls. None of those capabilities is asserted by the v2 vault.
