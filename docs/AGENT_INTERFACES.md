# PhiCleanroom PR #6: Investigator and Judge role interfaces

These are the first **provider-neutral role contracts**, not integrations
with commercial models or general-purpose reverse-engineering engines.
They are deliberately deterministic and offline. Neither has tool, shell,
browser, network, Vault review-writing, or release privileges.

## Roles and authority

| Component | What it sees | What it produces | Authority |
|---|---|---|---|
| Investigator (structured-offline-v1) | Curated, authorized observation bundle | An unapproved candidate JSON v2, with OBSERVED provenance | None |
| Vault inventory check | A candidate's SHA-256 references and investigator-private local Vault | Hash-check results only (booleans) | Integrity check, not semantic proof |
| Judge (rules-offline-v1) | Candidate v2 + optional digest-check booleans | Bounded JSON advice: RETURN_FOR_EVIDENCE or NEEDS_HUMAN_REVIEW | None |
| Human reviewer (existing Vault CLI) | Evidence artifacts + frozen staged candidate | REVIEW approve/return/reject event | Human review, identity currently self-declared |
| Separate future builder | Approved behavior-only SPEC.md | Independently implemented code | No release authority |

**Never confuse NEEDS_HUMAN_REVIEW with approval.** This status means
the declared evidence is VERIFIED and local referenced file bytes match
the Vault inventory. A human still has to examine semantics, authorization,
source expression, and approval. The snapshot is only an ingested manifest,
not an attestation of the actual running target.

## Try it locally

Requires Python 3.10+.

    python -m pip install -e .
    phicleanroom agents providers

First ingest the observation and snapshot files into your local Vault:

    phicleanroom vault --vault ./local-evidence-vault init
    phicleanroom vault --vault ./local-evidence-vault ingest --file ./snapshot.json
    phicleanroom vault --vault ./local-evidence-vault ingest --file ./observed.json

Create an observation bundle (example shape below) with real SHA-256
digests printed by the vault. This file is a *curated behavioral input*.
Do not paste someone else's source code, decompiled expressions, secrets,
or investigator traces into the behavior fields.

    {
      "schema_version": 1,
      "feature": "Owned app: title search",
      "authorization": {
        "scope": "My owned test application",
        "basis": "I am the original author",
        "approved_by": "Human owner"
      },
      "snapshot_sha256": "64-character-lowercase-SHA256-of-ingested-snapshot",
      "findings": [{
        "id": "R1",
        "behavior": "A title query finds the matching item.",
        "evidence": [{
          "id": "E1",
          "kind": "test",
          "summary": "Sanitized test observation for the pinned build",
          "artifact_sha256": "64-character-lowercase-SHA256-of-ingested-observation"
        }]
      }]
    }

The two example digest strings shown above are placeholders and will be
rejected as-is.

Run:

    phicleanroom agents investigate --input ./observations.json --out ./candidate.json
    phicleanroom agents judge --input ./candidate.json --vault ./local-evidence-vault --out ./advice.json

The Investigator **always** stamps every evidence record OBSERVED.
The Judge will therefore require human verification rather than approving
its own Investigator's output. After a separate, authorized human review
checks the actual evidence, that person may prepare an updated candidate
with genuinely justified VERIFIED declarations. The Judge can then suggest
NEEDS_HUMAN_REVIEW when all declared artifact bytes are available and
match their SHA-256 values.

The real v2 Vault review commands remain separate:

    phicleanroom vault --vault ./local-evidence-vault stage --input ./candidate.json
    phicleanroom vault --vault ./local-evidence-vault preview --stage YOUR_STAGE_SHA
    phicleanroom vault --vault ./local-evidence-vault review --stage YOUR_STAGE_SHA --rule R1 --decision approve --reviewer "Human reviewer" --note "Inspected the actual evidence"

A human should **not** approve an OBSERVED record; Vault itself blocks that.
An updated VERIFIED candidate receives a *different stage digest* and
requires explicit, current rule-by-rule human review to export any SPEC.md.

## Typed advice contract

One report example (metadata fields abbreviated here):

    {
      "schema_version": 1,
      "kind": "ADVISORY_ONLY",
      "adapter": "rules-offline-v1",
      "candidate_sha256": "<SHA-256 of canonical candidate JSON>",
      "authority": "NONE",
      "decision": "RETURN_FOR_EVIDENCE",
      "rules": [{
        "rule_id": "R1",
        "decision": "RETURN_FOR_EVIDENCE",
        "reasons": ["HUMAN_VERIFICATION_REQUIRED"]
      }],
      "note": "Not evidence truth, approval, a staged review, or release authorization."
    }

Allowed advice states are only RETURN_FOR_EVIDENCE and
NEEDS_HUMAN_REVIEW. Missing optional Vault means integrity is UNCHECKED,
not automatically approved. Unexpected adapters fail closed.

## Failure cases and known limits

- Role contracts reject unknown JSON fields, duplicate rule/evidence IDs,
  missing authorization, code-fenced behavioral rules and invalid digests.
  They cannot automatically detect every instance of copyrighted text or
  confidential content. A human must vet the curated inputs.
- Only adapters listed by the code are loadable. No dynamic code execution,
  model API access, REA or Jev client, or unsupervised investigation is
  implemented in this PR.
- Vault integrity uses the existing local content-addressed store. Byte
  checks do not prove the behavior is true or that evidence was collected
  from the correct target.
- A Python protocol class is a **logical interface, not a security sandbox**.
  Later external model/tool adapters will need independently enforced
  capabilities, model/task pinning, prompt isolation, timeouts, and budgets.
- Existing human Vault approval identity is self-declared, not authenticated.
- Running the Judge never calls Vault review/packet; no model grants DONE.
- Generated JSON uses exclusive-create semantics. Existing outputs are
  not overwritten; the Investigator and Judge operate on private local
  files, not public GitHub Pages.
