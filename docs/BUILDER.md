# PR #8: Independent Reference Builder Contract

## Purpose

An explicitly human-approved, frozen Evidence Vault v2 stage may be used to
launch a restricted Docker **reference builder**. The worker receives only
a freshly generated, behavior-only SPEC.md and returns one small
**unverified candidate source file** to a new quarantine directory.

This is **not** a general-purpose AI builder, a security attestation, a
clean-room legal guarantee, or permission to release code.

The reference worker supports precisely one synthetic requirement:

> An exact title query finds its matching item.

It refuses additional or unknown requirements. It generates a small
first-party Python title search function from a known reference template.
It never sees the investigated target application's code.

## Roles

- Human reviewer: checks actual authorized evidence and approves the exact
  frozen candidate in the Vault (reviewer identities remain self-declared).
- Vault: rehashes the evidence and regenerates an approved SPEC-only packet.
- Reference worker: runs without network, Docker socket, host output mounts,
  writable root filesystem or additional Linux capabilities. Only approved
  SPEC.md crosses into it.
- Host validator: checks all returned JSON fields, approved specification
  SHA-256, artifact UTF-8 SHA-256, safe filename, size and status.
- Quarantine: receives the new source file, marked UNVERIFIED; never runs
  generated code during the host builder command.
- Future test/Anti-M stages: independently test and approve or reject the
  candidate. These release controls do not yet exist.

## Run locally

Requires Docker Engine or Docker Desktop in Linux-container mode and
Python 3.10+ with PhiCleanroom installed. Docker daemon access can grant
host-equivalent privilege; inspect and trust the builder image before use.

Build and pin the included reference worker:

    docker build -f worker/Builder.Dockerfile -t phicleanroom-reference:local ./worker
    docker image inspect --format '{{.Id}}' phicleanroom-reference:local

Use the returned immutable image ID and an already human-approved stage.
Plan first without starting Docker:

    phicleanroom builder reference --vault ./local-evidence-vault --stage YOUR_STAGE_SHA --image sha256:YOUR_LOCAL_IMAGE_ID

Then execute, with explicit consent and two separate, new destinations:

    phicleanroom builder reference --vault ./local-evidence-vault --stage YOUR_STAGE_SHA --image sha256:YOUR_LOCAL_IMAGE_ID --out ./unverified-output --receipt ./unverified-receipt.json --execute --acknowledge-docker-risk

Output artifacts: unverified-output/search.py, alongside an out-of-directory
receipt with source and spec hashes, stage/image identity, and status
QUARANTINED_UNVERIFIED. The receipt includes no behavior text or source.

## Exact contract

JSON stdout requires:
- kind = PHICLEANROOM_REFERENCE_BUILDER_V1
- schema_version = 1
- generator = reference-exact-title-v1
- spec_sha256 = SHA-256 of the approved SPEC.md
- status = UNVERIFIED_CANDIDATE
- authority = NONE
- artifacts = list of {path, content, sha256} records

This first reference host accepts exactly one file called search.py,
with UTF-8 content no larger than 16 KiB. Every SHA-256 must match.
It rejects unexpected fields, incorrect provider, duplicate JSON keys,
path traversal, extra output files, forged approval, and existing output
paths. stdout is limited to 64 KiB *after* subprocess capture. The current
code assumes a known, trusted worker image; hostile-model output needs
streamed, proactively byte-limited IPC in a future milestone.

The worker image is built from a mutable upstream Python base tag. The
runner pins the locally built image ID, but the image's original build
provenance and security still need operator review.

## Automated checks

The Python unit tests validate quarantine, digest pinning, Docker argv,
forged output and missing permission without executing Docker.

The separate reference-builder GitHub Actions workflow creates an owned
synthetic Vault fixture, records a fixture-only approval, builds a trusted
Docker image, then launches an actual restricted container. It rehashes
the generated file and runs independent functionality checks **only for
the known synthetic example**, never for arbitrary untrusted user output.

## Missing features

This milestone does not connect REA, Jev, Opus or any external models; does
not run a generic independent coding session; does not implement streamed
bounded IPC, genuine mutation testing, authenticated reviewer identity,
or Anti-M DONE/release signing. The public GitHub Pages website remains
informational and cannot run Docker or access local investigator artifacts.

**Ledger Above Ego. Evidence Before Implementation.**
