# PR #7: Approved-SPEC Docker Isolation Probe

This is a **one-use isolation probe**, not an autonomous code builder, a full security attestation, or permission to release code.

## Purpose and trust boundary

An authorized, verified, human-reviewed Evidence Vault v2 stage is the *only*
input to the runner. The existing Vault exporter creates a fresh temporary
SPEC.md containing only the approved behavioral contract, not original code
or investigator artifacts. Only that directory is mounted into a disposable
Docker container, read-only.

The probe reads and hashes SPEC.md; it tests that the container cannot
reach the public network, see representative forbidden host paths, or write
to the root filesystem. It returns a narrowly typed JSON result over stdout.

## Requirements

- Docker Engine or Docker Desktop configured for **Linux containers**.
- Python 3.10+ with PhiCleanroom installed.
- Existing Evidence Vault v2 stage, with all rules marked VERIFIED after
  human evidence inspection and explicitly approved by a human reviewer.
- A locally built trusted probe image with an immutable sha256: image ID.

Docker daemon access is often root-equivalent on the host. Never let
untrusted software or agents use the host Docker socket, and do not run
unknown images merely because they appear to have a valid image digest.

## Build the reference worker

From the project root:

    docker build -t phicleanroom-probe:local ./worker
    docker image inspect --format '{{.Id}}' phicleanroom-probe:local

The Dockerfile currently uses a mutable Python base-image tag. Inspect
and pin the base-image digest for a more reproducible, reviewed environment.
The probe runner requires the complete local sha256 image ID, uses
--pull=never and rejects mutable tags.

## Plan without running Docker

Replace YOUR_STAGE_SHA and YOUR_IMAGE_ID with the full digests you obtained.

    phicleanroom sandbox probe --vault ./local-evidence-vault --stage YOUR_STAGE_SHA --image sha256:YOUR_IMAGE_ID

This validates the Vault approvals and current artifact hashes through
the existing Vault exporter, derives the exact SPEC digest, and returns
PLANNED_ONLY. No Docker process runs.

## Execute only with explicit permission

    phicleanroom sandbox probe --vault ./local-evidence-vault --stage YOUR_STAGE_SHA --image sha256:YOUR_IMAGE_ID --receipt ./sandbox-probe-receipt.json --execute --acknowledge-docker-risk

The output receipt must be a new file outside the Vault. It contains
stage/spec/image hashes, recorded Docker policy and the exact probe result,
not raw evidence, behavior text, original source or secrets.

### Docker constraints

- A pinned local image ID with no implicit image pulling
- No network (--network none), no host Docker socket, no original source mount
- Read-only root filesystem and read-only approved SPEC.md bind mount
- All Linux capabilities dropped, no-new-privileges, nonroot UID/GID 65532
- One CPU, 256 MiB memory, 64 PID limit
- Small 16 MiB noexec/nosuid temporary filesystem for /tmp
- Fixed python3 entrypoint and fixed probe script
- Timeout of 5-120 seconds, random disposable container name, best-effort
  force removal even on a client timeout
- No writable host output mount. Output is one bounded JSON stdout object.

## Meaning of PASS

A result of PROBE_PASS proves only that this *specific probe image* returned
the expected hash and reported the tested network/path/write restrictions
when launched with the recorded command. It is **not** a guarantee against
a malicious image, privileged Docker daemon, shared kernel vulnerability,
alternate host mounts, or dishonest reviewer.

The probe image's output is not a trusted hardware attestation. An image ID
pins the image bytes but cannot establish that they deserve trust. Use
operator-approved, inspectable worker images.

This does not yet implement a standalone AI builder, mutation runner,
runtime output channel, secure multi-tenant sandbox, authenticated reviewer,
or Anti-M release signing. The public GitHub Pages site cannot run Docker.

## CI evidence

The Python suite tests fixed Docker argv and fail-closed decisions without
launching containers. The separate Docker isolation workflow builds the
reference image on an Ubuntu GitHub runner, obtains its exact image ID,
creates a synthetic Vault stage and human-test approval, and runs the
actual probe under Docker restrictions.

The smoke test is a practical regression check, not a certification.
Failures never generate a successful probe receipt.

**Ledger Above Ego. Evidence Before Implementation.**
