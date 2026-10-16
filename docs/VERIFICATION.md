# PR #9: Independent Verification Engine, reference suite v1

## What is actually implemented

A human-approved Vault v2 stage, a previously quarantined builder artifact and
its original builder receipt are rehashed and bound together **before** a
separately pinned Docker verifier receives the SPEC and candidate source.
The host verifier never executes the generated source.

This first implementation is deliberately narrow: one first-party *synthetic*
exact-title lookup rule, seven independent acceptance assertions and **three
AST transformations of the actual quarantined candidate source**. The mutated
versions are not merely canned, unrelated broken programs.

## Trust path

1. An authorized reviewer checks the real evidence and approves the exact
   frozen v2 candidate using the existing Vault CLI.
2. The restricted reference builder (PR #8) receives only SPEC.md and returns
   quarantined search.py plus a new builder receipt with stage, spec and
   source SHA-256 values.
3. The verifier reexports the approved spec from the Vault and compares it
   with the original builder receipt. It rehashes the *current* source file,
   rejects missing, unexpected, symlinked or additional quarantine files,
   and refuses a stale or mismatched receipt.
4. A completely separate pinned Docker image, built from
   worker/Verifier.Dockerfile, receives only SPEC.md and search.py through
   a read-only mount. A nonsecret stage SHA-256 is passed as environment
   metadata.
5. The verifier runs a fixed, first-party acceptance harness in a subprocess
   **inside Docker**, then creates three changed variants from the actual
   candidate's Python AST. Every mutant is checked by the same harness.
6. The host checks the exact result schema, source/spec/stage digests, all
   seven named passing checks and all three uniquely hashed mutants killed
   specifically by failed assertions (not crashes).
7. A separate new metadata-only verification receipt is issued with status
   REFERENCE_CHECKS_PASS and authority NONE. **This is not a release, legal
   certification, or Anti-M DONE state.**

## Seven required behaviors

- exact_title: exact title match returns the correct item
- description_exclusion: description-only words do not match
- substring_exclusion: partial title matches do not count
- no_match: absent titles return no items
- case_sensitive: case changes do not match
- duplicate_titles: all exact matches appear in order
- missing_title: items missing a title do not match

The current synthetic reference specification only states exact title match;
the other cases operationalize a stricter interpretation of that requirement.
Future general-purpose verification must derive acceptance criteria from the
human-approved contract, rather than silently broadening requirements.

## Source-derived mutants

- always_empty: replaces the search function body with a return of an empty list.
- always_all: replaces the search function body with a return of every item.
- substring_title: replaces exact comparison with substring containment.

All three are created from an AST parsed from the original candidate file,
are required to differ in SHA-256, are compiled as Python and are run through
the same fixed test harness in the verifier container. A mutation is marked
KILLED_ASSERTION only if a named assertion fails, without a crash. A surviving,
missing, repeated or crashed mutant blocks verification.

These mutations demonstrate that the reference test suite detects these
three faults. They are not exhaustive mutation coverage and do not prove
all possible implementations correct.

## Local workflow

Requires a previously approved Vault stage and PR #8 generated quarantine
directory + builder receipt. See docs/BUILDER.md for preparation and consent.

Build a **different** verifier image:

    docker build -f worker/Verifier.Dockerfile -t phicleanroom-verifier:local ./worker
    docker image inspect --format '{{.Id}}' phicleanroom-verifier:local

First plan without executing untrusted source:

    phicleanroom verify reference --vault ./local-evidence-vault --stage YOUR_STAGE_SHA --artifacts ./unverified-output --builder-receipt ./unverified-receipt.json --image sha256:YOUR_VERIFIER_IMAGE_ID

Then launch Docker explicitly and write a new receipt *outside* Vault and
quarantine:

    phicleanroom verify reference --vault ./local-evidence-vault --stage YOUR_STAGE_SHA --artifacts ./unverified-output --builder-receipt ./unverified-receipt.json --image sha256:YOUR_VERIFIER_IMAGE_ID --receipt ./independent-verification.json --execute --acknowledge-docker-risk

When successful, the command reports REFERENCE_CHECKS_PASS. That status
never sets DONE, writes a release, modifies the builder source or grants a
human approval. Failure does not produce a successful verification receipt.

## Security limits

- The public GitHub Pages app cannot execute Docker, access the Vault,
  inspect arbitrary local sources or grant approvals.
- Docker shares the host kernel and its privileged daemon remains part of
  the trust boundary; this is not a secure hostile-code execution service.
  An approved and inspected verifier image is required, and an image ID
  only pins bytes, not trustworthiness. Upstream Docker base tags are not
  yet digest pinned during builds.
- The worker executes candidate Python inside a restricted Docker process:
  no network, nonroot user, read-only root, dropped capabilities, limited
  memory/PIDs/CPU, small noexec tmpfs and no host output mount. These
  measures mitigate but do not eliminate arbitrary-code risk.
- Child stdout is limited **after capture**, not streamed and capped. A
  hostile worker could still exhaust resources. Stronger cgroup/seccomp,
  brokered IPC, streaming output limits and a VM boundary are future tasks.
- No agent identity authentication, test-suite signature, independently
  anchored immutable verification ledger, or Anti-M release approval yet.
- CI uses owned, synthetic test fixtures only. No third-party source code
  or privileged private evidence is downloaded or committed.

## Run tests

    python -m unittest discover -s tests -v

The separate GitHub Actions job "PhiCleanroom independent verification smoke"
builds pinned local image IDs for the builder and verifier; creates a synthetic
approved Vault stage; runs both real Docker workers; checks seven acceptance
cases, three source-derived mutants and a tampered-file rejection.

**Ledger Above Ego. Evidence Before Implementation.**
