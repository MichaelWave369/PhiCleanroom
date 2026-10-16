# PR #12: Out-of-band witness checkpoints

PhiCleanroom can now generate a compact **checkpoint commitment** over a
CURRENT Anti-M completion contract and its private evidence history. It
includes the exact Vault ledger-head SHA-256, frozen stage, specification,
source, builder/verifier receipt hashes and the two locally pinned worker
image IDs.

**The checkpoint is not an authenticated witness, signature, external
service, software release or legal proof.** It becomes useful for tamper
detection *only after you independently retain its SHA-256 digest* in a place
the local machine or untrusted process cannot silently rewrite.

## Why this matters

A locally hash-linked ledger can detect changes to individual entries, but
a malicious process controlling the whole local filesystem might replace
the ledger, staged candidates and corresponding receipts together. All
the new files could be mutually consistent. Without an independent prior
commitment, there is no way to tell they were replaced.

An out-of-band digest helps by binding a local checkpoint to bytes recorded
somewhere else. The SHA-256 of the checkpoint is printed by this command,
but no remote server receives or saves it for you.

## 1. Make a checkpoint

First complete the authorized v2 Vault, reference Docker builder, independent
verifier and Anti-M completion workflow, following VAULT.md, BUILDER.md,
VERIFICATION.md and ANTI_M.md. The checkpoint is blocked unless current
Anti-M evidence still passes.

Run locally:

    phicleanroom witness checkpoint --vault ./local-evidence-vault --artifacts ./unverified-output --builder-receipt ./unverified-receipt.json --verifier-receipt ./independent-verification.json --contract ./completion-contract.json --out ./witness-checkpoint.json

The command creates a new JSON file outside the evidence Vault and source
quarantine. It prints:

- CHECKPOINT_CREATED_UNANCHORED
- checkpoint_sha256 (64 lowercase hexadecimal characters)
- current stage and Vault ledger-head SHA-256 values
- a warning to save the checkpoint SHA separately

It is **not yet anchored** merely because the JSON file exists or its digest
was printed on the same computer.

## 2. Retain the expected SHA somewhere independent

Keep a copy of the printed full checkpoint SHA-256 somewhere independently
controlled. Options include a hand-written paper record, independently
managed offline storage, or a separate write-protected USB used only for
copies. A hash in a second file within the same writable folder is not
a useful independent anchor.

Do **not** copy the private HMAC attestation key, confidential evidence
files or investigator source material into this checkpoint or its hash
record. The checkpoint itself contains only hashes, image IDs, scope
and a fixed disclaimer.

Make sure you know which version/date of the project each saved
checkpoint hash relates to. A new approval or ledger event creates a new
checkpoint and should not silently replace the historic independent anchor.

## 3. Verify current evidence against that independent value

Retrieve the independently saved digest. Provide it explicitly:

    phicleanroom witness verify --vault ./local-evidence-vault --artifacts ./unverified-output --builder-receipt ./unverified-receipt.json --verifier-receipt ./independent-verification.json --contract ./completion-contract.json --checkpoint ./witness-checkpoint.json --expected-checkpoint-sha256 YOUR_SEPARATELY_SAVED_64_CHARACTER_SHA256

The command checks in this order:

1. The expected SHA is present, exact-format and not an empty placeholder.
2. The checkpoint file's raw bytes match that *previously retained* digest.
3. The checkpoint JSON passes strict schema and duplicate-key checks.
4. The private Vault stage, rule approvals and ledger head are **current**.
5. The source, builder receipt, verifier receipt, pinned image IDs and
   required seven tests / three mutants match the frozen Anti-M contract.
6. Every checkpoint field matches the currently inspected completion
   contract and ledger head.

Only then is the result **INDEPENDENT_CHECKPOINT_MATCH**, with authority
NO_APPROVAL_NO_DONE_NO_DEPLOY.

If someone rewrites all local evidence and recreates a matching checkpoint,
it still fails against the original separately saved hash. However, if an
attacker also controls or replaces the independent expected digest,
this protection disappears.

## Trust model and limitations

- There is **no external witness service**, authenticated identity,
  asymmetric signature or trusted hardware ledger. The user must retain
  the earlier checksum independently.
- The checkpoint demonstrates a comparison between local information
  and an expected digest, not that the recorded behavior is true, that
  the correct software was investigated, or that a real human approved.
- File checks and live Vault reads are not one immutable cross-process
  transaction; protect against concurrent untrusted local file mutation.
- The CLI cannot distinguish honest, independent expected hash material
  from a fresh hash typed by an attacker. Out-of-band custody is a
  human/operator responsibility.
- An HMAC attestation from Anti-M is a distinct, optional private
  key-possession check. This witness never reads keys or creates attestations.
- Only one synthetic reference exact-title-search completion workflow
  is covered, not general-purpose software builds.
- No automatic GitHub release, deployment, signature, public key identity,
  DONE state or permission to ship code is created.
- The public React Pages UI does not yet import witness checkpoints or
  revalidate private Vault history. Use this command from a trusted
  local Python environment.

## Verification and CI

Python tests include original-anchor success, missing/wrong expected hash,
checkpoint byte substitution, a fully recomputed forged checkpoint,
malformed/duplicate-key records, receipt changes, source changes, a new
review ledger event, revoked approval and output location protection.

The existing real two-Docker-worker CI smoke was expanded to create and
verify an Anti-M witness checkpoint from actual synthetic builder and
verifier receipts. It then changes the generated source and confirms the
checkpoint cannot bless it. This is integration evidence for the first-party
synthetic fixture, not independently witnessed real-world deployment.

**Ledger Above Ego. Evidence Before Implementation. No Receipt, No DONE.**
