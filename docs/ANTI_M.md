# Anti-M v1: frozen completion contracts and human-held key attestations

Anti-M is the proposed **Anti-Mikey / Ultimate Ledger 5000** role.
This milestone adds a real fail-closed completion-review gate, not a
deployer, an identity service, or a system that declares software DONE.

## Exact meanings of Anti-M states

| Report status | Meaning | NOT equivalent to |
| --- | --- | --- |
| READY_FOR_HUMAN_RELEASE_REVIEW | Approved local Vault stage, quarantined source, original builder and independent verifier receipts match a frozen completion contract | Human release approval |
| LOCAL_KEY_ATTESTATION_RECORDED | A user entered the exact confirmation phrase and generated an HMAC with a local 32-byte private key | Authenticated identity, a public-key signature, deployment |
| KEYED_RELEASE_REVIEW_ATTESTATION_VALID | Supplied key validates MAC and current evidence still matches the frozen contract and Vault ledger head | Published, DONE or secure arbitrary code |

**Anti-M never writes DONE and never deploys.** Any real release process
must enforce further security review and human authority.

## What is frozen

The contract captures the Evidence Vault stage SHA-256, its current
hash-linked ledger head, behavior-only SPEC SHA-256, quarantined search.py
SHA-256, both exact receipt-file SHA-256 digests, pinned builder and verifier
image IDs, seven reference acceptance test identifiers, three AST mutation
identifiers, and a non-optional requires_human_release=true field.

Changes to the source, a receipt, the contract or a new Vault ledger event
invalidate readiness. Existing contract/attestation files may not be
overwritten by the CLI; create new ones for new evidence and approvals.

## 1. Freeze an eligible reference completion contract

First complete the authorized local workflow described in VAULT.md,
BUILDER.md and VERIFICATION.md: current human-reviewed stage,
unverified reference source, builder receipt and independent verifier
receipt.

    phicleanroom anti-m contract --vault ./local-evidence-vault --stage YOUR_STAGE_SHA --artifacts ./unverified-output --builder-receipt ./unverified-receipt.json --verifier-receipt ./independent-verification.json --out ./completion-contract.json

This emits READY_FOR_HUMAN_RELEASE_REVIEW, NOT DONE.

Recheck all live evidence and the frozen contract later:

    phicleanroom anti-m assess --vault ./local-evidence-vault --artifacts ./unverified-output --builder-receipt ./unverified-receipt.json --verifier-receipt ./independent-verification.json --contract ./completion-contract.json

## 2. Optional, explicitly human-triggered local attestation

The attestation needs a privately retained raw 32-byte random key. Keep it
OUTSIDE the public repo, Vault, build quarantine, browser and CI logs.
On POSIX it must have owner-only file permissions (0600 or stricter).
Windows ACLs require manual configuration.

Generate a new private key on a trusted machine, not in CI or the repo:

    python -c "import os,pathlib; p=pathlib.Path('private-attestation.key'); f=os.open(p,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600); os.write(f,os.urandom(32)); os.close(f)"

After a human has reviewed the exact artifact and receipts, explicitly
enter this required confirmation phrase:

    I AUTHORIZE THIS EXACT CANDIDATE FOR RELEASE REVIEW

This permits only recording release-REVIEW intent, NOT publication:

    phicleanroom anti-m attest --vault ./local-evidence-vault --artifacts ./unverified-output --builder-receipt ./unverified-receipt.json --verifier-receipt ./independent-verification.json --contract ./completion-contract.json --key-file ./private-attestation.key --signer "Human reviewer" --note "Reviewed the exact frozen artifact and all reference receipts." --confirmation "I AUTHORIZE THIS EXACT CANDIDATE FOR RELEASE REVIEW" --out ./release-review-attestation.json

Check the current evidence and MAC again:

    phicleanroom anti-m check-attestation --vault ./local-evidence-vault --artifacts ./unverified-output --builder-receipt ./unverified-receipt.json --verifier-receipt ./independent-verification.json --contract ./completion-contract.json --key-file ./private-attestation.key --attestation ./release-review-attestation.json

The confirmation is a nonsecret CLI argument. The private key bytes are
never passed as CLI arguments.

## Integrity and trust limitations

- HMAC-SHA256 checks possession of the same local secret. It is NOT
  public-key signing, verified human identity, a proof of genuine consent,
  a secure model-vs-human distinction or remotely verifiable governance.
  A stolen key can forge an attestation. Signer name and note are claims.
- Local builder/verifier receipts are not cryptographically signed by an
  independent hardware trust root; coordinated local forgery can create
  a mutually consistent chain. Hash agreement alone does not prove truth.
- The Vault ledger is locally hash-linked. A separately retained head is
  required to detect complete ledger replacement. Any new ledger event,
  even another approval, invalidates the current Anti-M contract.
- This version reads Vault/receipt/source files in several steps rather
  than a single atomic cross-process snapshot. Concurrent untrusted
  writers are unsafe. Stronger locking, immutable sealing and external
  audit anchors are future work.
- A signing key is checked for POSIX mode restrictions, but Windows access
  control is not managed by this tool.
- No Git commit sign-off, network deployment, source execution, distribution,
  software DONE marker, automatic release or model invocation occurs.
- The fixed reference implementation covers only one synthetic
  exact-title-search behavior. Seven checks and three mutants are not
  comprehensive correctness, intellectual-property or sandbox certification.
- The public GitHub Pages interface cannot access a private local Vault
  or generate keyed completion attestations.

## Verification coverage

Unit tests prove fail-closed handling of revoked approval, new ledger events,
changed source/receipts, missing or survived mutants, weakened contracts,
wrong keys and MAC tampering, duplicate JSON and destination collisions.

The separate real Docker smoke produces original builder/verifier receipts,
creates and rechecks an Anti-M contract, then alters source bytes and proves
that reuse of the frozen contract fails. The CI fixture does not represent
a genuine person's release decision.

**Ledger Above Ego. Evidence Before Implementation.**
