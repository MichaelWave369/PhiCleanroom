# PhiCleanroom

**Evidence before implementation. Ledger above ego.**

## Public React website

The project includes a responsive React/Vite GitHub Pages website in [web/](web/), with a pipeline explorer, clearly labeled evidence-gate simulation, a browser-local v2 candidate inspector, a read-only Anti-M completion console with local receipt/source SHA-256 reconciliation, implementation status, and links to the working Python CLI.

**Expected URL after Pages is configured and deployed:** https://michaelwave369.github.io/PhiCleanroom/

See [website setup and deployment](docs/WEBSITE.md) for required owner-side **Settings > Pages > GitHub Actions** configuration. The [Anti-M console](docs/ANTI_M_CONSOLE.md) locally checks contract, receipt and source-file hashes, but never validates a private Vault or authorizes a release. The [browser inspector](docs/BROWSER_INSPECTOR.md) reads user-selected v2 manifests and files entirely in client memory, without uploads. This site is **not** the private Python vault, an authenticated approval service, or a secure builder process.

PhiCleanroom is an **original, provider-neutral clean-room workflow** for rebuilding observable software features from reviewed behavioral specifications. The investigator, evidence reviewer, isolated builder, tester, and release approver have distinct responsibilities.

## What works now

- **Anti-M completion gate v1 (local):** freezes an approved stage, current Vault ledger head, source SHA-256, builder/verifier receipts, 7 checks and 3 mutations into a strict completion contract. A separate opt-in 32-byte-key HMAC attestation records *human-claimed release review*, without deploying or marking DONE. Identity is not authenticated. See [Anti-M Guide](docs/ANTI_M.md).
- **Anti-M React completion console (read-only):** compare local completion-contract, builder/verifier receipt and quarantined-source SHA-256 hashes against the frozen lineage. Synthetic demo included. Does not authenticate humans, approve code, or connect to the Vault.
- **Evidence Vault v2:** local content-addressed evidence artifacts, a target snapshot file, and hash-verified object contents.
- **Frozen candidate specifications:** a SHA-256 identifies the exact reviewed rule set and referenced artifacts.
- **Reviewer decision ledger:** per-rule approve, return, or reject records in a hash-linked append-only-by-the-app event file.
- **Fail-closed packet:** only the currently approved, staged, hash-verified behavior-only SPEC.md reaches the builder packet.
- **Audit receipt:** optional, always outside the builder packet, including stage, snapshot, specification and ledger-head hashes.
- **Provider-neutral Investigator + Judge interfaces:** an offline structured observation adapter creates unapproved v2 candidates; a deterministic advisory judge returns typed return/human-review decisions based on provenance claims and optional local Vault integrity checks. Neither can approve, build, or ship.
- **Independent reference verifier (synthetic):** a separately pinned no-network Docker worker tests quarantined source against seven fixed acceptance checks and three AST-derived faulty versions; host binds results to approved stage, spec, source and builder receipt. Not a general verification or release engine.
- **Independent reference builder (demo only):** accepts one synthetic search rule in approved SPEC.md, runs a fixed locally pinned no-network Docker image, validates returned source file hashes, and writes only unverified candidate code into a separate quarantine folder. This is not yet general AI coding or release.
- **Restricted Docker boundary probe:** a fresh approved SPEC-only mount, locally pinned Docker image ID, no network, read-only root filesystem, capability limits, explicit execution consent and a bounded probe receipt. This is not a code builder or security certification.
- **CI and negative controls:** Python 3.10/3.12/3.13 tests for tampering, missing files, changed candidates, revoked approval, unverified claims, malformed judge responses and directory separation.

**Important limitations:** reviewer names are *not authenticated*, the snapshot is an investigator-supplied manifest rather than a verified live binary, and an attacker who can rewrite the whole ledger could recompute it without an externally saved ledger-head hash. The builder packet directory is not an OS-level sandbox. The limited, deterministic Docker **reference builder** now demonstrates an isolated spec-to-quarantined-artifact handoff. General AI builders, external-model investigator/judge integration, automated reverse engineering, genuine mutation tests, authenticated reviewer identity and Anti-M release signatures remain future work.

## Use the local role interfaces

The first Investigator and Judge contracts are deterministic, offline and provider-neutral. They do **not** connect REA, Jev or a cloud model, and a Judge decision is never an approval. See [Agent Interfaces](docs/AGENT_INTERFACES.md) for the observation-bundle schema and full CLI sequence.

```bash
phicleanroom agents providers
phicleanroom agents investigate --input ./observations.json --out ./candidate.json
phicleanroom agents judge --input ./candidate.json --vault ./local-evidence-vault --out ./advice.json
```

## Run the isolated-spec probe

The optional Docker boundary check runs a trusted local probe image with **only** an approved SPEC.md mounted read-only, with networking disabled. It requires an explicitly approved Evidence Vault stage; **it does not build software or grant release approval**. See [Isolation Guide](docs/ISOLATION.md) for exact setup, risks and Docker commands.

```bash
docker build -t phicleanroom-probe:local ./worker
docker image inspect --format '{{.Id}}' phicleanroom-probe:local
# Copy the returned sha256 image ID:
phicleanroom sandbox probe --vault ./local-evidence-vault --stage YOUR_STAGE_SHA --image sha256:YOUR_IMAGE_ID
# Execution is opt-in, and writes only an out-of-vault receipt:
phicleanroom sandbox probe --vault ./local-evidence-vault --stage YOUR_STAGE_SHA --image sha256:YOUR_IMAGE_ID --receipt ./probe-receipt.json --execute --acknowledge-docker-risk
```

## Run Anti-M completion review

Anti-M is intentionally **not a releaser**. It can freeze evidence against the current Vault ledger head and require a separate explicit keyed review step, with no automatic DONE. After obtaining a genuine reference builder and independent verifier receipt:

    phicleanroom anti-m contract --vault ./local-evidence-vault --stage YOUR_STAGE_SHA --artifacts ./unverified-output --builder-receipt ./unverified-receipt.json --verifier-receipt ./independent-verification.json --out ./completion-contract.json

See [Anti-M](docs/ANTI_M.md) for re-assessment, local key handling, explicit human review attestation and the limitations of symmetric HMAC.

## Run the independent reference verifier

After producing a quarantined `search.py` and builder receipt from an approved stage, a separate pinned Docker verifier can run a fixed acceptance suite, demonstrate three source-level mutants being detected, and emit a nonauthoritative verification receipt. See [Verification Guide](docs/VERIFICATION.md).

    phicleanroom verify reference --vault ./local-evidence-vault --stage YOUR_STAGE_SHA --artifacts ./unverified-output --builder-receipt ./unverified-receipt.json --image sha256:YOUR_VERIFIER_IMAGE_ID

This only **plans** the run. Actual execution requires an independent trusted image, new --receipt, --execute and --acknowledge-docker-risk. General independent verification and Anti-M release authority remain unimplemented.

## Run the reference builder

A known first-party demo worker can accept one precisely supported synthetic title-search requirement from an approved Vault stage and return unverified source code. Nothing runs automatically, and output is never shipped. See [Builder Contract](docs/BUILDER.md) for the supported spec, Docker instructions, trust model and result receipt.

    phicleanroom builder reference --vault ./local-evidence-vault --stage YOUR_STAGE_SHA --image sha256:YOUR_LOCAL_IMAGE_ID

## Try the gate

Requires Python 3.10+.

```bash
python -m pip install -e .
python -m unittest discover -s tests -v

# Intentionally unapproved sample; must fail closed.
phicleanroom check --input examples/demo_unapproved.json

# Legacy v1 metadata-only checks remain available, but cannot silently export.
phicleanroom check --input path/to/legacy-reviewed.json
# Legacy packet only for demonstrations, with explicit unsafe opt-in:
phicleanroom packet --input path/to/legacy-reviewed.json --out /tmp/legacy-demo --legacy-unverified
```

The **v2** vault packet refuses incomplete approval, tampered evidence, missing snapshots, missing artifacts, malformed candidates, and unknown stages. The v1 command is deliberately marked as unsafe compatibility behavior. It never copies REA output, source files, artifacts, provenance records, or reviewer notes into the builder packet. The file's text is still human-authored and **must be checked for sensitive or source-derived material** before approval.

The builder must run in a **separately provisioned session/environment** with no access to the investigated software or investigator logs; directory separation by itself is **not** a security boundary.

## Contract

```text
Authorized observation -> Evidence record -> Human review -> Gate
                                                     |
                                 REJECT / RETURN <---+---> Approved SPEC.md
                                                             |
                                                     Fresh isolated builder
                                                             |
                                                     Tests + fault controls
                                                             |
                                              Anti-M / human release approval
```

Implemented today: curated observations -> unapproved candidate -> local artifact inventory + typed advisory check -> human Vault review -> behavior-only SPEC.md + optional separate receipt -> optional restricted Docker probe and **synthetic reference builder** that quarantines candidate source. General independent model coding, acceptance validation and release are not implemented. Fresh-builder process isolation, reviewer identity verification, and Anti-M completion remain future stages.

For the vault command sequence, see [docs/VAULT.md](docs/VAULT.md). Also see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and [docs/SCHEMA.md](docs/SCHEMA.md).

## Safety and licensing

Only inspect systems you are authorized to analyze. Behavior may be functionally described, but protected expression, third-party code, keys, and proprietary details must not be carried into the specification. A clean-room process does not by itself resolve copyrights, patents, contracts, licenses, or trade-secret obligations.

**No green build is equivalent to a human release approval.**
