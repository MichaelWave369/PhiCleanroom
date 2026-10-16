# PhiCleanroom

**Evidence before implementation. Ledger above ego.**

PhiCleanroom is an **original, provider-neutral clean-room workflow** for rebuilding observable software features from reviewed behavioral specifications. The investigator, evidence reviewer, isolated builder, tester, and release approver have distinct responsibilities.

## What works now

- **Evidence Vault v2:** local content-addressed evidence artifacts, a target snapshot file, and hash-verified object contents.
- **Frozen candidate specifications:** a SHA-256 identifies the exact reviewed rule set and referenced artifacts.
- **Reviewer decision ledger:** per-rule approve, return, or reject records in a hash-linked append-only-by-the-app event file.
- **Fail-closed packet:** only the currently approved, staged, hash-verified behavior-only SPEC.md reaches the builder packet.
- **Audit receipt:** optional, always outside the builder packet, including stage, snapshot, specification and ledger-head hashes.
- **CI and negative controls:** Python 3.10/3.12/3.13 tests for tampering, missing files, changed candidates, revoked approval, unverified claims, and directory separation.

**Important limitations:** reviewer names are *not authenticated*, the snapshot is an investigator-supplied manifest rather than a verified live binary, and an attacker who can rewrite the whole ledger could recompute it without an externally saved ledger-head hash. The builder packet directory is not an OS-level sandbox. Actual isolated agent sessions, integrated investigator adapters, mutation tests, and Anti-M release signatures are future work.

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

Implemented today: investigator-supplied artifacts -> local hash verification -> frozen candidate -> per-rule reviewer decisions -> behavior-only SPEC.md + optional separate receipt. Fresh-builder process isolation, reviewer identity verification, and Anti-M completion remain future stages.

For the vault command sequence, see [docs/VAULT.md](docs/VAULT.md). Also see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and [docs/SCHEMA.md](docs/SCHEMA.md).

## Safety and licensing

Only inspect systems you are authorized to analyze. Behavior may be functionally described, but protected expression, third-party code, keys, and proprietary details must not be carried into the specification. A clean-room process does not by itself resolve copyrights, patents, contracts, licenses, or trade-secret obligations.

**No green build is equivalent to a human release approval.**
