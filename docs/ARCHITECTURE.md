# PhiCleanroom architecture and milestones

## Roles

1. **Investigator (offline interface implemented)**: A structured, curated observation bundle from an authorized investigation becomes an unapproved v2 candidate stamped OBSERVED. Original observation and source files remain investigator-side. Automated website or binary inspection is not implemented.
2. **Evidence judge (offline interface implemented)**: A deterministic rules adapter uses only candidate metadata and optional separately hash-verified inventory booleans to return NEEDS_HUMAN_REVIEW or RETURN_FOR_EVIDENCE. It never issues Vault REVIEW events, authenticates humans, or promotes model confidence into proof. External Jev/model adapters are future work.
3. **Evidence vault (implemented v2)**: Copy evidence and an investigator-supplied snapshot manifest into a SHA-256 content-addressed local store; rehash objects and frozen candidate versions; append review decisions to a locally hash-linked ledger. This proves bytes match recorded digests, not that the observation is truthful or the human identity authenticated.
4. **Packet generator (implemented v2)**: Emit only reviewed behavioral requirements into a clean directory as SPEC.md after all frozen rules receive an explicit latest approval. Optionally write a separate audit receipt. Legacy v1 metadata-only export is now unsafe opt-in.
5. **Docker probe (implemented, limited)**: Explicit opt-in launches a prebuilt, SHA-256-pinned reference image with only a fresh approved SPEC.md bound read-only, no network or host output mount, read-only root and Linux capability limits. The probe reports narrow boundary checks, not a security attestation.
6. **Independent builder (future)**: Operate in a separately governed execution environment with only SPEC.md and a validated artifact output path. A probed Docker container is not yet an independent coding worker.
7. **Tester (future)**: Test required positive behavior and negative controls; run genuine source-level mutation tests against at least three fault-seeded implementations. Failing malformed specifications in current unit tests are **negative inputs**, not replacement implementations.
8. **Anti-M (future)**: Require a test-to-commit binding, passing mandatory tests, detected mutants, review trace, receipt and human release approval. No agent claims DONE merely because a model says so.

## Trust boundaries

```text
[Authorization] -> [Curated observations] -> [Offline Investigator]
                                              | produces OBSERVED v2
                                              v
                             [Vault digest verification] -> [Advisory Judge]
                                              | human reviews actual artifacts
                                              v
                                   [Human reviewer] -> [Fail-closed gate]
                                                        |       |
                                                        |       +--> audit receipt (separate)
                                                        v
                                                [SPEC.md only]
                                                        |
                                          (future OS isolation boundary)
                                                        v
                                               [Fresh builder]
                                                        |
                                           [Independent test runner]
                                                        |
                                          [Anti-M and human approval]
```

**Stop conditions:** missing authorization, absent or stale evidence, incorrect digest, non-VERIFIED provenance, non-approved review, incompatible schema, unknown record fields, unavailable judge, test timeout, mutation surviving, changed code snapshot, or missing human release approval. The v2 CLI enforces local artifact rehashing, snapshot-manifest digest pinning, frozen candidate review decisions, and packet purity. The Docker probe now constrains an optional one-shot container execution, without providing a full builder isolation or release guarantee. It does **not** independently verify live target identity, authenticate reviewers, evaluate semantic correctness, run mutation tests, or approve shipping.

## NBG-compatible provenance

Record classes are OBSERVED, VERIFIED, INFERRED, DREAMED, SIMULATED, UNKNOWN. Only VERIFIED currently passes the evidence gate. This deliberately keeps inference, dreams, simulations and initial observations from becoming approved facts without subsequent verification. A provenance label is a claim and must be independently corroborated before approval.

## Design targets

- **M1, merged:** schema v1, fail-closed metadata gate, behavior-only packet, tests.
- **M2, merged:** local hash-verified evidence store, frozen v2 candidates, locally hash-linked event ledger (external anchoring still required), human-entered reviewer decision CLI, SPEC.md preview, stricter packet.
- **M3, merged:** versioned provider-neutral Investigator/Judge protocols, offline structured investigator, deterministic advisory judge and CLI.
- **M4, this PR:** restricted Docker **probe only**, with a verified approved SPEC-only input, no network, read-only root and minimal container privileges, plus a synthetic real-Docker CI smoke test. Not a full coding worker or isolated hostile-code guarantee.
- **M4b, future:** production-grade isolated code-building worker and governed artifact channel, stronger host trust boundaries, source-leak checks and malicious-worker testing.
- **M5:** real mutation runner, test snapshot pinning, Anti-M DONE contract and human release signing.

No external provider is required by core. No third-party implementation or code is copied into the project.
