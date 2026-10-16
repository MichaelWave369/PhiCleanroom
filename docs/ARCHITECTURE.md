# PhiCleanroom architecture and milestones

## Roles

1. **Investigator (offline interface implemented)**: A structured, curated observation bundle from an authorized investigation becomes an unapproved v2 candidate stamped OBSERVED. Original observation and source files remain investigator-side. Automated website or binary inspection is not implemented.
2. **Evidence judge (offline interface implemented)**: A deterministic rules adapter uses only candidate metadata and optional separately hash-verified inventory booleans to return NEEDS_HUMAN_REVIEW or RETURN_FOR_EVIDENCE. It never issues Vault REVIEW events, authenticates humans, or promotes model confidence into proof. External Jev/model adapters are future work.
3. **Evidence vault (implemented v2)**: Copy evidence and an investigator-supplied snapshot manifest into a SHA-256 content-addressed local store; rehash objects and frozen candidate versions; append review decisions to a locally hash-linked ledger. This proves bytes match recorded digests, not that the observation is truthful or the human identity authenticated.
4. **Packet generator (implemented v2)**: Emit only reviewed behavioral requirements into a clean directory as SPEC.md after all frozen rules receive an explicit latest approval. Optionally write a separate audit receipt. Legacy v1 metadata-only export is now unsafe opt-in.
5. **Independent builder (future)**: Operate in a fresh isolated execution environment with access to only SPEC.md. Independent implementation should not see the original repository, tools' investigation traces, caches, or source files. A filesystem directory is not isolation.
6. **Tester (future)**: Test required positive behavior and negative controls; run genuine source-level mutation tests against at least three fault-seeded implementations. Failing malformed specifications in current unit tests are **negative inputs**, not replacement implementations.
7. **Anti-M (future)**: Require a test-to-commit binding, passing mandatory tests, detected mutants, review trace, receipt and human release approval. No agent claims DONE merely because a model says so.

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

**Stop conditions:** missing authorization, absent or stale evidence, incorrect digest, non-VERIFIED provenance, non-approved review, incompatible schema, unknown record fields, unavailable judge, test timeout, mutation surviving, changed code snapshot, or missing human release approval. The v2 CLI now enforces local artifact rehashing, snapshot-manifest digest pinning, frozen candidate review decisions, and packet purity. It does **not** independently verify live target identity, authenticate reviewers, evaluate semantic correctness, run mutation tests, or approve shipping.

## NBG-compatible provenance

Record classes are OBSERVED, VERIFIED, INFERRED, DREAMED, SIMULATED, UNKNOWN. Only VERIFIED currently passes the evidence gate. This deliberately keeps inference, dreams, simulations and initial observations from becoming approved facts without subsequent verification. A provenance label is a claim and must be independently corroborated before approval.

## Design targets

- **M1, merged:** schema v1, fail-closed metadata gate, behavior-only packet, tests.
- **M2, merged:** local hash-verified evidence store, frozen v2 candidates, locally hash-linked event ledger (external anchoring still required), human-entered reviewer decision CLI, SPEC.md preview, stricter packet.
- **M3, this PR:** versioned provider-neutral Investigator/Judge protocols, offline structured investigator, deterministic advisory judge, strict advice schema pinned to candidate hashes, optional Vault inventory digest verification, and CLI. External-model agents, Crane Fly/BudgetGenius worker selection, privileged investigator tools, and authenticated approvals are not implemented.
- **M4:** process/container-level access isolation, fresh builder session and execution privileges, source-leak checks.
- **M5:** real mutation runner, test snapshot pinning, Anti-M DONE contract and human release signing.

No external provider is required by core. No third-party implementation or code is copied into the project.
