# PhiCleanroom architecture and milestones

## Roles

1. **Investigator**: Observe externally visible behavior of a feature in software the operator is authorized to study. Save reproducible evidence separately, including the inspected version and test environment. Source code or decompiled expressions are never included in the approved builder specification.
2. **Evidence judge**: Assist a human reviewer in assessing whether each proposed behavior has a reproducible reference. A Jev-style classifier can return typed decisions; probabilities and self-reported confidence do not constitute proof. Absent/unavailable/uncertain judgments fail closed.
3. **Policy gate (implemented)**: Validate source authorization, explicit per-rule approvals, and the declared VERIFIED provenance. Reject any missing approval or ambiguous input. Note: it validates metadata, not independent truth of a hash or evidence.
4. **Packet generator (implemented)**: Emit only reviewed behavioral requirements into a clean directory as SPEC.md. Optionally write an audit receipt somewhere outside the builder directory.
5. **Independent builder (future)**: Operate in a fresh isolated execution environment with access to only SPEC.md. Independent implementation should not see the original repository, tools' investigation traces, caches, or source files. A filesystem directory is not isolation.
6. **Tester (future)**: Test required positive behavior and negative controls; run genuine source-level mutation tests against at least three fault-seeded implementations. Failing malformed specifications in current unit tests are **negative inputs**, not replacement implementations.
7. **Anti-M (future)**: Require a test-to-commit binding, passing mandatory tests, detected mutants, review trace, receipt and human release approval. No agent claims DONE merely because a model says so.

## Trust boundaries

```text
[Authorization] -> [Investigator & evidence store] -> [Human reviewer]
                                                   -> [Fail-closed gate]
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

**Stop conditions:** missing authorization, absent or stale evidence, incorrect digest, non-VERIFIED provenance, non-approved review, incompatible schema, unknown record fields, unavailable judge, test timeout, mutation surviving, changed code snapshot, or missing human release approval. The CLI currently enforces only the input record conditions visible to it, not freshness, artifact rehashing, or the later checks.

## NBG-compatible provenance

Record classes are OBSERVED, VERIFIED, INFERRED, DREAMED, SIMULATED, UNKNOWN. Only VERIFIED currently passes the evidence gate. This deliberately keeps inference, dreams, simulations and initial observations from becoming approved facts without subsequent verification. A provenance label is a claim and must be independently corroborated before approval.

## Design targets

- **M1, this PR:** schema, fail-closed policy gate, behavior-only builder packet, optional separated digest receipt, tests.
- **M2:** hash-verified evidence store, immutable event prefix (external anchoring required for strong tamper evidence), reviewer interfaces, SPEC.md preview/approval workflow.
- **M3:** actual investigator and judge adapters, optional local worker selection through Crane Fly/BudgetGenius, explicit unavailability states.
- **M4:** process/container-level access isolation, fresh builder session and execution privileges, source-leak checks.
- **M5:** real mutation runner, test snapshot pinning, Anti-M DONE contract and human release signing.

No external provider is required by core. No third-party implementation or code is copied into the project.
