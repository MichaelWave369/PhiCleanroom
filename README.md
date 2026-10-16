# PhiCleanroom

**Evidence before implementation. Ledger above ego.**

PhiCleanroom is an **original, provider-neutral clean-room workflow** for rebuilding observable software features from reviewed behavioral specifications. The investigator, evidence reviewer, isolated builder, tester, and release approver have distinct responsibilities.

## What PR #1 delivers

- A local, standard-library **evidence/approval gate** with explicit statuses.
- A **builder-packet exporter** that produces a directory containing **only `SPEC.md`**.
- A separate optional audit receipt containing evidence digests and review metadata.
- Automated tests, including three negative controls for incomplete or unapproved claims.
- No model APIs, third-party RE tooling, or external services required.

This first release does **not** launch a sandboxed builder, reverse engineer an app, integrate REA/Jev/Opus/Haiku, enforce process-level isolation, perform full mutation testing, or authorize shipping. Those are future milestones, not promises disguised as green checkmarks.

## Try the gate

Requires Python 3.10+.

```bash
python -m pip install -e .
python -m unittest discover -s tests -v

# Intentionally unapproved sample; must fail closed.
phicleanroom check --input examples/demo_unapproved.json

# For an authorized feature: create your own evidence-backed JSON and obtain review.
phicleanroom check --input path/to/reviewed.json
phicleanroom packet --input path/to/reviewed.json --out /tmp/fresh-builder-packet --receipt /tmp/phi-audit.json
```

`packet` refuses **any** incomplete, unsupported, unapproved, malformed, or ambiguously authorized requirement. It never copies REA output, source files, artifacts, provenance records, or reviewer notes into the builder packet. The file's text is still human-authored and **must be checked for sensitive or source-derived material** before approval.

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

The only implemented arrows in this PR are **reviewed JSON -> fail-closed gate -> SPEC.md + optional external receipt**.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and [docs/SCHEMA.md](docs/SCHEMA.md).

## Safety and licensing

Only inspect systems you are authorized to analyze. Behavior may be functionally described, but protected expression, third-party code, keys, and proprietary details must not be carried into the specification. A clean-room process does not by itself resolve copyrights, patents, contracts, licenses, or trade-secret obligations.

**No green build is equivalent to a human release approval.**
