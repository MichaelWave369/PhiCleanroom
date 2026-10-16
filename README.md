# PhiCleanroom

**Evidence before implementation. Ledger above ego.**

PhiCleanroom is an original, provider-neutral clean-room feature reconstruction workflow. An authorized investigator documents observable behavior; a reviewer approves evidence-backed requirements; a separate builder receives only a filtered specification; tests and a human release gate decide whether the work is complete.

> Status: initial repository bootstrap. The first implementation is developed on a pull-request branch. No external reverse-engineering or model services are installed by default.

## Boundaries

- Investigate only software and systems you are authorized to examine.
- Requirements describe externally observable behavior, not someone else's source code or protected expression.
- A clean-room workflow is a process aid, not a guarantee against copyright, patent, license, or contract issues.
- A model's assertion does not count as test evidence or human approval.
- Nothing ships without explicit release approval.

See the first pull request for the initial evidence gate and builder-packet tooling.
