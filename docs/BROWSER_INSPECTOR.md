# Browser-local Evidence Vault candidate inspector (PR #5)

The public React GitHub Pages site now offers a **read-only, browser-only**
inspector for candidate JSON documents using the Python Evidence Vault **v2**
schema. It does not connect to the private investigator vault, access arbitrary
local paths, authenticate reviewers, or create builder packets.

## Usage

1. Open the site's **Local Inspector** tab.
2. Choose a local v2 candidate JSON file (`candidate.json`) using the first file picker. A synthetic sample is also available; it is clearly marked and has no real evidence or approval.
3. Review the displayed **declared** rules and provenance categories.
4. Optionally choose local snapshot/evidence files in the second picker. The browser uses native Web Crypto SHA-256 on the selected files' bytes.
5. Compare **matches / referenced files**, the per-artifact statuses, and unmatched selected filenames. Clear the session to remove selected data from React memory.

The inspector limits individual artifact files to 16 MiB, a selection to
12 files, and candidate JSON to 512 KiB. These limits prevent accidental
large in-memory browser operations. If a real evidence collection is larger,
use the Python CLI to verify it instead.

## Precise meaning of a result

- **File hash match:** selected bytes equal the digest declared in a candidate.
- **File absent:** no selected file has the requested digest. No approval implied.
- **Unmatched selection:** selected bytes don't match any referenced digest. The
  v2 schema does not provide trusted filenames, so the UI doesn't guess which
  declared artifact a wrong file was intended to represent.
- **VERIFIED (declared):** a string inside the candidate, not independent
  semantic validation.
- **"All referenced bytes match":** comparison complete for locally selected
  files, **not** authorization, source attestation, behavioral truth, signed
  human approval, audit-ledger validation, or permission to release.

The private Python Evidence Vault remains the authority for stage review,
artifact ledger verification and spec-only packet export. The site is a
viewer, not a vault management interface.

## Privacy boundary

Selected files are read by the browser via File APIs and Web Crypto.
The inspector code has no API calls, no browser storage, no service worker,
and no network upload of candidate contents, file bytes or computed hashes.
Only the resulting digest, bounded filename, file size and parsed candidate
exist in in-memory React state. Clearing or reloading the page discards
those values, although ordinary browser/OS memory management does not
guarantee immediate secure erasure.

As with any remote web app, don't open highly sensitive evidence in the
public interface unless you trust the published script. For sensitive
materials, use the local Python CLI in an investigator-controlled environment.

## Testing

    cd web
    npm install
    npm test
    npm run build

Tests cover v2 schema rejection, invalid provenance, malformed and oversized
inputs, digest calculation, exact-match semantics, unmatched selected files,
missing Web Crypto, and React app server rendering. This is **not** a full
browser end-to-end security test, and Web Crypto hash equality does not
validate claims about code behavior.

## Compatibility

The viewer accepts candidate **schema v2** per
[VAULT.md](VAULT.md), not audit receipts, the v1 "reviewed" schema, raw
ZIP archives, or arbitrary reverse-engineering logs.
