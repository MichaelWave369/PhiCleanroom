"""Narrow clean-room DEMO worker, operating only on approved SPEC.md.

Supports one exact synthetic search requirement. This is intentionally NOT
a general coding model, nor an interpretation of unknown specifications.
"""
import hashlib
import json
import sys
from pathlib import Path


KIND = "PHICLEANROOM_REFERENCE_BUILDER_V1"
RULE = "An exact title query finds its matching item."
CONTENT = '''"""Reference implementation generated only from the approved synthetic behavior."""

def search(items, query):
    """Return entries whose title exactly equals query; do not search descriptions."""
    return [item for item in items if item.get("title") == query]
'''


def main():
    raw = Path("/approved/SPEC.md").read_bytes()
    text = raw.decode("utf-8")
    # Fail closed on any other requirement, extra rule, or changed contract.
    parts = text.split("\n## ")
    if len(parts) != 2 or not parts[1].startswith("R1\n\n" + RULE + "\n"):
        print("REFERENCE_BUILDER_UNSUPPORTED_SPEC", file=sys.stderr)
        return 4
    # Ensure no extra text follows the known rule beyond the renderer's newline.
    if parts[1] != "R1\n\n" + RULE + "\n":
        print("REFERENCE_BUILDER_UNSUPPORTED_EXTRA_CONTENT", file=sys.stderr)
        return 4
    result = {
        "kind": KIND,
        "schema_version": 1,
        "spec_sha256": hashlib.sha256(raw).hexdigest(),
        "generator": "reference-exact-title-v1",
        "status": "UNVERIFIED_CANDIDATE",
        "authority": "NONE",
        "artifacts": [{
            "path": "search.py",
            "content": CONTENT,
            "sha256": hashlib.sha256(CONTENT.encode("utf-8")).hexdigest(),
        }],
    }
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
