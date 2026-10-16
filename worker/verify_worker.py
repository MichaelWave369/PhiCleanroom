"""Trusted reference verifier that runs candidate code only inside Docker.

This image uses a fixed first-party acceptance suite and three AST source
mutations. The candidate is untrusted; this is a narrow Docker-based demo,
not a hostile-code sandbox, semantic security proof, or release mechanism.
"""
from __future__ import annotations

import ast
import copy
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

KIND = "PHICLEANROOM_REFERENCE_VERIFIER_V1"
RULE = "An exact title query finds its matching item."
CHECKS = ("exact_title", "description_exclusion", "substring_exclusion",
          "no_match", "case_sensitive", "duplicate_titles", "missing_title")
MUTANTS = (
    ("always_empty", "return []"),
    ("always_all", "return list(items)"),
    ("substring_title", 'return [item for item in items if query in item.get("title", "")]'),
)
TEST_SCRIPT = r'''
import json
import sys
from pathlib import Path
data = Path(sys.argv[1]).read_text(encoding="utf-8")
namespace = {"__name__": "candidate_isolation_test"}
try:
    exec(compile(data, sys.argv[1], "exec"), namespace)
    search = namespace["search"]
except BaseException:
    print(json.dumps({"status":"CRASH","checks":[]}))
    sys.exit(10)
items = [
    {"title": "Buy milk", "description": "blue carton"},
    {"title": "Pack bags", "description": "milk"},
]
checks = [
    ("exact_title", items, "Buy milk", [items[0]]),
    ("description_exclusion", items, "carton", []),
    ("substring_exclusion", items, "milk", []),
    ("no_match", items, "Missing", []),
    ("case_sensitive", items, "buy milk", []),
    ("duplicate_titles", [
        {"title": "X", "n": 1}, {"title": "Y"}, {"title": "X", "n": 2}
    ], "X", [{"title": "X", "n": 1}, {"title": "X", "n": 2}]),
    ("missing_title", [
        {"description": "A"}, {"title": "A"}
    ], "A", [{"title": "A"}]),
]
results = []
for check, values, query, expected in checks:
    try:
        actual = search(values, query)
        status = "PASS" if actual == expected else "ASSERTION_FAILURE"
    except BaseException:
        status = "CRASH"
    results.append({"id": check, "status": status})
print(json.dumps({"status":"OK","checks":results}, separators=(",",":")))
'''
MAX_WORKER_OUTPUT = 16384


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def checked_spec(raw: bytes) -> None:
    text = raw.decode("utf-8")
    parts = text.split("\n## ")
    if len(parts) != 2 or parts[1] != "R1\n\n" + RULE + "\n":
        raise ValueError("unsupported approved reference specification")
    if not text.startswith("# APPROVED BEHAVIORAL SPECIFICATION\n"):
        raise ValueError("not an approved spec")


def mutation_source(source: str, replacement: str) -> str:
    """Change the *candidate's* AST, not simply run unrelated broken fixtures."""
    tree = ast.parse(source)
    targets = [node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
               and node.name == "search"]
    if len(targets) != 1 or not isinstance(targets[0], ast.FunctionDef):
        raise ValueError("candidate must contain one top-level synchronous search function")
    patch = ast.parse("def placeholder(items, query):\n    " + replacement + "\n")
    targets[0].body = copy.deepcopy(patch.body[0].body)
    ast.fix_missing_locations(tree)
    mutated = ast.unparse(tree) + "\n"
    compile(mutated, "<mutation>", "exec")
    if mutated == source:
        raise ValueError("source mutation was no-op")
    return mutated


def acceptance(path: Path) -> list[dict[str, str]]:
    """Separate subprocess for every variant, bounded time and result shape."""
    try:
        result = subprocess.run(
            [sys.executable, "-I", "-B", "-c", TEST_SCRIPT, str(path)],
            cwd="/tmp", capture_output=True, text=True, timeout=6, check=False)
    except subprocess.TimeoutExpired as exc:
        raise ValueError("candidate timed out") from exc
    if len(result.stdout.encode("utf-8")) > MAX_WORKER_OUTPUT:
        raise ValueError("candidate output too large")
    try:
        doc = json.loads(result.stdout)
    except ValueError as exc:
        raise ValueError("candidate produced invalid test summary") from exc
    if result.returncode != 0 or doc.get("status") != "OK":
        raise ValueError("candidate crashed or interfered with test harness")
    rows = doc.get("checks")
    if (not isinstance(rows, list) or len(rows) != len(CHECKS) or
        any(not isinstance(row, dict) or set(row) != {"id", "status"} or row["id"] != name
            or row["status"] not in ("PASS", "ASSERTION_FAILURE", "CRASH")
            for row, name in zip(rows, CHECKS))):
        raise ValueError("candidate check results malformed")
    return rows


def main() -> int:
    try:
        spec = Path("/approved/SPEC.md").read_bytes()
        checked_spec(spec)
        source_raw = Path("/approved/search.py").read_bytes()
        if not source_raw or len(source_raw) > 16384:
            raise ValueError("source size invalid")
        source = source_raw.decode("utf-8")
        original = acceptance(Path("/approved/search.py"))
        mutants = []
        for name, expression in MUTANTS:
            changed = mutation_source(source, expression)
            digest = sha256(changed.encode("utf-8"))
            path = Path("/tmp") / (name + ".py")
            path.write_text(changed, encoding="utf-8")
            rows = acceptance(path)
            failed = next((row["id"] for row in rows if row["status"] == "ASSERTION_FAILURE"), None)
            status = ("KILLED_ASSERTION" if failed is not None and
                      all(row["status"] != "CRASH" for row in rows) else "SURVIVED_OR_CRASHED")
            mutants.append({"id": name, "status": status, "source_sha256": digest, "failed_check": failed})
        success = (
            all(row["status"] == "PASS" for row in original) and
            all(row["status"] == "KILLED_ASSERTION" for row in mutants) and
            len({row["source_sha256"] for row in mutants} | {sha256(source_raw)}) == 4
        )
        report = {
            "schema_version": 1, "kind": KIND,
            "stage_sha256": os.environ.get("PHICLEANROOM_STAGE_SHA", ""),
            "spec_sha256": sha256(spec), "source_sha256": sha256(source_raw),
            "suite": "reference-exact-title-acceptance-v1",
            "checks": original, "mutants": mutants,
            "status": "CHECKS_PASS_MUTANTS_KILLED" if success else "VERIFICATION_FAILED",
            "authority": "NONE",
        }
        print(json.dumps(report, sort_keys=True, separators=(",", ":")))
        return 0 if success else 3
    except (OSError, UnicodeError, ValueError, SyntaxError) as exc:
        print("REFERENCE_VERIFICATION_BLOCKED: " + str(exc)[:180], file=sys.stderr)
        return 4


if __name__ == "__main__":
    raise SystemExit(main())
