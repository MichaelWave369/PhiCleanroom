"""Disposable container-side isolation probe. No code builder and no host writes."""
import hashlib
import json
import socket
from pathlib import Path


def network_available() -> bool:
    try:
        with socket.create_connection(("1.1.1.1", 53), timeout=1.5):
            return True
    except OSError:
        return False


def root_writable() -> bool:
    try:
        Path("/phicleanroom-root-write-probe").write_text("FAIL")
        return True
    except OSError:
        return False


def main() -> int:
    spec = Path("/approved/SPEC.md").read_bytes()
    visible = any(Path(path).exists() for path in (
        "/investigator", "/original", "/host", "/var/run/docker.sock",
    ))
    network = network_available()
    writable = root_writable()
    passed = not (visible or network or writable)
    print(json.dumps({
        "kind": "PHICLEANROOM_ISOLATION_PROBE_V1",
        "spec_sha256": hashlib.sha256(spec).hexdigest(),
        "network_reachable": network,
        "forbidden_paths_visible": visible,
        "root_writable": writable,
        "status": "PASS" if passed else "FAIL",
    }, sort_keys=True))
    return 0 if passed else 3


if __name__ == "__main__":
    raise SystemExit(main())
