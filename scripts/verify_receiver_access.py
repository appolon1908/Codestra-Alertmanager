#!/usr/bin/env python3
"""Check mounted receiver files as the existing Alertmanager identity.

Only test(1) is executed in the container: secret contents are never read out,
and no alternate user, extra group or privilege is requested.
"""
import argparse
import json
import subprocess


PREFIXES = ("/run/secrets/alertmanager_", "/run/secrets/middleware-alert-")


def references(container):
    return sorted({mount["Destination"] for mount in container.get("Mounts", [])
                   if mount.get("Destination", "").startswith(PREFIXES)})


def verify(container, run=subprocess.run):
    identity = str(container.get("Config", {}).get("User") or "")
    if identity.split(":")[0] in {"", "0", "root"}:
        return {"ready": False, "error": "non_root_runtime_identity_required"}
    paths = references(container)
    if not paths:
        return {"ready": False, "error": "receiver_mounts_missing"}
    results = []
    for path in paths:
        readable = run(["docker", "exec", container["Id"], "test", "-r", path],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       timeout=10, check=False).returncode == 0
        nonempty = run(["docker", "exec", container["Id"], "test", "-s", path],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       timeout=10, check=False).returncode == 0
        results.append({"path": path, "readable": readable, "nonempty": nonempty})
    return {"ready": all(x["readable"] and x["nonempty"] for x in results),
            "runtime_user": identity, "files": results,
            "notification_delivery_verified": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--container", required=True)
    args = parser.parse_args()
    try:
        raw = subprocess.check_output(["docker", "inspect", "--", args.container],
                                      stderr=subprocess.DEVNULL, timeout=10)
        report = verify(json.loads(raw)[0])
    except (OSError, subprocess.SubprocessError, ValueError, KeyError, IndexError):
        report = {"ready": False, "error": "runtime_access_check_failed"}
    print(json.dumps(report, sort_keys=True))
    return 0 if report["ready"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
