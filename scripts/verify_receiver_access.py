#!/usr/bin/env python3
"""Check receiver mounts and configured file references without reading secrets."""
import argparse
import json
from pathlib import Path, PurePosixPath
import subprocess

PREFIXES = ("/run/secrets/alertmanager_", "/run/secrets/middleware-alert-")
FILE_KEYS = {"url_file", "credentials_file", "bearer_token_file",
             "password_file", "ca_file", "cert_file", "key_file"}


def references(container):
    return sorted({mount["Destination"] for mount in container.get("Mounts", [])
                   if mount.get("Destination", "").startswith(PREFIXES)})


def configured_references(config):
    """Include authentication and TLS files even when their mounts are absent."""
    if not isinstance(config, dict) or not isinstance(config.get("receivers"), list) or not config["receivers"]:
        raise ValueError("receiver_configuration_required")
    found = set()

    def visit(value):
        if isinstance(value, dict):
            for key, item in value.items():
                if key in FILE_KEYS:
                    if not isinstance(item, str) or not item.startswith("/run/secrets/"):
                        raise ValueError("protected_secret_file_reference_required")
                    path = PurePosixPath(item)
                    if ".." in path.parts or str(path) != item:
                        raise ValueError("normalized_secret_file_reference_required")
                    found.add(item)
                elif isinstance(item, (dict, list)):
                    visit(item)
        elif isinstance(value, list):
            for item in value:
                visit(item)

    visit(config["receivers"])
    if not found:
        raise ValueError("receiver_file_references_missing")
    return sorted(found)


def verify(container, run=subprocess.run, config=None):
    identity = str(container.get("Config", {}).get("User") or "")
    if identity.split(":")[0] in {"", "0", "root"}:
        return {"ready": False, "error": "non_root_runtime_identity_required"}
    mounted = references(container)
    required = configured_references(config) if config is not None else []
    paths = sorted(set(mounted) | set(required))
    if not paths:
        return {"ready": False, "error": "receiver_mounts_missing"}
    destinations = {m.get("Destination"): m for m in container.get("Mounts", [])}
    results = []
    for path in paths:
        mount = destinations.get(path)
        # A configured credential must be a read-only mounted file, never an
        # accidentally baked image secret or a mutable writable mount.
        valid_mount = mount is not None and (
            path not in required or mount.get("RW") is False)
        readable = valid_mount and run(
            ["docker", "exec", container["Id"], "test", "-r", path],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=10, check=False).returncode == 0
        nonempty = valid_mount and run(
            ["docker", "exec", container["Id"], "test", "-s", path],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=10, check=False).returncode == 0
        results.append({"path": path, "mounted": mount is not None,
                        "readonly_mount": mount is not None and mount.get("RW") is False,
                        "readable": bool(readable), "nonempty": bool(nonempty)})
    return {"ready": all(x["readable"] and x["nonempty"] for x in results),
            "runtime_user": identity, "files": results,
            "configuration_references_verified": config is not None,
            "notification_delivery_verified": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--container", required=True)
    parser.add_argument("--config", type=Path,
                        help="Host copy of the effective Alertmanager YAML; required for complete reference verification")
    args = parser.parse_args()
    try:
        raw = subprocess.check_output(["docker", "inspect", "--", args.container],
                                      stderr=subprocess.DEVNULL, timeout=10)
        config = None
        if args.config is not None:
            import yaml
            config = yaml.safe_load(args.config.read_text(encoding="utf-8"))
            configured_references(config)  # Reject empty/malformed YAML too.
        report = verify(json.loads(raw)[0], config=config)
    except (OSError, subprocess.SubprocessError, ValueError, KeyError, IndexError, ImportError):
        report = {"ready": False, "error": "runtime_access_check_failed"}
    except Exception:
        # YAML parser errors can contain source text; never echo it.
        report = {"ready": False, "error": "receiver_configuration_invalid"}
    print(json.dumps(report, sort_keys=True))
    return 0 if report["ready"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
