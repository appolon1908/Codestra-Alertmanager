#!/usr/bin/env python3
"""Repair only mounted receiver-file ownership; dry run unless --apply.

Run by the host's authorized administrator. Uses host filesystem permissions,
never a privileged container. Keeps secret values out of stdout and Git.
"""
import argparse
import json
import os
from pathlib import Path
import stat
import subprocess

from verify_receiver_access import references, verify


def plan(container):
    if container.get("Config", {}).get("User") not in {"nobody", "65534", "65534:65534"}:
        raise ValueError("review_runtime_uid_gid_before_repair")
    destinations = references(container)
    if not destinations:
        raise ValueError("receiver_mounts_missing")
    changes = []
    for mount in container["Mounts"]:
        if mount.get("Destination") not in destinations:
            continue
        if mount.get("Type") != "bind" or mount.get("RW") is not False:
            raise ValueError("readonly_bind_mount_required")
        source = Path(mount["Source"])
        # Exact normalized protected host path; refuse aliases and symlinks.
        if not source.is_absolute() or source.resolve() != source or not str(source).startswith("/etc/codestra/secrets/monitoring/"):
            raise ValueError("protected_receiver_path_required")
        metadata = source.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_size == 0:
            raise ValueError("nonempty_regular_receiver_file_required")
        if metadata.st_uid != 0:
            raise ValueError("root_owned_receiver_file_required")
        changes.append({"path": str(source), "before_uid": metadata.st_uid,
                        "before_gid": metadata.st_gid,
                        "before_mode": oct(stat.S_IMODE(metadata.st_mode)),
                        "after_uid": 0, "after_gid": 65534, "after_mode": "0o440"})
    return changes


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--container", required=True)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    try:
        container = json.loads(subprocess.check_output(
            ["docker", "inspect", "--", args.container], stderr=subprocess.DEVNULL, timeout=10))[0]
        changes = plan(container)  # Validate the whole fixed batch before writing.
        if args.apply:
            if os.geteuid() != 0:
                raise ValueError("authorized_host_administrator_required")
            security = json.loads(subprocess.check_output(
                ["docker", "info", "--format", "{{json .SecurityOptions}}"],
                stderr=subprocess.DEVNULL, timeout=10)) or []
            if any("userns" in option or "rootless" in option for option in security):
                raise ValueError("review_host_identity_mapping_before_repair")
            for flag in ("-u", "-g"):
                identity = subprocess.check_output(
                    ["docker", "exec", container["Id"], "id", flag],
                    stderr=subprocess.DEVNULL, timeout=10).strip()
                if identity != b"65534":
                    raise ValueError("runtime_identity_mismatch")
            for change in changes:
                # O_NOFOLLOW also closes the final-component symlink race.
                fd = os.open(change["path"], os.O_RDONLY | os.O_NOFOLLOW)
                try:
                    metadata = os.fstat(fd)
                    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_nlink != 1:
                        raise ValueError("receiver_file_changed_since_plan")
                    os.fchown(fd, 0, 65534)
                    os.fchmod(fd, 0o440)
                finally:
                    os.close(fd)
        print(json.dumps({"applied": args.apply, "changes": changes}, sort_keys=True))
        if args.apply:
            report = verify(container)
            print(json.dumps(report, sort_keys=True))
            return 0 if report["ready"] else 1
        return 0
    except (OSError, subprocess.SubprocessError, ValueError, KeyError, IndexError):
        print(json.dumps({"ready": False, "error": "receiver_mode_repair_blocked"}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
