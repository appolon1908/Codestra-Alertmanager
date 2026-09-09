# Receiver access and alert delivery recovery

The September 9 inventory found the existing central instance on
65.109.65.169 (`codestra-monitoring-alertmanager-1`) running as `nobody` with
read-only receiver URL bind mounts. Its logs report permission denied reading
those files. All 20,565 observed webhook attempts were failures. Klyrow's local
Prometheus on 37.27.128.39 separately has no Alertmanager target, so its alerts
are absent centrally. This does not verify a migration to the canonical
`aler.codestra.media` deployment, whose reviewed contract uses mTLS.

## Existing runtime repair

Run `python3 scripts/verify_receiver_access.py --container
codestra-monitoring-alertmanager-1` on the central host. This only executes
`test -r` and `test -s` under the container's existing identity; it prints no
secret values and makes no changes. A passing access check is not delivery proof.

An authorized host administrator can run
`python3 scripts/repair_receiver_modes.py --container
codestra-monitoring-alertmanager-1` to preview the exact mounted-file changes.
It only accepts existing root-owned, nonempty, single-link regular files
under `/etc/codestra/secrets/monitoring/`, with read-only bind mounts and the
expected runtime identity. Review the recorded prior UID/GID/mode. Re-run with
`--apply` to retain root ownership and set group 65534, mode 0440. No restart,
receiver URL change, public port, or root container is required. Store the
sanitized plan with operational change evidence; it contains rollback metadata.

The script uses ordinary host permissions and refuses an apply by a non-root
host identity. SentinelX currently lacks that authorized host access. Do not
use privileged containers or Docker host mounts to circumvent it. If the
deployment uses user namespace remapping, another UID/GID, ACLs, or volume
secrets, this repair is not applicable: use that deployment's identity mapping.
The script's final in-container read-back must pass.

Update the accepted monitoring installer/secret projection with the same
root:65534/0440 contract; a root-only preflight or `amtool check-config` does
not establish runtime readability. The canonical deployment's external secret
UID/GID settings remain unchanged. Changes to routing configuration itself
remain owned by the signed Codestra configuration artifact.

## Delivery verification

After access is restored, read fresh successful/failed notification counter
deltas and correlate an existing alert fingerprint with the receiving
Middleware inbox and notification receipt. Do not clear alerts or claim that
20,565 historical failures vanish. Avoid an artificial notification to an
unverified destination. Repair Klyrow's private Prometheus-to-Alertmanager route
using its mTLS configuration overlay and verify both actual stalled-delivery
alerts centrally. Downstream receipt confirmation is still required.

To roll back file metadata, restore each reviewed prior UID/GID/mode on the
same mounted inode and repeat the access check. Restoring root-only modes will
reproduce the outage for a non-root process, so retain the successful access
contract through the next governed release.

No production files were modified or notifications sent in this review.
Evidence: `docs/evidence/provider-recovery-20260909.json`.
