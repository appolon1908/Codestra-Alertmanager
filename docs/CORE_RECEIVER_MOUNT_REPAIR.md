# Existing core Alertmanager receiver mount repair

Observed on 2026-09-10 at 65.109.65.169. Prometheus successfully delivered alerts
to Alertmanager, but Alertmanager could not send authenticated webhooks because
the effective configuration referenced an absent
/run/secrets/alertmanager_receiver_bearer mount. The staging receiver URL was
also configured but absent from the container. Testing only existing mounts
previously missed both omissions.

The compatibility override adds these two existing protected files as read-only
bind mounts. It does not select an image, publish ports, alter routes, remove
authentication, configure provider delivery, or install the new Server B stack.
The existing runtime image and state volume must be preserved.

## Preflight and rollback

Record the exact container image ID/digest, Compose and configuration hashes,
container ID, private network addresses, and state-volume identity. Preserve a
protected copy of the original Compose file and file metadata. Confirm both
source files are nonempty regular root-owned files with no symlink or hardlink.
Verify the runtime UID/GID is 65534 and Docker is neither rootless nor remapped.
Apply the existing restricted file-mode policy (root:65534, 0440); never print
credential or receiver URL values. Record previous modes for rollback.

Validate the merged Compose configuration and effective Alertmanager
configuration with the current runtime's amtool. Only the two new mount targets
may differ; preserve image, ports, networks, command, hardening and state volume.
Apply only the Alertmanager service, without dependencies, pulls, builds,
migration or volume deletion. Use the host's deployment wrapper if required.

Quiesce Alertmanager before a consistent state snapshot when a restart is
required. Keep the snapshot protected and do not upload its contents as
evidence. Follow the repository's encrypted off-host backup and restore gate
before recreating the container. If that gate is unavailable, leave runtime
application blocked and retain the prepared override.

After the approved recreation, run:

```sh
python3 scripts/verify_receiver_access.py \
  --container codestra-monitoring-alertmanager-1 \
  --config /etc/codestra/monitoring/alertmanager.yml
```

Require every configured credential/URL reference to be mounted, read-only,
readable and nonempty under the existing non-root runtime identity. Verify
/-/ready and observe notification success/failure deltas for naturally firing
alerts. Scrape success alone does not prove webhook delivery, and webhook
success does not prove downstream email receipt.

If rollback is required, restore the previous Compose file, existing image and
state-volume binding, recreate only Alertmanager and restore recorded file
metadata. Do not overwrite secret values or erase silences/notification state.
The original missing-mount condition returns, so rollback is a service recovery
step, not a notification-delivery PASS.

## Provider server remains separate

37.27.128.39 still needs its accepted observability release artifacts and
private authenticated integration. Its Klyrow and Telnexa Prometheus instances
have no Alertmanager destination. This repair must not be reported as that
fourteen-component deployment.
