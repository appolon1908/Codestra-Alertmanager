# Existing core alert-routing repair

The provider monitoring audit found two independent problems: provider Prometheus
had no Alertmanager destination, and the existing core route tree sent production
warnings and Caddy alerts with missing metadata only to the rejected-route queue.

Use scripts/repair_core_routing.py to produce a new candidate from the effective
core YAML. It adds production warnings to the secondary operator queue, preserves
critical/recovery routing and credential files, separates business/severity groups,
and sends otherwise unclassified alerts to both quarantine and secondary review.
It never upgrades unknown alerts to primary paging or removes the audit path.
This compatibility repair does not claim the legacy receiver is the canonical
Middleware incident service; its durable ledger currently stores hashes only.

Before applying, preserve the exact source SHA, config checksum, image digest,
state-volume identity and encrypted off-host backup/restore evidence. Validate the
candidate with the running image's amtool, then execute native route tests for
production warning, critical/recovery, unknown severity, missing metadata, and
staging special routes. Preserve file ownership/mode. Recheck the live input hash
immediately before replacement, reload only Alertmanager, and require readiness,
configuration reload success and natural webhook success without failure deltas.
Rollback restores the original config and reloads the same binary.

Provider connectivity additionally requires a private authenticated destination,
valid client/server TLS identities and Prometheus-readable certificate mounts.
Never publish the unauthenticated legacy port 9093 on a public address. The
Middleware observability API must be deployed from its verified principal release
and tested for durable incident ingestion before claiming the full chain works.
