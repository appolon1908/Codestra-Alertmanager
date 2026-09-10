# Backup, restore and rollback design

This is repository recovery design and disposable-test guidance. It is not evidence that production data has been backed up or restored.

## Scope and objectives

Alertmanager configuration is authoritative in the signed Codestra configuration artifact. Runtime state includes silences and notification log state in the mounted data directory. The target design is an encrypted, access-restricted off-host snapshot with a 24-hour RPO and a 2-hour RTO; the live values require later runtime certification.

Before a change, record the current protected source SHA, exact runtime image digest, configuration artifact digest, configuration checksum, volume identity and health/readiness results. Quiesce only the single Alertmanager replica being snapshotted, capture the mounted state consistently, calculate SHA-256, and copy the encrypted snapshot off-host. Never include webhook credentials or secret-file contents in evidence.

## Isolated restore verification

Restore the snapshot to a new disposable volume with no provider route. Start the exact recorded image and configuration digests on an isolated network. Require `/-/healthy`, `/-/ready`, configuration validation, expected silence-state inspection and a mock-only routing test. Destroy disposable credentials and state after the test.

## Rollback gate

Rollback requires an actually pullable previous image digest, a verified previous configuration artifact digest, its deterministic checksum and a compatibility statement. Apply configuration before the binary only when the previous binary accepts it; otherwise restore both as one reviewed unit. After rollback, require health, readiness, Prometheus connectivity and mock Middleware delivery. If state format is not backward compatible, use forward recovery instead of downgrading.

No current previous accepted release digest is asserted by this document. The release evidence must remain blocked until the registry proves one.
