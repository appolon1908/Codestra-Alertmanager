# Codestra Alertmanager authority

This repository owns Codestra alert grouping, inhibition, silencing and routing. Prometheus is the alert evaluator. Alertmanager may hand validated webhook v4 payloads only to the governed Middleware endpoint; it contains no email, SMS or provider receiver.

The native listener on port 9093 is private. `aler.codestra.media`, if retained, is a restricted admin-plane name and is not authorization for public native API exposure. Merging source does not deploy Alertmanager or enable notifications.

## Validate

```sh
python3 scripts/validate_codestra_alertmanager.py
python3 scripts/test_stage6_alert_routing.py
python3 scripts/validate_repository_readiness.py
python3 -m unittest discover -s tests -p 'test_*.py'
```

CI additionally validates the configuration with the exact accepted Alertmanager image in `codestra/release/runtime-image.lock.json`.

## Release model

The repository uses Model B: the reviewed upstream Alertmanager image is pinned by digest, while Codestra configuration is packaged and signed as a separate immutable artifact. The release workflow remains disabled until it is merged through the accepted protected production lineage. Runtime secret values are mounted as files and never belong in Git or release evidence.

See [REPOSITORY_PROFILE.md](REPOSITORY_PROFILE.md), [codestra/docs/OPERATING-MODEL.md](codestra/docs/OPERATING-MODEL.md), and [docs/BACKUP_RESTORE_ROLLBACK.md](docs/BACKUP_RESTORE_ROLLBACK.md).
