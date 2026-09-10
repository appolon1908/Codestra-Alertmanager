# Repository profile — Codestra Alertmanager

## Identity and authority

- Repository: `appolon1908-hue/Codestra-Alertmanager`
- Component ID: `alertmanager`
- Principal purpose: alert grouping, deduplication, inhibition, silencing and Middleware-only routing
- Non-goals: alert evaluation, direct provider delivery, business mutations and public native API access
- Accepted branch path: `feature/* -> development -> test -> staging -> production -> main`
- Configuration authority: `codestra/alertmanager.yml` plus its JSON policy and integration contracts

## Upstream and runtime

- Upstream project: `prometheus/alertmanager`
- Reviewed source snapshot: `CODESTRA_UPSTREAM_LOCK.json`
- Accepted runtime: Alertmanager `v0.34.0`, tag commit `085f0ef7eb41da24cab8cd000f1345b6250f2edb`
- Runtime image: `quay.io/prometheus/alertmanager@sha256:690c7b525f4367aa91f73e2f91c632206d32e97c6384bdbf2fb7a861b420340d`
- Artifact model: verified upstream image plus signed Codestra configuration artifact (Model B)

The upstream image has no discoverable Sigstore signature. This is recorded fail-closed; the exact digest is scanned, and the Codestra configuration artifact must be signed and verified before release readiness can pass.

## Operations

- Entrypoint: upstream `/bin/alertmanager` with `codestra/alertmanager.yml`
- Health: `GET /-/healthy`
- Readiness: `GET /-/ready`
- Dependencies: Prometheus, private storage and the authenticated Middleware webhook boundary
- Consumers: Grafana and governed operators
- Secret files: `middleware-alert-webhook-url`, `middleware-alert-webhook-token`
- Exposure: private service; native port 9093 is never public
- Persistence: Alertmanager state/silence data only; configuration is restored from the signed bundle
- Release: exact upstream digest plus signed immutable configuration artifact
- Rollback: previous verified runtime digest, configuration artifact digest and checksum; never a mutable tag

## Current verdict

`SOURCE_PREPARED_NOT_DEPLOYED`. Repository readiness remains blocked until a protected production merge publishes and verifies the signed configuration artifact and a real previous rollback artifact exists. This source profile does not claim production activation.
