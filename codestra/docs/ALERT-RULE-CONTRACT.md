# Alert Rule Producer Contract

Alertmanager routes alerts; it does not decide what conditions should fire. Prometheus and each owning service must produce alerts that satisfy this contract.

## Required labels

```text
alertname
severity             # critical | high | warning | informational
environment          # development | test | staging | production
service              # stable low-cardinality service identifier
codestra_business    # stable business/application identifier
owner                # stable owning team identifier
```

Optional low-cardinality labels may include `region`, `cluster`, `server_role`, `dependency`, `channel` and `component` when they have bounded values.

Do not use customer IDs, tenant IDs, request IDs, correlation IDs, phone numbers, emails, message IDs or trace IDs as grouping labels. Those belong in annotations, structured logs or traces.

## Required annotations

```text
summary
description
runbook_url
```

Recommended annotations:

```text
dashboard_url
deployment_sha
correlation_id
trace_id
change_reference
```

## Reserved control alerts

### CodestraWatchdog

Continuously firing informational heartbeat used to prove the complete Prometheus -> Alertmanager -> Middleware path. It must not trigger user-facing communications.

### CodestraDeploymentInProgress

A bounded deployment signal carrying at least `service` and `environment`. It may inhibit non-critical noise for that service/environment. It must have an automatic end condition and must never suppress critical alerts.

## Required alert families

Each production service should eventually provide rules for:

- availability/readiness failure;
- elevated error rate;
- elevated latency;
- dependency failure;
- queue/backlog saturation where applicable;
- database/cache exhaustion where applicable;
- authentication/authorization anomaly where applicable;
- reconciliation/dead-letter backlog where applicable;
- certificate/TLS expiry where applicable;
- deployment health;
- SLO/error-budget burn where an SLO exists.

Business-specific rules stay in the owning Prometheus/application repositories. This document defines only the routing metadata contract.
