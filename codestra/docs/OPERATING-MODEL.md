# Codestra Alert Routing Operating Model

## Mission

`Codestra-Alertmanager` is the alert-routing authority for the Codestra observability stack. It receives alert groups from Prometheus, applies grouping, deduplication, inhibition and silence policy, and forwards normalized alert notifications to Middleware. It is not a second communications platform.

Canonical host: `aler.codestra.media`.

The native service remains network-restricted even when DNS points at the shared edge address. Public DNS is not permission to expose Alertmanager's native port directly to the internet.

## Permanent effect boundary

```text
Prometheus
   |
   v
Alertmanager
   |
   | authenticated webhook only
   v
Middleware
   |
   +--> approved email/SMS/voice notification path
   +--> governed Odoo incident/ticket write when policy requires
   +--> governed n8n orchestration when policy requires
   +--> audit / incident timeline
```

Alertmanager must not directly deliver email, SMS, voice calls, Slack, PagerDuty, Odoo writes, n8n privileged writes, provider writes or business mutations.

## Severity model

| Severity | Meaning | Initial behavior |
|---|---|---|
| critical | Active outage, security control failure, data-integrity risk, financial/trading safety risk or multi-business platform failure | 10s group wait, 15m repeat, immediate Middleware escalation policy |
| high | Material degradation, failed dependency or incident likely to breach SLA | 30s group wait, 30m repeat |
| warning | Degradation needing owner attention but not immediate paging | 2m group wait, 2h repeat |
| informational | Operational state worth recording; normally no page | 5m group wait, 12h repeat |

Prometheus owns the alert rules that assign severity. Alertmanager owns how a valid alert is grouped and routed after it fires.

## Required alert metadata

Every routed alert must carry these labels:

- `alertname`
- `severity`
- `environment`
- `service`
- `codestra_business`
- `owner`

Every routed alert must carry these annotations:

- `summary`
- `description`
- `runbook_url`

Useful optional fields include `deployment_sha`, `region`, `server`, `container`, `dashboard_url`, `trace_id` and `correlation_id`. High-cardinality customer IDs, emails, phone numbers and request IDs must not become Prometheus/Alertmanager grouping labels.

## Grouping and storm protection

The default group key is:

```text
alertname + codestra_business + service + environment + severity
```

This keeps one failing service from creating one notification per instance while preserving business/environment ownership.

Storm protection is implemented through:

1. Prometheus rule design that avoids duplicate equivalent alerts.
2. Alertmanager grouping.
3. Alertmanager deduplication.
4. severity inhibition.
5. deployment-noise inhibition.
6. repeat intervals by severity.
7. Middleware durable notification deduplication and escalation state.

Alertmanager must never fan out directly to several external notification providers as a workaround for missing Middleware policy.

## Inhibition

- critical inhibits high/warning/informational variants for the same alert/business/service/environment.
- high inhibits warning/informational variants for the same alert/business/service/environment.
- warning inhibits informational variants for the same alert/business/service/environment.
- `CodestraDeploymentInProgress` may inhibit non-critical service noise for the same service/environment during a governed deployment.
- critical incidents are not suppressed by the deployment inhibition rule.

## Maintenance silences

Maintenance suppression uses Alertmanager silences, not permanent route edits.

Every operational silence must have:

- an owner/creator;
- an explicit matcher scope;
- a change, incident or maintenance reference in the comment;
- a start time;
- an expiry time.

Indefinite silences are forbidden. Broad silences over critical security or financial/trading safety alerts require explicit security/release approval outside Alertmanager.

## Incident IDs and acknowledgement

Alertmanager does not own the durable incident lifecycle. Middleware assigns `incident_id`, stores the incident timeline and owns acknowledgement/escalation state.

Target incident states are:

```text
detected -> notified -> acknowledged -> escalated -> mitigating -> resolved
                                        \-> reopened
```

Alertmanager's own alert state remains `firing`, `resolved` or `silenced`.

## Ticket and Odoo integration

When policy requires an incident/ticket record:

```text
Alertmanager -> Middleware -> Odoo adapter -> Odoo incident/ticket record
```

There is no direct Alertmanager-to-Odoo credential or write path.

## n8n integration

n8n can coordinate follow-up workflows, reminders, evidence collection or human approvals only after Middleware has accepted and normalized the incident. n8n must not become a direct notification/provider bypass.

## Supervisor escalation

Middleware owns the escalation matrix. The routing decision can use severity, business, service owner, environment, duration, recurrence and acknowledgement state. Alertmanager only sends the source alert group with the metadata needed for that decision.

## Dead-man monitoring

Prometheus should emit a continuously firing `CodestraWatchdog` informational alert. Alertmanager routes it to the Middleware heartbeat receiver every five minutes. Absence detection belongs to the downstream incident/monitoring logic because Alertmanager cannot alert on an event it did not receive.

## Recurring alert detection

Recurring-alert detection is not solved by Alertmanager deduplication alone. Middleware or an analytics rule should track alert fingerprint recurrence over time and open/escalate a problem record when configured thresholds are crossed.

## Deployment-related suppression

Deployment pipelines should emit the `CodestraDeploymentInProgress` signal with `service` and `environment`. Non-critical alerts for that service/environment can be inhibited during the deployment. Deployment completion must remove the signal promptly; failures must not suppress critical alerts.

## Secrets

Git contains only references to secret files:

- `/run/secrets/middleware-alert-webhook-url`
- `/run/secrets/middleware-alert-webhook-token`

The actual webhook URL and token must come from the deployment secret authority. They must not be committed to this repository.

## Runtime readiness gates

Source being merged does not mean the route is live. Before runtime activation, prove all of the following:

1. the Middleware alert ingestion endpoint exists and is authenticated;
2. the endpoint accepts the documented payload contract;
3. durable idempotency works across Alertmanager retries;
4. approved notification routing is configured in Middleware;
5. Odoo/n8n effects, if enabled, still pass through Middleware;
6. no direct external receiver exists in Alertmanager;
7. Prometheus alert labels/annotations satisfy the contract;
8. `aler.codestra.media` TLS/network policy is correct;
9. Alertmanager native service ports are not publicly exposed;
10. staging fire/resolve/dedup/inhibit/silence tests pass before production promotion.
