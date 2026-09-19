# Middleware V3 incident ingress (Lane E preparation)

Status: **PREPARED_DISABLED**. `MIDDLEWARE_PREP_BASE=22d023a9c65b0789a0f7ee6c28548753521a9eff`,
`V3_FINAL_SHA=PENDING`. Alertmanager routes and groups; Middleware owns incident state.

## Contract (`codestra/contracts/middleware-v3-incident-ingress.v1.json`)

Path: Prometheus -> Alertmanager -> `POST /v1/integrations/alertmanager/events`.

| Concern | Rule |
| --- | --- |
| Authentication | Bearer JWT, issuer `https://auth.codestra.co/realms/codestra`, audience `middleware-api`, client `alertmanager`, scope `alerts.write` (status reads `alerts.read`), lifetime <= 300 s, token from `/run/secrets/middleware-alert-webhook-token` (OpenBao reference) |
| Bounded body | `Content-Type: application/json` exact; Content-Length and streamed body bounded by the Middleware policy; native webhook <= 100 alerts; receiver `max_alerts: 100`, `timeout: 10s` |
| Idempotency | `Idempotency-Key` (8..180 chars); request identity = sha256(client, key, fingerprint); exact replay -> 200 |
| Fingerprint dedupe | incident id = uuid5(tenant, fingerprint) -> **ONE_ALERT_FINGERPRINT_ONE_INCIDENT = PASS**; every repeat_interval re-send is `result=duplicate`, never a new incident |
| Safe retry | retry only on 503 / network errors with the same key; never on 400, 403, 409 |
| Correlation | `X-Correlation-ID` required (1..180), carried into the incident timeline; `X-Source-Deployment` and `X-Tenant-ID=codestra-platform` required |
| Lifecycle | OPEN=firing, ACK=acknowledged (operator), RESOLVED=resolved, SUPPRESSED=inhibited/silenced (status-events snapshot); transitions are Middleware-only |

Alertmanager never delivers e-mail, SMS, voice, Odoo, n8n or provider writes, never executes
commands and never resolves secrets; every receiver is a webhook to the file-provided
Middleware URL with the file-provided bearer.

## Proofs

* `scripts/validate_middleware_v3_incident_ingress.py` (in
  `validate-codestra-alertmanager.yml`): contract dark and pinned; every receiver speaks the
  contract; identity rules replayed over duplicate deliveries yield one incident per fingerprint.
* `tests/test_middleware_v3_incident_ingress.py` (discovered by the readiness workflow):
  24 firing re-sends + a network retry + resolve/re-fire = one incident identity.

## After `V3_FINAL_SHA`

Re-pin `middleware.v3_final_sha`, confirm the ingress path (or its `/platform/v1` successor)
keeps the same headers, bounds and identity rules, and rerun both proofs. The
`MiddlewareV3*` alerts prepared in Codestra-Prometheus route through the existing severity
receivers unchanged.
