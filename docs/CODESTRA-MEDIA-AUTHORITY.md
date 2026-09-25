# Codestra Alertmanager Authority

Principal repository: `ingtrader21-spec/Codestra-Alertmanager`
Canonical service host: `aler.codestra.media`
Canonical DNS target: `37.27.128.39`

Use no alternate authoritative hostname.

## Ownership
Own Alertmanager routing, grouping, inhibition, silencing policy, receiver templates, escalation config, validation and upgrade runbooks. Do not own Prometheus alert rules, Grafana dashboards, provider credentials, Caddy or application logic.

## Exposure
Private/internal only. DNS may exist; do not expose the Alertmanager service port publicly.

## Integration
Upstream: Prometheus alerts. Downstream: approved notification receivers and Grafana/operator views.

## Branch policy
Persistent: `main`, `development`, `test`, `staging`, `production`. Temporary: `feature/*`, `fix/*`, `upgrade/*`, `security/*`, `docs/*`, `hotfix/*`, optional `release/*`, `rollback/*`. Promotion: work -> development -> test -> staging -> production -> main.
