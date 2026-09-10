# Provider alert transport

Provider Prometheus needs a reachable authenticated core destination. Its reviewed
Klyrow/Telnexa overlay expects HTTPS 10.40.0.1:19093 with the TLS server identity
alertmanager.core.codestra.internal and a distinct client certificate per service.

The opt-in operations/core-private-transport overlay adds native mTLS to the
existing core Alertmanager using its current image, state volume and receivers.
It publishes only the core private address. It does not select an image or
replace a state volume. Native TLS changes the existing internal 9093 endpoint
too: migrate core Prometheus alerting, Alertmanager scrape jobs and every other
existing client in the same controlled cutover. Do not apply the overlay alone.

Provision dedicated short-lived server/client identities through the platform
PKI, with serverAuth/clientAuth EKUs and the correct server SAN. Trust a dedicated
observability client CA, not the entire platform client population. Keep each
private key on its host and preserve readable least-privilege ownership for the
container UID. Require server.crt, server.key, client-ca.crt, server-ca.crt,
probe.crt and probe.key in the root-controlled TLS directory; source Git contains
no certificates or credentials. Point the three required overlay environment
variables at absolute provisioned paths. Bind creation is disabled to detect
missing material. The probe performs an authenticated native configuration read.

Before cutover record the exact source SHA, current image, all effective mounts,
configuration hashes, live target count, current alert destinations and delivery
counters. Validate merged Compose without changing other services, validate the
native server/client configuration using the running image, prove a no-delivery
isolated mTLS handshake, and verify an encrypted off-host backup plus isolated
state restore. Recreate only the affected services with the existing state.
Require all original scrape targets up, both provider activeAlertmanagers lists
populated, certificate verification enabled, mTLS rejection without a client
certificate, and natural alert delivery without failure deltas. Roll back all
client/server configuration together if a gate fails.

## Native Middleware authentication

The principal six-receiver configuration is a separate release from the existing
legacy hash receiver. scripts/configure_native_middleware.py prepares a candidate
with OAuth2 client_credentials and the native webhook header accepted by
Middleware PR224. It preserves receiver routing, inhibition and batch limits.
It refuses unknown authentication, direct delivery and insecure token URLs.
The output must be a new file; it is never installed automatically.

Supply --token-url with the accepted HTTPS Keycloak realm token endpoint.
Provision these file references in the accepted release:
middleware-alert-webhook-url (canonical private incident API URL),
alertmanager-oidc-client-secret (alertmanager-service only),
alertmanager-source-deployment (the actual approved deployment identity),
middleware-alert-trust-bundle (issuer and Middleware trust chains), and
alertmanager-middleware-client-cert/key. The explicit tenant is codestra-platform
and scope is observability.alerts.write. Both token and webhook requests verify
TLS. Keycloak audience, tenant and client mappings remain mandatory.
Never substitute the old receiver bearer or a static Idempotency-Key.

Do not switch the legacy receivers until the protected Middleware source,
signed image, schema migrations, backup/restore, private ingress and Keycloak
identity are accepted. Start with delivery disabled and verify a durable incident,
replay deduplication and resolution. A legacy receiver 2xx or body-hash ledger
does not establish Middleware incident ingestion. These files are source
preparation and do not claim activation or release readiness.
