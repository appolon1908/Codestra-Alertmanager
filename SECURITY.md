# Security policy

Report vulnerabilities privately through GitHub Security Advisories for this repository. Do not include credentials, customer data or production evidence in an issue or pull request.

The Codestra overlay must preserve these controls:

- private Alertmanager native endpoints;
- secret-file credentials only;
- Middleware-only webhook receivers;
- no direct SMTP, provider or business-system integration;
- immutable runtime and configuration artifact identities;
- exact-head CI and independent review where branch policy requires it.

Production secrets, notification activation and runtime changes are outside repository pull requests. Security fixes must be committed, reviewed, tested and promoted through the accepted branch lineage.
