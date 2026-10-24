# Security policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately (a security advisory on the repository, or an email to the maintainers
listed in the repository settings) rather than opening a public issue. Include the version, configuration (proxy / tunnel /
LAN mode) and reproduction steps. You will get an acknowledgement within a few days.

## Trust model in one paragraph

RepoCuck republishes third-party `.deb` files **under your signing key**. Anything an Admin approves is installed as root on
every client that trusts the repository. The controls (approval gate, quarantine inspection, reserved-name/epoch policy,
optional release holdback, apt pin, digest verification, audit log) reduce risk; they do not make an untrusted upstream safe.
Only approve repositories whose maintainers you would trust with root on your machines.

## Hardening defaults

* Container: non-root (UID 1654), read-only root filesystem, no capabilities, `no-new-privileges`.
* The app listens on plain HTTP and expects a TLS-terminating proxy or tunnel; forwarded headers are honoured only from
  `Security__TrustedProxies`. Do not publish the app port directly.
* Session cookies are `HttpOnly`, `SameSite=Lax` and `__Host-`/`Secure` whenever `Security__PublicScheme=https`.
* All state-changing requests require an antiforgery token (forms) or `X-Repocuck-CSRF` plus a same-origin check (API).
* Secrets (signing passphrase, DB password, OIDC client secrets, TOTP secrets) never appear in logs or API responses.
  OIDC client secrets and TOTP secrets are encrypted with ASP.NET Data Protection; the keys live in `/data/dpkeys`.

## Known limits

* The `audit_log` is append-only through a database trigger, but the application's database role also owns the schema
  (migrations run in-process). Use PostgreSQL role separation if you need tamper-resistance against a compromised app.
* OIDC discovery is fetched from the Admin-supplied authority, including private addresses (home labs run IdPs on the LAN).
* Backups contain the signing key and encryption keys. Encrypt them.
