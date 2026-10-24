# RepoCuck — Operations guide

This guide covers running RepoCuck 1.0. The design is in [`PLAN.md`](PLAN.md) and [`IMPLEMENTATION_SPEC.md`](IMPLEMENTATION_SPEC.md);
the places where the implementation differs from the spec are listed in the spec's *Implementation status* appendix.

## 1. Deploying

### Cloudflare Tunnel (reference)

```bash
cd deploy
cp .env.example .env                     # DB_PASSWORD, REPOCUCK_BASE_URL, CLOUDFLARE_TUNNEL_TOKEN, optional GITHUB_TOKEN
mkdir -p secrets
openssl rand -base64 24 > secrets/admin_password     # initial admin password (must be changed at first login)
openssl rand -base64 32 > secrets/gpg_passphrase     # protects the generated repository signing key
docker compose up -d
```

In the Cloudflare dashboard (Zero Trust → Networks → Tunnels) add a public hostname for the tunnel pointing at `http://app:8080`.
The compose file sets `Security__ClientIpHeader=CF-Connecting-IP` and trusts the compose network as the proxy; without both,
every client appears to come from the `cloudflared` container and rate limits/lockouts collapse into one bucket.

Cloudflare notes:

* **Caching.** `.deb` files are not cached by default. Add cache rules for `/apt/pool/*` and `/apt/dists/*/by-hash/*`
  (eligible for cache, long edge TTL; the content is immutable). Bypass the cache for `/apt/dists/*/InRelease`, `Release`,
  `Release.gpg` and `Packages*`, and for everything outside `/apt/`.
* **Compression / ETags.** Cloudflare may recompress text and weaken ETags. apt tolerates both.
* **Terms of service.** Cloudflare's self-serve terms restrict serving large amounts of non-HTML content through the proxy.
  Check them for your plan before publishing a large pool this way, or use Caddy / LAN mode instead.
* **Cloudflare Access.** You can protect the UI and API with Access, but add a *bypass* policy for `/apt/*`: apt cannot do
  browser SSO.

### Caddy (automatic HTTPS)

`docker compose -f docker-compose.caddy.yml up -d`, after editing `Caddyfile` with your hostname. Uses `X-Forwarded-For`.

### LAN only, plain HTTP

Set `Security__PublicScheme=http` and `REPOCUCK__BASE_URL=http://host:8080`, publish port 8080, and drop the TLS front. Cookies are
not `Secure`, there is no HSTS and a warning is logged at startup. apt traffic is still verified (signed metadata); logins are not
protected, so only do this on a trusted network.

### First run

If `Bootstrap__AdminUsername` and `Bootstrap__AdminPasswordFile` are set the first admin is created with a forced password
change. Otherwise a one-time token is printed to the container's stdout (not the structured log); open `/setup` within 30 minutes.

## 2. Configuration reference

Environment variables use `__` as the section separator. Security-sensitive keys are environment/file only.

| Variable | Default | Notes |
| --- | --- | --- |
| `ConnectionStrings__Postgres` | — | required |
| `REPOCUCK__BASE_URL` | — | required in Production; its scheme must equal `Security__PublicScheme` |
| `REPOCUCK__ROLE` | `all` | `web`/`worker` split is experimental (needs a shared `/data`) |
| `REPOCUCK__MIGRATE` | `apply` | `none` + `docker run … --migrate` for init-container style migrations |
| `Security__PublicScheme` | `https` | `https` or `http` (LAN mode) |
| `Security__TrustedProxies` | empty | CIDRs allowed to set forwarded headers; required for `https` unless `Security__AssumeTlsFront=true` |
| `Security__ClientIpHeader` | `X-Forwarded-For` | `CF-Connecting-IP` behind Cloudflare |
| `Security__HstsMaxAgeDays` | `365` | HTTPS only |
| `Security__TrustedHosts` | from `BASE_URL` | extra allowed `Host` values, comma separated |
| `Auth__LocalEnabled` | `true` | refuse to disable the last way for an admin to sign in |
| `Auth__SessionIdleMinutes` / `Auth__SessionAbsoluteHours` | `60` / `12` | |
| `Auth__MaxFailedAttempts` / `Auth__LockoutMinutes` | `5` / `15` | per (username, IP) |
| `Auth__AllowInsecureOidc` | `false` | tests only: allow `http://` authorities |
| `Limits__PendingRequestsPerUser` / `Limits__RequestsPerHour` | `10` / `20` | |
| `Limits__LoginAttemptsPer5MinutesPerIp` | `10` | |
| `Limits__AptRequestsPerMinutePerIp` | `600` | raise for large shared egress IPs |
| `Requests__ProposedExpiryDays` | `30` | stale `proposed` repositories are rejected as expired |
| `Policy__AllowEpoch` | `false` | epoch ≥ 1 quarantines a package |
| `Policy__ReservedNames` | built-in list | comma-separated additions; also editable in the UI |
| `Apt__PathPrefix` | `/apt` | |
| `Apt__SigningKeyPath` | `/data/keys/repo-signing.key` | if absent a key is generated into `/data/gnupg` |
| `Apt__SigningKeyPassphraseFile` | — | recommended; `Apt__SigningKeyPassphrase` also works |
| `Apt__KeyFingerprint` | — | pin: refuse to start if the key differs |
| `Apt__PublicHost` | from `BASE_URL` | host shown in client snippets |
| `Apt__Architectures` | `amd64,arm64,armhf,i386,riscv64` | initial allow-list; editable in the UI afterwards |
| `Apt__EnableTesting` | `false` | enables the `testing` suite (stable + prereleases, `NotAutomatic`) |
| `Apt__InitialBackfillReleases` / `Apt__ProposedBackfillReleases` | `20` / `3` | |
| `GitHub__Token` | — | optional; 60 → 5000 requests/hour |
| `GitHub__MaxAssetBytes` | `2147483648` | per asset |
| `GitHub__WebhookSecret` | — | enables `POST /webhooks/github` (release events) |
| `GitHub__AllowInsecureForTesting` | `false` | tests only |
| `Jobs__WorkerConcurrency` | `4` | |
| `Retention__VersionsPerPackage` | `3` | per package/architecture/channel |
| `Retention__OrphanGraceDays` | `30` | removed repositories stay published this long |
| `Retention__BlobGraceHours` / `Retention__GenerationHours` / `Retention__GenerationCount` | `24` / `48` / `5` | a generation is deleted only beyond **both** the age and the count |
| `Bootstrap__AdminUsername` / `Bootstrap__AdminPasswordFile` | — | first-run admin |
| `Storage__Root` | `/data` | blobs, keys, data-protection keys, temp |
| `Metrics__Token` | — | bearer token for `/metrics`; without it only loopback (no forwarded header) may read it |
| `Logging__Format` | JSON | set to `simple` for human-readable logs |

## 3. Everyday use

* **Members** browse all repositories and file *requests* (new repository, or extra architectures for an existing one).
* **Admins** review `Approvals`. For a new repository the quarantine inspection has already fetched the latest releases, so the
  page shows what packages were found and which were flagged. Approve (adjusting architectures) or reject with a reason.
* Flagged packages (reserved distro names — including via `Provides`/`Replaces`/`Conflicts` — or epochs) sit in **Quarantine**
  until an Admin releases them. Identity conflicts between forks appear under **Conflicts**; the first source wins until you set a
  repository's priority and press *Re-arbitrate*.
* Clients: the landing page at `/apt/` gives the exact commands, including the recommended pin
  (`Pin-Priority: 400`, so a RepoCuck package never silently replaces a distribution package of the same name).

## 4. Single sign-on

Admin → SSO. Register `https://<host>/signin-oidc/<slug>` as the redirect URI (and `…/signout-callback-oidc/<slug>` for logout) at
the provider; use the authorization-code flow with PKCE. Typical settings:

| Provider | Authority | Group claim |
| --- | --- | --- |
| Keycloak | `https://kc.example.com/realms/<realm>` | add a *Group Membership* mapper named `groups` (full path off) |
| Authentik | `https://auth.example.com/application/o/<slug>/` | the `groups` claim is in the `profile` scope |
| Entra ID | `https://login.microsoftonline.com/<tenant>/v2.0` | enable *groups* optional claim; values are group object IDs |

Map group values to `admin`/`member` (admin wins; unmapped users are members). Roles are re-evaluated at every sign-in; an admin
who pins a user's role (editing it in Users) is not overwritten, and the IdP can never demote the last admin. Use **Test** on the
provider to check discovery and the JWKS. Local login stays available as the break-glass path.

## 5. Backup and restore

```bash
deploy/backup.sh /srv/backups            # writes db-<stamp>.dump and data-<stamp>.tgz (mode 0600)
deploy/restore.sh db-<stamp>.dump data-<stamp>.tgz
```

The data archive contains the **signing key and encryption keys**: encrypt it (age, gpg, restic …) before storing it elsewhere.
The restore drill (`tests/e2e/restore_drill.py`) destroys all volumes, restores, and checks that a client holding the *old*
keyring still runs `apt-get update && apt-get install`. Targets: RTO 2 h, RPO = backup interval.

## 6. Signing key

* A key is generated on first start (Ed25519, 10-year expiry) unless `Apt__SigningKeyPath` points at one to import.
* **Rotation** (Admin → Key): *Start* generates a new key and signs with both; `repocuck.gpg` now contains both. Wait at least
  7 days for clients to refresh `/etc/apt/keyrings/repocuck.gpg`, then *Complete* to drop the old key. Clients that still only
  trust the old key keep working during the overlap because apt accepts a file with at least one good signature.
* The metric `repocuck_signing_key_expiry_seconds` lets you alert well before expiry.

## 7. Monitoring

`GET /metrics` (Prometheus text) exposes `repocuck_sync_total{result}`, `repocuck_sync_duration_seconds_{sum,count}`,
`repocuck_assets_ingested_total{result}`, `repocuck_index_generation_total{suite,result}`, `repocuck_index_generation_seconds_*`,
`repocuck_index_age_seconds{suite}`, `repocuck_jobs_queue_depth{state}`, `repocuck_package_variants{state}`,
`repocuck_requests_pending{kind}`, `repocuck_apt_requests_total{kind,status}`, `repocuck_blob_bytes`,
`repocuck_signing_key_expiry_seconds`. Example rules:

```yaml
- alert: RepoCuckReleaseStale      # heartbeat should refresh daily; Valid-Until is 7 days
  expr: repocuck_index_age_seconds > 5 * 86400
- alert: RepoCuckPublishFailing
  expr: increase(repocuck_index_generation_total{result="failed"}[1h]) >= 3
- alert: RepoCuckSigningKeyExpiring
  expr: repocuck_signing_key_expiry_seconds < 60 * 86400
- alert: RepoCuckDeadJobs
  expr: repocuck_jobs_queue_depth{state="dead"} > 0
```

Logs are JSON on stdout with trace/span ids; `/healthz` and `/readyz` expose only `{"status":"ok"}`.

## 8. Runbooks

* **Recover an admin** (no UI access): `docker compose exec app dotnet RepoCuck.Web.dll admin list`, then
  `… admin reset --username <name>` (prints a temporary password, forces a change) or `… admin promote --username <name>`.
* **Force a reindex**: Admin → Queue → *Rebuild APT indices* (also what runs after key rotation).
* **Unpublish a package quickly**: Admin API `DELETE /api/v1/admin/variants/{id}` or quarantine it; blocking a repository removes all
  of its packages from the next generation.
* **Sync failing**: the repository page shows each run's outcome and failed assets; Admin → Queue shows retries and dead jobs.
  GitHub rate limits are honoured automatically; set `GitHub__Token` to raise the limit.
* **Behind a tunnel, everyone gets locked out together**: check `Security__ClientIpHeader` and `Security__TrustedProxies`.
* **Upgrade**: pull the new image and `docker compose up -d`; migrations apply under an advisory lock. Migrations are additive
  (expand/contract), so rolling back to the previous image is safe for one minor version.

## 9. Not implemented / limitations (1.0)

* No OpenTelemetry trace export (JSON logs carry trace ids; metrics via `/metrics`).
* Self-registration (`invite`/`open`) is not offered: Admins create local accounts, or users sign in through SSO.
* Filesystem blob storage only (no S3). The `web`/`worker` split is experimental.
* The password denylist is a small bundled list, not the top-10k list; there is no breached-password lookup.
* Private GitHub repositories, non-`.deb` assets and non-GitHub upstreams are out of scope.
