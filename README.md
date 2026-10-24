# RepoCuck

Turn a curated list of GitHub repositories into **one signed APT repository**.

RepoCuck watches GitHub releases, pulls out installable `.deb` assets for the architectures
you select, and publishes a proper Debian repository (`InRelease`, `Packages`, immutable
pool) that `apt-get` can use directly.

- Shared, transparent watch list: everyone sees every watched repository
- Two roles: **Admin** (owns the list) and **Member** (requests additions and architectures)
- Local accounts **or** OIDC/OAuth2 with IdP group → role mapping
- Per-repository architecture selection (`amd64`, `arm64`, `armhf`, …)
- Quarantine-before-approval, package policy checks, one published variant per package identity
- Signed APT metadata, digest-verified upstream assets, hardened container
- Plain-HTTP origin for use behind a reverse proxy or **Cloudflare Tunnel** (LAN-only HTTP mode for homelabs)
- .NET 10 + PostgreSQL, shipped as a single Docker image

## Documentation

| Document | Purpose |
| --- | --- |
| [`docs/PLAN.md`](docs/PLAN.md) | Product plan: goals, roles, requirements, architecture, milestones, risks |
| [`docs/IMPLEMENTATION_SPEC.md`](docs/IMPLEMENTATION_SPEC.md) | Buildable specification: schema, ingestion, APT generation, auth, API, security, tests (+ implementation status) |
| [`docs/OPERATIONS.md`](docs/OPERATIONS.md) | Deploying (Cloudflare Tunnel / Caddy / LAN), configuration, SSO, backups, key rotation, monitoring, runbooks |
| [`SECURITY.md`](SECURITY.md) | Trust model, hardening defaults, reporting |

## Status

RepoCuck 1.0 is implemented: .NET 10 + PostgreSQL, shipped as one Docker image, with unit, integration and end-to-end tests
(including a real Debian `apt` client and a backup/restore drill). See [`docs/OPERATIONS.md`](docs/OPERATIONS.md) to run it and
the *Implementation status* appendix of the spec for the (few) deviations.

## At a glance

```
Member request ─▶ Admin approval ─▶ GitHub releases ─▶ ingest/verify ─▶ pooled .deb blobs
                                                                          │
                                                                    index + sign
                                                                          ▼
                                                        /apt  (stable | testing, main)
                                                                          │
                                                                       apt-get
```

Quick start:

```bash
cd deploy && cp .env.example .env            # edit: DB_PASSWORD, REPOCUCK_BASE_URL, CLOUDFLARE_TUNNEL_TOKEN
mkdir -p secrets && openssl rand -base64 24 > secrets/admin_password && openssl rand -base64 32 > secrets/gpg_passphrase
docker compose up -d                          # app + PostgreSQL + cloudflared (or: -f docker-compose.caddy.yml,
                                              # or `up -d app db` behind your own proxy: see docs/OPERATIONS.md)
```

Then sign in as `admin`, request/approve a repository, and on clients follow the commands on `https://<host>/apt/`
(full client guide with deb822 format, pinning, Ansible and troubleshooting: [`docs/OPERATIONS.md`](docs/OPERATIONS.md#adding-the-repository-to-a-client-debian--ubuntu)):

```bash
sudo install -d -m 0755 /etc/apt/keyrings
curl -fsSL https://apt.example.com/apt/repocuck.gpg | sudo tee /etc/apt/keyrings/repocuck.gpg >/dev/null
echo "deb [signed-by=/etc/apt/keyrings/repocuck.gpg] https://apt.example.com/apt stable main" | sudo tee /etc/apt/sources.list.d/repocuck.list
sudo apt-get update
```

## Development

```bash
dotnet build -warnaserror
dotnet test tests/RepoCuck.UnitTests
dotnet test tests/RepoCuck.IntegrationTests       # needs Docker (Testcontainers) plus gpg/gpgv on the host
tests/e2e/run_e2e.sh                              # builds the image, runs the full stack + a real apt client
python3 tests/e2e/restore_drill.py                # backup -> destroy -> restore -> old client still works
```

## Repository layout

```
src/RepoCuck.Domain          entities, Debian versioning, policies
src/RepoCuck.Application     use cases and ports
src/RepoCuck.Infrastructure  EF Core, GitHub, storage, signing
src/RepoCuck.Debian          .deb parsing and APT index writing
src/RepoCuck.Web             UI, API, auth, /apt endpoints, workers
tests/                       unit, integration, E2E, load
deploy/                      Dockerfile, compose (cloudflared / Caddy), Caddyfile, backup/restore scripts
docs/                        plan and implementation spec
```
