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
| [`docs/IMPLEMENTATION_SPEC.md`](docs/IMPLEMENTATION_SPEC.md) | Buildable specification: schema, ingestion, APT generation, auth, API, security, tests |

## Status

Design phase (v1.1). No application code yet.

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

Quick start once implemented:

```bash
docker compose up -d      # app + postgres + cloudflared (or the Caddy variant)
# add/approve repos in the UI, then on clients:
sudo install -d -m 0755 /etc/apt/keyrings
curl -fsSL https://apt.example.com/apt/repocuck.gpg \
  | sudo tee /etc/apt/keyrings/repocuck.gpg >/dev/null
echo "deb [arch=amd64,arm64 signed-by=/etc/apt/keyrings/repocuck.gpg] \
https://apt.example.com/apt stable main" \
  | sudo tee /etc/apt/sources.list.d/repocuck.list
sudo apt-get update
```

## Repository layout (planned)

```
src/RepoCuck.Domain          entities, Debian versioning, policies
src/RepoCuck.Application     use cases and ports
src/RepoCuck.Infrastructure  EF Core, GitHub, storage, signing
src/RepoCuck.Debian          .deb parsing and APT index writing
src/RepoCuck.Web             UI, API, auth, /apt endpoints, workers
tests/                       unit, integration, E2E, load
deploy/                      Dockerfile, compose (cloudflared / Caddy), proxy config
docs/                        plan and implementation spec
```
