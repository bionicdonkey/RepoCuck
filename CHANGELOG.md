# Changelog

## 1.0.0 — 2026-10-24

First release. Highlights:

* GitHub release ingestion (ETag/rate-limit aware), bounded in-process `.deb` parsing, digest verification, content-addressed blobs.
* Signed APT repository (`InRelease`, `Release.gpg`, `Packages{,.gz,.xz}`, by-hash, daily heartbeat), `stable` and optional `testing` suites.
* Two roles (Admin/Member), shared watch list, request workflow with quarantine inspection before approval.
* Package policy (reserved names, epochs, release holdback), first-come arbitration with Admin re-arbitration.
* Local accounts with TOTP and recovery codes; OIDC (PKCE) with group→role mapping, linking and RP-initiated logout.
* Signing-key rotation with overlap; retention/GC; audit log; Prometheus metrics; offline admin CLI.
* Docker image, compose stacks for Cloudflare Tunnel and Caddy, backup/restore scripts and a tested restore drill.
