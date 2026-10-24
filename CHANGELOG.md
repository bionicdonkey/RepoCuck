# Changelog

## 1.0.1 — 2026-10-25

* **New web interface:** redesigned app shell with sidebar navigation and an approvals counter, a copyable install strip with the
  server's real apt commands, catalogue-style repository lists, status pills, a reworked approvals page that flags risky packages,
  a step-by-step public install page, new sign-in and setup pages. Light and dark themes, responsive down to phones, self-hosted fonts.
* **Fixes:**
  * Restore no longer races PostgreSQL's first-start init server (`deploy/restore.sh` and the compose healthchecks wait on TCP).
  * A corrupt or hostile `.deb` can only ever be rejected as an invalid package; unexpected reader failures no longer escape the parser.
  * GitHub rate-limit pauses end when the reset time passes instead of stalling the job runner.
  * Sync runs and index generations interrupted by a crash are marked failed at startup instead of staying "running".
  * Per-package version limits are applied right after a sync, so a 20-release backfill no longer briefly publishes every version.
  * `Security__TrustedProxies` behaviour is tested and documented (comma-separated list; the indexed environment form is not supported).
* **Docs:** adding the apt source on a client (deb822, pinning, Ansible, troubleshooting), running behind an existing proxy on another host,
  Docker bridge-gateway notes for trusted proxies.
* **Releases:** multi-arch (amd64/arm64) images on GHCR, signed with cosign, with an SBOM and deployment bundle attached to each release.

## 1.0.0 — 2026-10-24

First release. Highlights:

* GitHub release ingestion (ETag/rate-limit aware), bounded in-process `.deb` parsing, digest verification, content-addressed blobs.
* Signed APT repository (`InRelease`, `Release.gpg`, `Packages{,.gz,.xz}`, by-hash, daily heartbeat), `stable` and optional `testing` suites.
* Two roles (Admin/Member), shared watch list, request workflow with quarantine inspection before approval.
* Package policy (reserved names, epochs, release holdback), first-come arbitration with Admin re-arbitration.
* Local accounts with TOTP and recovery codes; OIDC (PKCE) with group→role mapping, linking and RP-initiated logout.
* Signing-key rotation with overlap; retention/GC; audit log; Prometheus metrics; offline admin CLI.
* Docker image, compose stacks for Cloudflare Tunnel and Caddy, backup/restore scripts and a tested restore drill.
