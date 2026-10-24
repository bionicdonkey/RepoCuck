#!/usr/bin/env bash
# Backs up the database (pg_dump custom format) and the /data volume (blobs, signing keys, data-protection keys).
# Usage: PROJECT=repocuck ./backup.sh /path/to/backup-dir
# Encrypt the result before moving it off the machine: it contains the signing key and TOTP/OIDC encryption keys.
set -euo pipefail
out="${1:?usage: backup.sh <output-dir>}"
project="${PROJECT:-repocuck}"
mkdir -p "$out"; out="$(cd "$out" && pwd)"
cd "$(dirname "$0")"      # compose files live next to this script (override with COMPOSE_FILE)
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
docker compose -p "$project" exec -T db pg_dump -U repocuck -Fc repocuck > "$out/db-$stamp.dump"
# sockets (gpg-agent) and temp files are runtime-only; ownership is handed back to the invoking user
docker run --rm -v "${project}_repocuck-data:/data:ro" -v "$out:/out" alpine \
  sh -c "tar czf /out/data-$stamp.tgz --exclude='./gnupg/S.*' --exclude='./tmp' -C /data . && chown $(id -u):$(id -g) /out/data-$stamp.tgz"
chmod 600 "$out"/*-"$stamp".*
echo "Wrote $out/db-$stamp.dump and $out/data-$stamp.tgz"
