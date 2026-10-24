#!/usr/bin/env bash
# Restores a backup produced by backup.sh into the running compose project (stops the app first).
# Usage: PROJECT=repocuck ./restore.sh db-<stamp>.dump data-<stamp>.tgz
set -euo pipefail
dump="${1:?usage: restore.sh <db.dump> <data.tgz>}"; data="${2:?usage: restore.sh <db.dump> <data.tgz>}"
project="${PROJECT:-repocuck}"
dump="$(cd "$(dirname "$dump")" && pwd)/$(basename "$dump")"; data="$(cd "$(dirname "$data")" && pwd)/$(basename "$data")"
cd "$(dirname "$0")"      # compose files live next to this script (override with COMPOSE_FILE)
docker compose -p "$project" stop app || true
docker compose -p "$project" up -d db
# TCP check: during first start the image runs a throw-away server on the unix socket only; the real one listens on TCP
until docker compose -p "$project" exec -T db pg_isready -h 127.0.0.1 -U repocuck >/dev/null 2>&1; do sleep 1; done
docker compose -p "$project" exec -T db psql -U repocuck -d postgres -c "drop database if exists repocuck with (force)" -c "create database repocuck owner repocuck"
docker compose -p "$project" exec -T db pg_restore -U repocuck -d repocuck --no-owner < "$dump"
docker run --rm -v "${project}_repocuck-data:/data" -v "$(dirname "$data"):/in:ro" alpine \
  sh -c "rm -rf /data/* /data/.[!.]* 2>/dev/null; tar xzf /in/$(basename "$data") -C /data && chown -R 1654:1654 /data"
docker compose -p "$project" up -d app
echo "Restored. Verify with: curl -fsS http://localhost:8080/readyz  and  apt-get update on a client."
