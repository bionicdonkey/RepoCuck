#!/usr/bin/env bash
# Builds the image (unless SKIP_BUILD=1), starts the compose stack, runs the suite, tears down.
set -euo pipefail
cd "$(dirname "$0")"
root="$(cd ../.. && pwd)"
[ "${SKIP_BUILD:-0}" = "1" ] || docker build -f "$root/deploy/Dockerfile" -t repocuck:dev "$root"
./build_debs.sh fixture/assets >/dev/null
docker compose -f docker-compose.e2e.yml down -v >/dev/null 2>&1 || true
docker compose -f docker-compose.e2e.yml up -d
trap 'docker compose -f docker-compose.e2e.yml logs --no-color app > e2e-app.log 2>&1 || true; [ "${KEEP:-0}" = "1" ] || docker compose -f docker-compose.e2e.yml down -v >/dev/null 2>&1' EXIT
python3 run_e2e.py
