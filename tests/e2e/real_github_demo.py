#!/usr/bin/env python3
"""Opt-in end-to-end demo against the REAL GitHub: mirror BurntSushi/ripgrep and install it with apt from RepoCuck."""
import os, re, subprocess, sys
import run_e2e as e2e

HERE = os.path.dirname(os.path.abspath(__file__))
COMPOSE = f"docker compose -f {HERE}/docker-compose.e2e.yml -f {HERE}/real.override.yml"

def main():
    e2e.sh(f"{COMPOSE} down -v"); e2e.sh("docker rm -f rce2e-client")
    try:
        e2e.check(e2e.sh(f"{COMPOSE} up -d").returncode == 0, "stack starts against real GitHub")
        e2e.wait_for(lambda: e2e.fetch("/readyz")[0] == 200, "ready")
        a = e2e.Session(); a.login("admin", "e2e-bootstrap-password-1")
        a.api("POST", "/me/password", {"current": "e2e-bootstrap-password-1", "newPassword": "admin-new-password-42"})
        a = e2e.Session(); a.login("admin", "admin-new-password-42")
        c, js = a.api("POST", "/admin/repositories", {"url": "https://github.com/BurntSushi/ripgrep", "architectures": ["amd64"]})
        e2e.check(c == 201, "admin adds BurntSushi/ripgrep")
        rid = js["id"]
        pk = e2e.wait_for(lambda: (lambda c, b, _: b.decode() if c == 200 and "Package: ripgrep\n" in b.decode() else None)(*e2e.fetch("/apt/dists/stable/main/binary-amd64/Packages")), "ripgrep published", timeout=240)
        e2e.check(pk is not None, "ripgrep appears in the signed index")
        vers = re.findall(r"Package: ripgrep\nVersion: (\S+)", pk or "")
        print("  mirrored ripgrep versions in index:", vers)
        e2e.check(0 < len(vers) <= 3, "retention keeps at most 3 versions after the backfill")
        e2e.sh("docker run -d --name rce2e-client --network rce2e_default debian:12 sleep 600")
        r = e2e.client("""for i in 1 2 3; do apt-get update -qq >/dev/null && break; sleep 3; done
apt-get install -y -qq --no-install-recommends curl ca-certificates gnupg >/dev/null
install -d -m 0755 /etc/apt/keyrings
curl -fsS http://app:8080/apt/repocuck.gpg -o /etc/apt/keyrings/repocuck.gpg
echo 'deb [signed-by=/etc/apt/keyrings/repocuck.gpg] http://app:8080/apt stable main' > /etc/apt/sources.list.d/repocuck.list
apt-get update 2>&1 | tee /tmp/upd >/dev/null; ! grep -E '^(W|E):' /tmp/upd
apt-get install -y -qq -t stable ripgrep >/dev/null
apt-cache policy ripgrep | head -4
rg --version | head -1""")
        print(r.stdout)
        newest = vers[-1].split("-")[0] if vers else "?"
        e2e.check(r.returncode == 0 and f"Installed: {vers[-1]}" in r.stdout and newest in r.stdout, "apt installs the newest real ripgrep .deb from RepoCuck and rg runs")
    finally:
        e2e.sh("docker rm -f rce2e-client"); e2e.sh(f"{COMPOSE} down -v")
    if e2e.failures:
        print(f"{len(e2e.failures)} FAILED"); sys.exit(1)
    print("REAL GITHUB DEMO PASSED")

if __name__ == "__main__":
    main()
