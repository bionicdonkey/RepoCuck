#!/usr/bin/env python3
"""Backup/restore drill (AC-13/AC-15): seeds a published repository with the SHIPPED deploy/ compose + scripts,
backs it up, destroys every volume, restores, and proves a client holding the OLD signing key can still apt-get update/install."""
import json, os, re, secrets, shutil, subprocess, sys, tempfile, time
import run_e2e as e2e

HERE = os.path.dirname(os.path.abspath(__file__))
DEPLOY = os.path.abspath(os.path.join(HERE, "..", "..", "deploy"))
PROJECT = "repocuck"
e2e.BASE = "http://localhost:18081"
ENV = dict(os.environ, DB_PASSWORD="drill-db-password", REPOCUCK_BASE_URL="http://app:8080", CLOUDFLARE_TUNNEL_TOKEN="unused", PROJECT=PROJECT, E2E_DIR=HERE, COMPOSE_FILE=f"{DEPLOY}/docker-compose.yml:{HERE}/drill.override.yml")
COMPOSE = f"docker compose -p {PROJECT} -f {DEPLOY}/docker-compose.yml -f {HERE}/drill.override.yml"

def sh(cmd, **kw):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True, env=ENV, **kw)
    if r.returncode != 0:
        print("CMD FAILED:", cmd); print(r.stdout[-1500:]); print(r.stderr[-1500:])
    return r

def wait_ready():
    return e2e.wait_for(lambda: e2e.fetch("/readyz")[0] == 200, "app ready", timeout=180)

def client(cmd): return e2e.client(cmd)

def main():
    secrets_dir = os.path.join(DEPLOY, "secrets"); os.makedirs(secrets_dir, exist_ok=True)
    admin_pw = "drill-bootstrap-pass-1"
    open(os.path.join(secrets_dir, "admin_password"), "w").write(admin_pw)
    open(os.path.join(secrets_dir, "gpg_passphrase"), "w").write(secrets.token_urlsafe(24))
    st = json.load(open(os.path.join(HERE, "fixture", "state.template.json")))
    json.dump(st, open(os.path.join(HERE, "fixture", "state.json"), "w"))
    out = tempfile.mkdtemp(prefix="rc-backup-")
    sh(f"{COMPOSE} down -v"); sh("docker rm -f rce2e-client")
    try:
        print("== seed")
        check = e2e.check
        check(sh(f"{COMPOSE} up -d").returncode == 0, "shipped compose stack starts")
        wait_ready()
        admin = e2e.Session(); check(admin.login("admin", admin_pw), "bootstrap admin logs in")
        admin.api("POST", "/me/password", {"current": admin_pw, "newPassword": "drill-new-admin-pass-9"})
        admin = e2e.Session(); check(admin.login("admin", "drill-new-admin-pass-9"), "admin logs in with changed password")
        c, js = admin.api("POST", "/admin/repositories", {"owner": "acme", "name": "fooapp", "architectures": ["amd64"]}); check(c == 201, "admin adds repository")
        pk = e2e.wait_for(lambda: (lambda c, b, _: b.decode() if c == 200 and "Package: fooapp\n" in b.decode() else None)(*e2e.fetch("/apt/dists/stable/main/binary-amd64/Packages")), "package published")
        old_key = e2e.fetch("/apt/repocuck.gpg")[1]
        key_file = os.path.join(out, "client-keyring.gpg"); open(key_file, "wb").write(old_key)
        old_release = e2e.fetch("/apt/dists/stable/Release")[1]

        print("== backup")
        r = sh(f"{DEPLOY}/backup.sh {out}/b"); check(r.returncode == 0, "backup.sh succeeds")
        files = os.listdir(os.path.join(out, "b"))
        dump = os.path.join(out, "b", [f for f in files if f.startswith("db-")][0]); data = os.path.join(out, "b", [f for f in files if f.startswith("data-")][0])
        check(oct(os.stat(dump).st_mode)[-3:] == "600", "backup files are mode 0600")

        print("== disaster")
        sh(f"{COMPOSE} down -v")
        check("repocuck_repocuck-data" not in sh("docker volume ls --format '{{.Name}}'").stdout, "all volumes destroyed")

        print("== restore")
        sh(f"{COMPOSE} create fakegh db app >/dev/null 2>&1")
        r = sh(f"{DEPLOY}/restore.sh {dump} {data}"); check(r.returncode == 0, "restore.sh succeeds")
        sh(f"{COMPOSE} up -d fakegh")
        wait_ready()
        key2 = e2e.fetch("/apt/repocuck.gpg")[1]
        check(key2 == old_key, "restored signing key is identical (clients need no key change)")
        pk2 = e2e.wait_for(lambda: (lambda c, b, _: b.decode() if c == 200 and "Package: fooapp\n" in b.decode() else None)(*e2e.fetch("/apt/dists/stable/main/binary-amd64/Packages")), "package index served after restore")
        check(pk2 is not None, "published index survives restore")
        admin2 = e2e.Session(); check(admin2.login("admin", "drill-new-admin-pass-9"), "users/passwords restored (admin logs in with the changed password)")
        net = f"{PROJECT}_internal"
        r = sh(f"docker run -d --name rce2e-client --network {net} -v {key_file}:/etc/apt/keyrings/repocuck.gpg:ro debian:12 sleep 600")
        r = client("""for i in 1 2 3; do apt-get update -qq >/dev/null && break; sleep 3; done
echo 'deb [signed-by=/etc/apt/keyrings/repocuck.gpg] http://app:8080/apt stable main' > /etc/apt/sources.list.d/repocuck.list
apt-get update 2>&1 | tee /tmp/upd >/dev/null; ! grep -E '^(W|E):' /tmp/upd
apt-get install -y -qq fooapp >/dev/null && fooapp""")
        check(r.returncode == 0 and "fooapp 1.0.0 amd64" in r.stdout, "client with the OLD keyring: apt update + install works against the restored server")
        admin2.api("POST", "/admin/apt/rebuild")
        time.sleep(8)
        r = client("apt-get update 2>&1 | tee /tmp/upd2 >/dev/null; ! grep -E '^(W|E):' /tmp/upd2")
        check(r.returncode == 0, "restored server can publish new generations signed with the restored key")
    finally:
        sh("docker rm -f rce2e-client"); sh(f"{COMPOSE} down -v")
        shutil.rmtree(out, ignore_errors=True); shutil.rmtree(secrets_dir, ignore_errors=True)
    print()
    if e2e.failures:
        print(f"{len(e2e.failures)} FAILED:"); [print(" -", f) for f in e2e.failures]; sys.exit(1)
    print("RESTORE DRILL PASSED")

if __name__ == "__main__":
    main()
