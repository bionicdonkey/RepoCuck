#!/usr/bin/env python3
"""End-to-end suite: drives the RepoCuck API against a fake GitHub and verifies a real apt client.

Usage: run_e2e.py   (expects `docker compose -f docker-compose.e2e.yml up -d` to be running; see run_e2e.sh)
"""
import json, os, re, shlex, subprocess, sys, time, urllib.error, urllib.parse, urllib.request, http.cookiejar

BASE = os.environ.get("E2E_BASE", "http://localhost:18080")
HERE = os.path.dirname(os.path.abspath(__file__))
STATE = os.path.join(HERE, "fixture", "state.json")
NET = "rce2e_default"
failures = []

def check(cond, msg):
    print(("  ok   " if cond else "  FAIL ") + msg, flush=True)
    if not cond: failures.append(msg)

class Session:
    def __init__(self):
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))
        self.csrf = None

    def raw(self, method, path, data=None, headers=None):
        req = urllib.request.Request(BASE + path, data=data, method=method, headers=headers or {})
        try:
            with self.opener.open(req, timeout=60) as r: return r.status, r.read(), dict(r.headers)
        except urllib.error.HTTPError as e: return e.code, e.read(), dict(e.headers)

    def login(self, user, pw):
        _, body, _ = self.raw("GET", "/login")
        tok = re.search(r'name="__RequestVerificationToken"[^>]*value="([^"]+)"', body.decode()).group(1)
        form = urllib.parse.urlencode({"Username": user, "Password": pw, "__RequestVerificationToken": tok}).encode()
        code, body, _ = self.raw("POST", "/login", form, {"Content-Type": "application/x-www-form-urlencoded"})
        ok = any(c.name.endswith("repocuck") for c in self.jar)
        self.csrf = None
        return ok

    def api(self, method, path, obj=None):
        if method != "GET" and self.csrf is None:
            _, b, _ = self.raw("GET", "/api/v1/csrf"); self.csrf = json.loads(b)["token"]
        h = {"Content-Type": "application/json"}
        if method != "GET": h["X-Repocuck-CSRF"] = self.csrf
        code, body, hd = self.raw(method, "/api/v1" + path, json.dumps(obj).encode() if obj is not None else (b"{}" if method == "POST" else None), h)
        try: js = json.loads(body) if body else None
        except Exception: js = body
        return code, js

def wait_for(fn, what, timeout=120, interval=1.5):
    end = time.time() + timeout
    while time.time() < end:
        try:
            r = fn()
            if r: return r
        except Exception as e:
            pass
        time.sleep(interval)
    check(False, f"timeout waiting for {what}")
    return None

def sh(cmd, check_ok=True):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if r.returncode != 0 and check_ok:
        print(r.stdout[-2000:]); print(r.stderr[-2000:])
    return r

def client(cmd):
    return sh("docker exec rce2e-client bash -ec " + shlex.quote(cmd))

def fetch(path):
    return Session().raw("GET", path)

def main():
    shutil_state = json.load(open(os.path.join(HERE, "fixture", "state.template.json")))
    json.dump(shutil_state, open(STATE, "w"), indent=1)

    print("== health")
    wait_for(lambda: fetch("/readyz")[0] == 200, "readyz")
    check(fetch("/healthz")[0] == 200, "healthz is 200")
    check(b"version" not in fetch("/healthz")[1], "healthz exposes no version")
    code, hdrs = fetch("/login")[0], fetch("/login")[2]
    check("default-src 'self'" in hdrs.get("Content-Security-Policy", ""), "login page has CSP")
    check(hdrs.get("X-Content-Type-Options") == "nosniff", "nosniff header present")
    check("Server" not in hdrs, "no Server header")
    check(fetch("/api/v1/repositories")[0] == 401, "API requires authentication")

    print("== accounts")
    admin = Session()
    check(admin.login("admin", "e2e-bootstrap-password-1"), "bootstrap admin can log in")
    code, js = admin.api("GET", "/repositories")
    check(code == 403 and js["code"] == "password_change_required", "must-change-password blocks API")
    code, _ = admin.api("POST", "/me/password", {"current": "e2e-bootstrap-password-1", "newPassword": "admin-new-password-42"})
    check(code == 204, "admin changes password")
    admin = Session()
    check(admin.login("admin", "admin-new-password-42"), "admin logs in with new password")
    check(not Session().login("admin", "wrong-password-xx"), "wrong password rejected")

    code, js = admin.api("POST", "/admin/users", {"username": "alice", "password": "alice-initial-pass-1", "role": "member"})
    check(code == 201, "admin creates member alice")
    alice = Session()
    check(alice.login("alice", "alice-initial-pass-1"), "alice first login")
    alice.api("POST", "/me/password", {"current": "alice-initial-pass-1", "newPassword": "alice-new-password-7"})
    alice = Session(); check(alice.login("alice", "alice-new-password-7"), "alice logs in after change")
    code, _ = alice.api("GET", "/admin/users"); check(code == 403, "member cannot list users")
    code, _ = alice.api("POST", "/admin/repositories", {"owner": "acme", "name": "fooapp", "architectures": ["amd64"]}); check(code == 403, "member cannot add repos directly")
    code, js = alice.api("POST", "/me/totp/enable", {"password": "alice-new-password-7"}); check(code == 200 and js.get("secret"), "totp enrollment starts")

    print("== request flow")
    code, js = alice.api("POST", "/requests", {"kind": "add_repo", "url": "https://github.com/acme/fooapp", "architectures": ["amd64", "arm64"], "note": "needed for CI"})
    check(code == 201 and js["repository"]["state"] == "proposed", "member request creates proposed repo")
    repo_id = js["repository"]["id"]; req_id = js["request"]["id"]
    code, js = alice.api("POST", "/requests", {"kind": "add_repo", "owner": "acme", "name": "fooapp", "architectures": ["amd64"]})
    check(code == 409 and js["code"] == "request_pending", "same user duplicate -> request_pending")
    code, js = admin.api("POST", "/requests", {"kind": "add_repo", "owner": "acme", "name": "fooapp", "architectures": ["amd64"]})
    check(code == 409 and js["code"] == "already_watched" and js["repositoryId"] == repo_id, "other user duplicate -> already_watched with link")
    code, js = alice.api("POST", "/requests", {"kind": "add_repo", "owner": "acme", "name": "nonexistent", "architectures": ["amd64"]})
    check(code == 404 and js["code"] == "repository_not_found", "unknown repo -> 404")
    code, js = alice.api("POST", "/requests", {"kind": "add_repo", "owner": "acme", "name": "fork", "architectures": ["sparc"]})
    check(code == 400, "unsupported architecture rejected")

    print("== quarantine inspection")
    def pkgs():
        c, j = alice.api("GET", f"/repositories/{repo_id}/packages")
        return j["items"] if c == 200 and len(j["items"]) >= 5 else None
    items = wait_for(pkgs, "quarantine sync to ingest packages")
    names = {(i["package"], i["version"], i["architecture"]): i for i in (items or [])}
    check(("fooapp", "1.0.0", "amd64") in names and ("fooapp", "1.0.0", "arm64") in names, "amd64+arm64 fooapp ingested")
    check(("fooapp", "1.0.0", "armhf") not in names, "armhf not ingested (not selected)")
    check(names.get(("libc6", "99.0", "amd64"), {}).get("state") == "quarantined", "reserved name libc6 quarantined")
    check(names.get(("epochpkg", "2.0", "amd64"), {}).get("state") == "quarantined" or names.get(("epochpkg", "1:2.0", "amd64"), {}).get("state") == "quarantined", "epoch package quarantined")
    status, body, _ = fetch("/apt/dists/stable/InRelease")
    wait_for(lambda: fetch("/apt/dists/stable/InRelease")[0] == 200, "initial InRelease")
    status, body, _ = fetch("/apt/dists/stable/main/binary-amd64/Packages")
    check(status == 404 or b"fooapp" not in body, "nothing published from proposed repo")

    print("== approval + publishing")
    code, js = admin.api("GET", "/admin/requests")
    check(code == 200 and any(g["repositoryId"] == repo_id for g in js["items"]), "admin sees pending request")
    code, js = alice.api("POST", f"/admin/requests/{req_id}/approve", {})
    check(code == 403, "member cannot approve")
    code, js = admin.api("POST", f"/admin/requests/{req_id}/approve", {"architectures": ["amd64", "arm64"]})
    check(code == 200 and js["status"] == "approved", "admin approves request")
    def amd64_packages():
        c, b, _ = fetch("/apt/dists/stable/main/binary-amd64/Packages")
        return b.decode() if c == 200 and "Package: fooapp\n" in b.decode() else None
    pk = wait_for(amd64_packages, "fooapp in amd64 Packages")
    check(pk is not None and "Package: fooapp-data" in pk, "arch:all package in amd64 index")
    check(pk is not None and "libc6" not in pk and "epochpkg" not in pk, "quarantined packages not in index")
    check(pk is not None and pk.count("Package: fooapp\n") == 1, "exactly one fooapp stanza")
    c, b, h = fetch("/apt/dists/stable/Release"); rel = b.decode()
    check("Architectures: all amd64 arm64" in rel and "armhf" not in rel, "Release advertises exactly amd64 arm64 all")
    check("Acquire-By-Hash: yes" in rel and "MD5Sum" not in rel, "Release by-hash, no MD5")
    check(fetch("/apt/dists/stable/main/binary-armhf/Packages")[0] == 404, "no armhf index")
    m = re.search(r" ([0-9a-f]{64}) +\d+ main/binary-amd64/Packages\n", rel)
    check(m and fetch(f"/apt/dists/stable/main/binary-amd64/by-hash/SHA256/{m.group(1)}")[0] == 200, "by-hash path resolves")
    c, b, h = fetch("/apt/dists/stable/Release")
    check('"sha256:' in h.get("ETag", ""), "strong sha256 ETag")
    rq = urllib.request.Request(BASE + "/apt/dists/stable/Release", headers={"If-None-Match": h["ETag"]})
    try: urllib.request.urlopen(rq); got = 200
    except urllib.error.HTTPError as e: got = e.code
    check(got == 304, "conditional GET returns 304")
    check(fetch("/apt/pool/main/f/fooapp/..%2f..%2fetc%2fpasswd")[0] in (400, 404), "path traversal rejected")
    check(fetch("/apt/dists/stable/main/binary-amd64/by-hash/SHA256/../../../etc/passwd")[0] in (400, 404), "by-hash traversal rejected")
    check(sh("curl -s -o /dev/null -w '%{http_code}' -X PUT " + BASE + "/apt/dists/stable/Release").stdout.strip() in ("405", "404"), "PUT not allowed on /apt")

    print("== real apt client")
    sh("docker rm -f rce2e-client")
    r = sh(f"docker run -d --name rce2e-client --network {NET} debian:12 sleep 3600")
    check(r.returncode == 0, "client container started")
    r = client("""for i in 1 2 3; do apt-get update -qq >/dev/null && break; sleep 3; done
apt-get install -y -qq --no-install-recommends curl gnupg ca-certificates >/dev/null
install -d -m 0755 /etc/apt/keyrings
curl -fsS http://app:8080/apt/repocuck.gpg -o /etc/apt/keyrings/repocuck.gpg
echo 'deb [signed-by=/etc/apt/keyrings/repocuck.gpg] http://app:8080/apt stable main' > /etc/apt/sources.list.d/repocuck.list
apt-get update 2>&1 | tee /tmp/upd >/dev/null; ! grep -E '^(W|E):' /tmp/upd
apt-get install -y -qq fooapp >/dev/null
fooapp""")
    check(r.returncode == 0 and "fooapp 1.0.0 amd64" in r.stdout, "apt update (no warnings) + apt install fooapp works")
    r = client("apt-get install -y -qq fooapp-data >/dev/null && dpkg -s fooapp-data | grep -q 'Architecture: all'")
    check(r.returncode == 0, "arch:all package installs")
    r = client("curl -fsS http://app:8080/apt/repocuck.asc | gpg --show-keys --with-colons | grep -c '^fpr'")
    check(r.returncode == 0, "armored key is a valid OpenPGP key")
    r = client("dpkg --add-architecture arm64 && apt-get update -qq >/dev/null && cd /tmp && apt-get download fooapp:arm64 && ls fooapp_1.0.0_arm64.deb && dpkg-deb -f fooapp_1.0.0_arm64.deb Architecture")
    check(r.returncode == 0 and "arm64" in r.stdout, "apt-get download fooapp:arm64 on amd64 host")
    r = client("apt-get install -y -qq libc6 2>&1 | tail -1; apt-cache policy libc6 | grep -c 99.0 || true")
    check("0" in r.stdout.strip().splitlines()[-1], "quarantined libc6 99.0 not offered")

    print("== upgrade")
    st = json.load(open(STATE))
    st["repos"]["acme/fooapp"]["releases"].insert(0, {"id": 2, "tag": "v1.1.0", "assets": ["fooapp_1.1.0_amd64.deb", "fooapp_1.1.0_arm64.deb"]})
    json.dump(st, open(STATE, "w"))
    code, _ = admin.api("POST", f"/admin/repositories/{repo_id}/sync", {"reevaluate": False}); check(code == 202, "admin triggers sync")
    pk = wait_for(lambda: (lambda c, b, _: b.decode() if c == 200 and "Version: 1.1.0" in b.decode() else None)(*fetch("/apt/dists/stable/main/binary-amd64/Packages")), "1.1.0 in index")
    r = client("apt-get update -qq >/dev/null && apt-get upgrade -y -qq >/dev/null && fooapp")
    check("fooapp 1.1.0 amd64" in r.stdout, "apt-get upgrade installs 1.1.0")
    check(pk is not None and "Version: 1.0.0" in pk, "older version still in index (retention keeps 3)")

    print("== fork conflict")
    code, js = admin.api("POST", "/admin/repositories", {"owner": "acme", "name": "fork", "architectures": ["amd64"]})
    check(code == 201, "admin adds fork directly"); fork_id = js["id"]
    def conflict():
        c, j = admin.api("GET", "/admin/conflicts")
        return j["items"] if c == 200 and j["items"] else None
    conf = wait_for(conflict, "conflict to be recorded")
    check(conf is not None and conf[0]["package"] == "fooapp", "conflict visible to admin")
    c, j = alice.api("GET", f"/repositories/{fork_id}/packages")
    check(c == 200 and any(i["others"] for i in j["items"]), "conflict visible to members on repo page")
    r = client("cd /tmp && apt-get update -qq >/dev/null; rm -f fooapp_1.0.0_amd64.deb; apt-get download fooapp=1.0.0 >/dev/null && dpkg-deb -f fooapp_1.0.0_amd64.deb Maintainer")
    check("Fixture" in r.stdout and "Fork" not in r.stdout, "first-come source still serves 1.0.0 bytes (not the fork's)")
    c, j = admin.api("POST", f"/admin/repositories/{fork_id}/block", {"reason": "test"}); check(c == 200, "admin blocks the fork")
    c, j = alice.api("POST", "/requests", {"kind": "add_repo", "owner": "acme", "name": "fork", "architectures": ["amd64"]})
    check(c == 403 and j["code"] == "repository_blocked", "blocked repo cannot be requested")

    print("== architecture request")
    c, j = alice.api("POST", "/requests", {"kind": "add_arch", "repositoryId": repo_id, "architectures": ["amd64"]})
    check(c == 409 and j["code"] == "already_enabled", "arch already enabled -> 409")
    c, j = alice.api("POST", "/requests", {"kind": "add_arch", "repositoryId": repo_id, "architectures": ["armhf"], "note": "pi"})
    check(c == 201, "member requests armhf"); r2 = j["request"]["id"]
    c, j = admin.api("POST", f"/admin/requests/{r2}/approve", {}); check(c == 200, "admin approves armhf")
    def armhf():
        c, b, _ = fetch("/apt/dists/stable/main/binary-armhf/Packages")
        return b.decode() if c == 200 and "Package: fooapp\n" in b.decode() else None
    ah = wait_for(armhf, "armhf index appears (excluded asset re-evaluated)")
    check(ah is not None and "Version: 1.0.0" in ah, "previously excluded armhf asset now published")
    c, b, _ = fetch("/apt/dists/stable/Release"); check("armhf" in b.decode(), "Release now advertises armhf")
    c, js = alice.api("POST", "/requests", {"kind": "add_arch", "repositoryId": repo_id, "architectures": ["riscv64"]})
    c2, js2 = admin.api("POST", f"/admin/requests/{js['request']['id']}/reject", {"reason": "no hardware to test"})
    check(c2 == 200, "admin rejects arch request")
    c, js = alice.api("GET", "/requests?mine=true"); check(any(i["status"] == "rejected" and i["decisionNote"] for i in js["items"]), "requester sees rejection reason")

    print("== digest mismatch")
    c, js = admin.api("POST", "/admin/repositories", {"owner": "acme", "name": "baddigest", "architectures": ["amd64"]}); bad_id = js["id"]
    def bad_asset():
        c, j = admin.api("GET", f"/repositories/{bad_id}/releases")
        a = [x for r in j["items"] for x in r["assets"]] if c == 200 else []
        return a if a and a[0]["state"] in ("failed", "parsed") else None
    a = wait_for(bad_asset, "bad digest asset processed")
    check(a and a[0]["state"] == "failed" and a[0]["reason"] == "digest_mismatch", "digest mismatch marks asset failed")
    c, b, _ = fetch("/apt/dists/stable/main/binary-amd64/Packages"); check("baddigest" not in b.decode(), "mismatched asset not published")

    print("== blocking removes packages")
    c, j = admin.api("POST", f"/admin/repositories/{repo_id}/block", {"reason": "e2e"}); check(c == 200, "admin blocks fooapp repo")
    gone = wait_for(lambda: (lambda c, b, _: "Package: fooapp\n" not in b.decode() if c == 200 else False)(*fetch("/apt/dists/stable/main/binary-amd64/Packages")), "fooapp removed from index")
    check(bool(gone), "blocked repository's packages leave the next generation")

    print("== audit")
    c, js = admin.api("GET", "/admin/audit?limit=200")
    acts = {i["action"] for i in js["items"]} if c == 200 else set()
    for a in ("request.created", "request.approved", "request.rejected", "repository.block", "auth.login", "user.created"):
        check(a in acts, f"audit has {a}")
    c, js = alice.api("GET", "/admin/audit"); check(c == 403, "member cannot read audit log")

    sh("docker rm -f rce2e-client")
    print()
    if failures:
        print(f"{len(failures)} FAILED:"); [print(" -", f) for f in failures]; sys.exit(1)
    print("ALL E2E CHECKS PASSED")

if __name__ == "__main__":
    main()
