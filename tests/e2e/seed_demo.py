#!/usr/bin/env python3
"""Seeds a running e2e stack (docker-compose.e2e.yml) with demo data: users, repositories in every state, a conflict,
a quarantined package, a failed asset and pending requests. Prints the credentials. Used for UI development and screenshots."""
import json, os, sys
import run_e2e as e

def main():
    e.wait_for(lambda: e.fetch("/readyz")[0] == 200, "ready")
    a = e.Session(); a.login("admin", "e2e-bootstrap-password-1")
    a.api("POST", "/me/password", {"current": "e2e-bootstrap-password-1", "newPassword": "admin-new-password-42"})
    a = e.Session(); assert a.login("admin", "admin-new-password-42")
    a.api("POST", "/admin/users", {"username": "alice", "displayName": "Alice Archer", "password": "alice-initial-pass-1", "role": "member"})
    m = e.Session(); m.login("alice", "alice-initial-pass-1")
    m.api("POST", "/me/password", {"current": "alice-initial-pass-1", "newPassword": "alice-new-password-7"})
    m = e.Session(); assert m.login("alice", "alice-new-password-7")
    ids = {}
    for name, archs in [("fooapp", ["amd64", "arm64"]), ("fork", ["amd64"]), ("baddigest", ["amd64"])]:
        c, js = a.api("POST", "/admin/repositories", {"owner": "acme", "name": name, "architectures": archs}); ids[name] = js["id"]
    e.wait_for(lambda: (lambda c, b, _: "Package: fooapp\n" in b.decode() if c == 200 else False)(*e.fetch("/apt/dists/stable/main/binary-amd64/Packages")), "published")
    c, js = m.api("POST", "/requests", {"kind": "add_repo", "url": "https://github.com/acme/newtool", "architectures": ["amd64", "arm64"], "note": "Handy for our CI images."}); ids["newtool"] = js["repository"]["id"]
    c, js = m.api("POST", "/requests", {"kind": "add_repo", "url": "https://github.com/acme/rejectme", "architectures": ["amd64"]})
    a.api("POST", f"/admin/requests/{js['request']['id']}/reject", {"reason": "Upstream hasn't shipped a release in years."})
    m.api("POST", "/requests", {"kind": "add_arch", "repositoryId": ids["fooapp"], "architectures": ["armhf"], "note": "For the Raspberry Pi."})
    e.wait_for(lambda: (lambda c, j: c == 200 and len(j["items"]) >= 3)(*m.api("GET", f"/repositories/{ids['newtool']}/packages")), "quarantine sync")
    json.dump(ids, open("/tmp/demo-ids.json", "w"))
    print("admin / admin-new-password-42   alice / alice-new-password-7"); print(json.dumps(ids))

if __name__ == "__main__":
    main()
