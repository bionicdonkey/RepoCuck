#!/usr/bin/env python3
"""Tiny fake GitHub API for the RepoCuck end-to-end suite.

State is read from /fixture/state.json on every request, so tests can add releases mid-run.
Layout: {"repos": {"acme/fooapp": {"id": 1001, "releases": [{"id": 1, "tag": "v1.0.0", "prerelease": false, "assets": ["fooapp_1.0.0_amd64.deb", ...]}]}}}
Asset names starting with "fork/" are served from /fixture/assets/fork/.
"""
import hashlib, json, os, sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

FIXTURE = os.environ.get("FIXTURE_DIR", "/fixture")
BASE = os.environ.get("PUBLIC_BASE", "http://fakegh:8000")
BAD_DIGEST = set()

def state():
    with open(os.path.join(FIXTURE, "state.json")) as f:
        return json.load(f)

def repo_json(full, r):
    owner, name = full.split("/")
    return {"id": r["id"], "name": name, "full_name": full, "private": False, "html_url": f"https://github.com/{full}",
            "description": r.get("description", f"Fixture repo {full}"), "default_branch": "main", "archived": False,
            "owner": {"login": owner}, "license": {"spdx_id": "MIT"}}

def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()

class H(BaseHTTPRequestHandler):
    def log_message(self, fmt, *a):
        sys.stderr.write("fakegh: " + fmt % a + "\n")

    def send_json(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(body)))
        self.send_header("X-RateLimit-Limit", "5000"); self.send_header("X-RateLimit-Remaining", "4990"); self.end_headers(); self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?")[0]
        parts = [p for p in path.split("/") if p]
        st = state()
        if len(parts) == 3 and parts[0] == "repos":
            full = f"{parts[1]}/{parts[2]}"
            if full in st["repos"]: return self.send_json(repo_json(full, st["repos"][full]))
            return self.send_json({"message": "Not Found"}, 404)
        if len(parts) == 2 and parts[0] == "repositories":
            for full, r in st["repos"].items():
                if str(r["id"]) == parts[1]: return self.send_json(repo_json(full, r))
            return self.send_json({"message": "Not Found"}, 404)
        if len(parts) == 4 and parts[0] == "repos" and parts[3] == "releases":
            full = f"{parts[1]}/{parts[2]}"
            if full not in st["repos"]: return self.send_json({"message": "Not Found"}, 404)
            out = []
            for rel in st["repos"][full]["releases"]:
                assets = []
                for i, a in enumerate(rel["assets"]):
                    p = os.path.join(FIXTURE, "assets", a)
                    if not os.path.exists(p): continue
                    digest = sha256(p)
                    if a in st.get("bad_digest", []): digest = "0" * 64
                    assets.append({"id": rel["id"] * 1000 + i + (st["repos"][full]["id"] * 100000), "name": os.path.basename(a), "size": os.path.getsize(p),
                                   "content_type": "application/octet-stream", "download_count": 3, "digest": "sha256:" + digest,
                                   "browser_download_url": f"{BASE}/assets/{a}"})
                out.append({"id": rel["id"] + st["repos"][full]["id"] * 100, "tag_name": rel["tag"], "name": rel["tag"], "body": "", "draft": False,
                            "prerelease": rel.get("prerelease", False), "published_at": "2026-10-01T00:00:00Z", "html_url": f"https://github.com/{full}/releases/{rel['tag']}", "assets": assets})
            return self.send_json(out)
        if parts and parts[0] == "assets":
            rel = "/".join(parts[1:])
            p = os.path.join(FIXTURE, "assets", rel)
            if ".." in rel or not os.path.isfile(p): return self.send_json({"message": "Not Found"}, 404)
            size = os.path.getsize(p)
            self.send_response(200); self.send_header("Content-Type", "application/octet-stream"); self.send_header("Content-Length", str(size)); self.end_headers()
            with open(p, "rb") as f: self.wfile.write(f.read())
            return
        self.send_json({"message": "Not Found"}, 404)

if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8000), H).serve_forever()
