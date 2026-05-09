"""
Cache-poisoning challenge backend.

Reflects X-Forwarded-Host into a script tag's `src` so a poisoned cache entry
serves attacker-controlled JS to subsequent visitors.

Send:
    GET /landing
    Host: poisonlab.local
    X-Forwarded-Host: evil.tld

Then a normal user issuing GET /landing will be served the cached page that
points at evil.tld/payload.js.

The backend tracks distinct visitor IPs hitting /landing AFTER a poisoned
cache entry was placed; once a non-poisoner IP receives the poisoned content,
the flag is awarded on subsequent /flag fetch.
"""
import os
import threading
from flask import Flask, request, Response

FLAG_DIR = os.environ.get("FLAG_DIR", "/flags")
app = Flask(__name__)

state = {"poisoned_to": None, "victims": set()}
lock = threading.Lock()


def read_flag(name):
    p = os.path.join(FLAG_DIR, f"{name}.flag")
    return open(p).read().strip() if os.path.exists(p) else f"FLAG{{missing-{name}}}"


@app.route("/landing")
def landing():
    xfh = request.headers.get("X-Forwarded-Host", "")
    with lock:
        if xfh and xfh != request.host:
            state["poisoned_to"] = xfh
        if state["poisoned_to"] and request.remote_addr:
            state["victims"].add(request.remote_addr)
    js_host = xfh or request.host
    body = f"""<!doctype html><title>PoisonLab</title>
<h1>PoisonLab landing</h1>
<p>Try to poison this page so that subsequent visitors load JS from
your domain.</p>
<script src="//{js_host}/static/site.js"></script>"""
    # Make response cacheable
    return Response(body, headers={"Cache-Control": "public, max-age=300"})


@app.route("/flag")
def flag():
    with lock:
        if state["poisoned_to"] and len(state["victims"]) >= 2:
            return read_flag("cache_poison")
    return "not yet — poison the cache, then have at least one different " \
           "client receive the poisoned page.\n", 200


@app.route("/healthz")
def health(): return "ok"


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
