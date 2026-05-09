"""
ShopFlux SSO — toy OAuth 2.0 / OIDC provider.

Vulnerabilities (lab):
  - redirect_uri is matched by `startswith` so attacker-controlled subdomains
    of the registered URI succeed (open-redirect → token theft chain).
  - Authorization codes are not bound to the originating client_id.
  - PKCE is optional even though the client requested it.
  - The `state` value is reflected unsanitized in error pages (XSS gadget).

Endpoints:
  GET  /authorize?response_type=code&client_id=...&redirect_uri=...&scope=...&state=...
  POST /token (code → access_token + id_token)
  GET  /userinfo
"""

import os
import time
import jwt
import secrets
from urllib.parse import urlencode, urlparse
from flask import Flask, request, redirect, jsonify, render_template_string

CLIENT_ID = os.environ.get("OAUTH_CLIENT_ID", "shopflux")
CLIENT_SECRET = os.environ.get("OAUTH_CLIENT_SECRET", "shopflux-oauth-secret")
FLAG_DIR = os.environ.get("FLAG_DIR", "/flags")
SIGNING_KEY = "oauth-lab-signing-key-not-secret"

# Allowed redirect URIs — but matched by startswith() (vuln).
REGISTERED_REDIRECTS = [
    "http://localhost:8080/oauth/callback",
    "http://shopflux.local/oauth/callback",
]

CODES = {}    # code -> {client_id, user, scope, redirect_uri, exp}
USERS = {
    "admin@shopflux.local": {"sub": "1", "role": "admin"},
    "alice@shopflux.local": {"sub": "2", "role": "customer"},
}


app = Flask(__name__)


def read_flag(name):
    p = os.path.join(FLAG_DIR, f"{name}.flag")
    try:
        return open(p).read().strip()
    except OSError:
        return f"FLAG{{missing-{name}}}"


def redirect_uri_allowed(uri):
    """VULN: startswith match — attacker-controlled domain works if it shares
    the prefix (e.g., http://localhost:8080/oauth/callback.evil.com)."""
    for r in REGISTERED_REDIRECTS:
        if uri.startswith(r):
            return True
    return False


@app.route("/authorize", methods=["GET", "POST"])
def authorize():
    if request.method == "GET":
        # show fake login form
        return render_template_string("""
        <h1>SSO — Sign in to ShopFlux</h1>
        <form method=post>
          <input name=email value="alice@shopflux.local" required>
          <input name=password type=password value="alice123" required>
          <input type=hidden name=client_id value="{{ q.get('client_id','') }}">
          <input type=hidden name=redirect_uri value="{{ q.get('redirect_uri','') }}">
          <input type=hidden name=scope value="{{ q.get('scope','openid email') }}">
          <input type=hidden name=state value="{{ q.get('state','') }}">
          <button>Authorize</button>
        </form>
        <!-- state is reflected for testing: {{ q.get('state','')|safe }} -->
        """, q=request.args)

    email = request.form.get("email", "")
    redirect_uri = request.form.get("redirect_uri", "")
    state = request.form.get("state", "")
    scope = request.form.get("scope", "openid email")

    if not redirect_uri_allowed(redirect_uri):
        return f"Invalid redirect_uri: {redirect_uri}", 400
    if email not in USERS:
        return "unknown user", 401

    code = secrets.token_urlsafe(16)
    CODES[code] = {
        "client_id": request.form.get("client_id", CLIENT_ID),
        "user": email,
        "scope": scope,
        "redirect_uri": redirect_uri,
        "exp": time.time() + 600,
    }
    sep = "&" if "?" in redirect_uri else "?"
    return redirect(f"{redirect_uri}{sep}{urlencode({'code': code, 'state': state})}")


@app.route("/token", methods=["POST"])
def token():
    code = request.form.get("code", "")
    redirect_uri = request.form.get("redirect_uri", "")
    client_id = request.form.get("client_id", "")
    info = CODES.pop(code, None)
    if not info or info["exp"] < time.time():
        return jsonify({"error": "invalid_code"}), 400
    # VULN: don't compare client_id strictly — accept any client
    # VULN: don't compare redirect_uri at token exchange
    user = USERS[info["user"]]
    access_token = jwt.encode(
        {"sub": user["sub"], "email": info["user"], "scope": info["scope"],
         "role": user["role"], "iat": int(time.time())},
        SIGNING_KEY, algorithm="HS256",
    )
    id_token = jwt.encode(
        {"sub": user["sub"], "email": info["user"], "iss": "http://localhost:8081",
         "aud": client_id or info["client_id"], "iat": int(time.time())},
        SIGNING_KEY, algorithm="HS256",
    )
    flag = ""
    if client_id and client_id != info["client_id"]:
        flag = read_flag("oauth_takeover")
    return jsonify({"access_token": access_token, "id_token": id_token,
                    "token_type": "Bearer", "scope": info["scope"], "flag": flag})


@app.route("/userinfo")
def userinfo():
    auth = request.headers.get("Authorization", "")
    tok = auth.replace("Bearer ", "")
    try:
        claims = jwt.decode(tok, SIGNING_KEY, algorithms=["HS256"])
    except Exception as e:
        return jsonify({"error": str(e)}), 401
    return jsonify(claims)


@app.route("/healthz")
def healthz():
    return "ok\n"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8081)
