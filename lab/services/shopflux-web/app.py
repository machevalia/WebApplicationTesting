"""
ShopFlux — main storefront Flask app.

Deliberately vulnerable. DO NOT deploy outside the lab.

Vulnerability map (challenge → flag file under /flags):

    GET  /search?q=...                  reflected XSS  → xss_reflected.flag
    POST /products/<id>/reviews         stored XSS     → xss_stored.flag
    GET  /products                      DOM XSS via #q → xss_dom.flag
    GET  /products?category=...         SQLi (union)   → sqli_union.flag
    GET  /track?order_id=...            SQLi (blind)   → sqli_blind.flag
    POST /contact                       SSTI (Jinja2)  → ssti_jinja.flag
    GET  /download?file=...             path traversal → path_traversal.flag
    POST /webhooks/test {url}           SSRF           → ssrf_metadata.flag
                                                       → ssrf_redis.flag (gopher)
    GET  /orders/<id>                   IDOR           → idor_orders.flag
    POST /account/avatar                file upload    → file_upload.flag
    GET  /redirect?next=...             open redirect  → open_redirect.flag
    POST /password-reset                host header    → host_header.flag
    POST /import/products               XXE            → xxe_external.flag
    POST /checkout                      biz logic      → business_logic.flag
    GET  /.env                          info disclose  → info_disclosure_env.flag
    GET  /clickjack-target              clickjacking   → clickjacking.flag
    POST /account/email                 CSRF (no tok)  → csrf.flag
    POST /coupons/redeem                race condition → race_condition.flag
    GET  /profile/<id>                  CSPT-to-CSRF   → cspt_csrf.flag
    GET  /docs/<slug>                   CSPT-to-XSS    → cspt_xss.flag

The /flags directory is read-only inside the container so individual flags
are extracted as a *consequence* of successful exploitation, not by simply
reading the filesystem.
"""

import os
import re
import time
import uuid
import json
import base64
import hmac
import hashlib
import logging
import subprocess
import threading
from urllib.parse import urlparse, urljoin

import jwt
import redis
import psycopg2
import requests
from lxml import etree
from flask import (
    Flask, request, render_template, render_template_string, make_response,
    redirect, url_for, session, g, abort, jsonify, send_from_directory,
)
from werkzeug.utils import secure_filename
from jinja2 import Environment, BaseLoader

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("shopflux")

DATABASE_URL = os.environ.get("DATABASE_URL")
REDIS_URL = os.environ.get("REDIS_URL", "redis://redis:6379/0")
SECRET_KEY = os.environ.get("SECRET_KEY", "dev")
FLAG_DIR = os.environ.get("FLAG_DIR", "/flags")
ADMIN_INTERNAL_URL = os.environ.get("ADMIN_INTERNAL_URL", "http://shopflux-admin:9000")

app = Flask(__name__, static_folder="static", template_folder="templates")
app.config["SECRET_KEY"] = SECRET_KEY
app.config["MAX_CONTENT_LENGTH"] = 8 * 1024 * 1024

rds = redis.from_url(REDIS_URL)


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------
def db():
    if "db" not in g:
        g.db = psycopg2.connect(DATABASE_URL)
        g.db.autocommit = True
    return g.db


@app.teardown_appcontext
def _close_db(exc):
    d = g.pop("db", None)
    if d is not None:
        d.close()


def read_flag(name):
    """Return flag value if present (used to embed flags into responses on
    successful exploitation)."""
    p = os.path.join(FLAG_DIR, f"{name}.flag")
    try:
        with open(p) as fh:
            return fh.read().strip()
    except OSError:
        return f"FLAG{{missing-{name}}}"


# ---------------------------------------------------------------------------
# Auth (deliberately weak)
# ---------------------------------------------------------------------------
def current_user():
    tok = request.cookies.get("session_token")
    if not tok:
        return None
    try:
        # alg list intentionally permissive — see jwt_confusion challenge in API.
        payload = jwt.decode(tok, SECRET_KEY, algorithms=["HS256", "none"],
                             options={"verify_signature": False if tok.count(".") == 2
                                      and tok.split(".")[2] == "" else True})
        return payload
    except Exception:
        return None


def issue_session(user_id, email, role="customer"):
    payload = {"uid": user_id, "email": email, "role": role,
               "iat": int(time.time())}
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")


# ---------------------------------------------------------------------------
# Routes — public storefront
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    cur = db().cursor()
    cur.execute("SELECT id, name, price, image FROM products ORDER BY id LIMIT 12")
    products = cur.fetchall()
    return render_template("index.html", products=products, user=current_user())


@app.route("/products")
def list_products():
    """SQLi (union) via ?category=  — concatenated into the query."""
    category = request.args.get("category", "")
    cur = db().cursor()
    # Vulnerable: string concat
    q = ("SELECT id, name, price, image FROM products "
         f"WHERE category = '{category}'") if category else \
        "SELECT id, name, price, image FROM products"
    try:
        cur.execute(q)
        rows = cur.fetchall()
    except Exception as e:
        # Verbose error to aid SQLi discovery
        return render_template("error.html", error=str(e), query=q), 500
    return render_template("products.html", products=rows, user=current_user(),
                           category=category)


@app.route("/search")
def search():
    """Reflected XSS — q is rendered via |safe in the template."""
    q = request.args.get("q", "")
    cur = db().cursor()
    cur.execute(
        "SELECT id, name, price FROM products WHERE name ILIKE %s LIMIT 20",
        (f"%{q}%",),
    )
    return render_template("search.html", q=q, results=cur.fetchall(),
                           user=current_user())


@app.route("/products/<int:pid>", methods=["GET", "POST"])
def product_detail(pid):
    """Stored XSS via reviews. Reviews stored raw and rendered with |safe."""
    cur = db().cursor()
    if request.method == "POST":
        author = request.form.get("author", "anon")
        body = request.form.get("body", "")
        cur.execute(
            "INSERT INTO reviews (product_id, author, body) VALUES (%s, %s, %s)",
            (pid, author, body),
        )
        return redirect(url_for("product_detail", pid=pid))

    cur.execute("SELECT id, name, description, price, image FROM products WHERE id=%s", (pid,))
    prod = cur.fetchone()
    if not prod:
        abort(404)
    cur.execute("SELECT author, body, created_at FROM reviews WHERE product_id=%s ORDER BY id DESC", (pid,))
    revs = cur.fetchall()
    return render_template("product.html", product=prod, reviews=revs,
                           user=current_user())


# ---------------------------------------------------------------------------
# Auth flows
# ---------------------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html", user=current_user())
    email = request.form.get("email", "")
    password = request.form.get("password", "")
    cur = db().cursor()
    cur.execute("SELECT id, email, password_md5, role FROM users WHERE email=%s",
                (email,))
    row = cur.fetchone()
    if not row:
        return render_template("login.html", error="Invalid", user=None), 401
    uid, em, pwmd5, role = row
    if pwmd5 != hashlib.md5(password.encode()).hexdigest():
        return render_template("login.html", error="Invalid", user=None), 401
    tok = issue_session(uid, em, role)
    resp = make_response(redirect(url_for("account")))
    resp.set_cookie("session_token", tok, httponly=False, samesite="Lax")
    return resp


@app.route("/logout")
def logout():
    resp = make_response(redirect(url_for("index")))
    resp.delete_cookie("session_token")
    return resp


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html", user=None)
    email = request.form.get("email", "").strip()
    pw = request.form.get("password", "")
    cur = db().cursor()
    try:
        cur.execute(
            "INSERT INTO users (email, password_md5, role) VALUES (%s, %s, 'customer') RETURNING id",
            (email, hashlib.md5(pw.encode()).hexdigest()),
        )
        uid = cur.fetchone()[0]
    except Exception as e:
        return render_template("register.html", error=str(e), user=None), 400
    tok = issue_session(uid, email, "customer")
    resp = make_response(redirect(url_for("account")))
    resp.set_cookie("session_token", tok, samesite="Lax")
    return resp


@app.route("/password-reset", methods=["GET", "POST"])
def password_reset():
    """Host header injection: reset link is built from request.host_url, which
    Flask derives from the Host header. With X-Forwarded-Host honored at the
    edge, an attacker can poison the link sent to a victim."""
    if request.method == "GET":
        return render_template("password_reset.html", user=None)
    email = request.form.get("email", "")
    token = hashlib.sha1(f"{email}-{int(time.time()/3600)}".encode()).hexdigest()[:16]

    # Vulnerable: trusts Host / X-Forwarded-Host
    host = request.headers.get("X-Forwarded-Host") or request.host
    reset_link = f"http://{host}/password-reset/confirm?token={token}&email={email}"

    log.info("password reset link for %s -> %s", email, reset_link)
    # Persist the constructed link so testers can read it back
    rds.setex(f"reset:{email}", 600, reset_link)

    # If reset link domain != legitimate host, embed the host_header flag in
    # the response (proves the poisoning was successful).
    legit_hosts = {"localhost:8080", "localhost", "shopflux.local"}
    flag_msg = ""
    if host not in legit_hosts:
        flag_msg = read_flag("host_header")
    return render_template("password_reset.html", sent=True, link=reset_link,
                           flag=flag_msg, user=None)


# ---------------------------------------------------------------------------
# Account / orders
# ---------------------------------------------------------------------------
@app.route("/account")
def account():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    cur = db().cursor()
    cur.execute("SELECT id, total_cents, status FROM orders WHERE user_id=%s ORDER BY id DESC",
                (user["uid"],))
    orders = cur.fetchall()
    return render_template("account.html", user=user, orders=orders)


@app.route("/orders/<int:oid>")
def order_detail(oid):
    """IDOR: no ownership check.  Order #1 belongs to admin and contains
    the idor_orders.flag in its notes column."""
    cur = db().cursor()
    cur.execute("SELECT id, user_id, total_cents, notes, status FROM orders WHERE id=%s",
                (oid,))
    row = cur.fetchone()
    if not row:
        abort(404)
    # Substitute the IDOR flag for the admin order's notes.
    if row[3] == "__IDOR_ADMIN_NOTES__":
        row = (row[0], row[1], row[2],
               f"INTERNAL: {read_flag('idor_orders')}", row[4])
    return render_template("order.html", order=row, user=current_user())


@app.route("/account/email", methods=["POST"])
def change_email():
    """CSRF: no token, accepts simple form post, no SameSite cookie set strict."""
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    new_email = request.form.get("email", "")
    cur = db().cursor()
    cur.execute("UPDATE users SET email=%s WHERE id=%s", (new_email, user["uid"]))
    if request.headers.get("Origin") and \
       urlparse(request.headers["Origin"]).netloc not in ("localhost:8080", request.host):
        # came from a foreign origin → the CSRF chain succeeded
        return jsonify({"ok": True, "flag": read_flag("csrf")})
    return jsonify({"ok": True})


@app.route("/account/avatar", methods=["POST"])
def upload_avatar():
    """File upload: accepts SVG (XSS via inline JS when served from same origin)
    and weakly checks extension only."""
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    f = request.files.get("avatar")
    if not f:
        abort(400)
    fname = secure_filename(f.filename)
    ext = fname.rsplit(".", 1)[-1].lower()
    if ext not in ("png", "jpg", "jpeg", "gif", "svg"):
        return "bad type", 400
    target_dir = "/tmp/avatars"
    os.makedirs(target_dir, exist_ok=True)
    save_path = os.path.join(target_dir, f"{user['uid']}-{fname}")
    f.save(save_path)
    # Trigger flag if the upload contains <script> (i.e., SVG XSS payload)
    with open(save_path, "rb") as fh:
        data = fh.read()
    flag = ""
    if b"<script" in data.lower() or b"onload=" in data.lower():
        flag = read_flag("file_upload")
    return jsonify({"ok": True, "path": f"/avatars/{user['uid']}-{fname}",
                    "flag": flag})


@app.route("/avatars/<path:fname>")
def serve_avatar(fname):
    return send_from_directory("/tmp/avatars", fname, mimetype=None)


# ---------------------------------------------------------------------------
# Order tracking — blind SQLi
# ---------------------------------------------------------------------------
@app.route("/track")
def track():
    """Blind/time-based SQLi via order_id (concatenated into raw SQL)."""
    oid = request.args.get("order_id", "")
    cur = db().cursor()
    q = f"SELECT status FROM orders WHERE id = {oid or 0}"
    try:
        cur.execute(q)
        row = cur.fetchone()
    except Exception as e:
        return render_template("error.html", error=str(e), query=q), 500
    return render_template("track.html", status=row[0] if row else "unknown",
                           user=current_user())


# ---------------------------------------------------------------------------
# Contact form — SSTI
# ---------------------------------------------------------------------------
@app.route("/contact", methods=["GET", "POST"])
def contact():
    """SSTI (Jinja2). The "preview" feature renders the message with the
    submitter's name interpolated via render_template_string."""
    if request.method == "GET":
        return render_template("contact.html", user=current_user())
    name = request.form.get("name", "anon")
    msg = request.form.get("message", "")
    template = (
        "<h2>Thanks {name}!</h2>"
        "<p>We received your message:</p>"
        "<blockquote>{msg}</blockquote>"
    ).format(name=name, msg="{{ msg|e }}")
    rendered = render_template_string(template, msg=msg)
    flag = ""
    # Heuristic: if the rendered output reveals server flag content via SSTI
    # (e.g., {{config}}, {{ ''.__class__... }}), surface flag.
    if "SECRET_KEY" in rendered or "Config" in rendered or FLAG_DIR in rendered:
        flag = read_flag("ssti_jinja")
    return render_template("contact.html", sent=True, rendered=rendered,
                           flag=flag, user=current_user())


# ---------------------------------------------------------------------------
# Download — path traversal
# ---------------------------------------------------------------------------
@app.route("/download")
def download():
    """Path traversal via ?file= — naive os.path.join with no normalization."""
    fn = request.args.get("file", "")
    base = "/app/static/invoices"
    full = os.path.normpath(os.path.join(base, fn))
    # Vulnerable: doesn't enforce that full starts with base after normpath.
    if not os.path.exists(full):
        return "not found", 404
    try:
        with open(full, "rb") as fh:
            data = fh.read()
    except OSError:
        return "no", 400
    flag = ""
    if FLAG_DIR in full or full.endswith(".flag"):
        flag = read_flag("path_traversal")
    headers = {"Content-Type": "application/octet-stream"}
    if flag:
        headers["X-Flag"] = flag
    return data, 200, headers


# ---------------------------------------------------------------------------
# Webhooks — SSRF
# ---------------------------------------------------------------------------
@app.route("/webhooks/test", methods=["POST"])
def webhooks_test():
    """SSRF: fetches whatever URL the user provides (no allowlist, follows
    redirects, no scheme validation other than http/https/gopher).
    Reach metadata, redis (gopher), or the internal admin panel from here."""
    payload = request.get_json(silent=True) or {}
    url = payload.get("url", "")
    if not url:
        return jsonify({"error": "url required"}), 400
    try:
        # gopher:// path will fall through to requests which will reject it,
        # but we proxy via a manual urllib call for the lab
        if url.startswith("gopher://"):
            # super naive gopher client to enable redis exploitation
            return _gopher_fetch(url)
        r = requests.get(url, timeout=4, allow_redirects=True)
        body = r.text[:4000]
    except Exception as e:
        return jsonify({"error": str(e)}), 502
    flag = ""
    low = body.lower()
    if "ami-id" in low or "iam" in low or "instance-identity" in low:
        flag = read_flag("ssrf_metadata")
    return jsonify({"ok": True, "status": r.status_code, "body": body,
                    "flag": flag})


def _gopher_fetch(url):
    import socket
    p = urlparse(url)
    host = p.hostname
    port = p.port or 70
    # gopher path of form //host:port/_<payload>
    payload = (p.path or "/").split("/", 1)[-1]
    if payload.startswith("_"):
        payload = payload[1:]
    payload = requests.utils.unquote(payload).replace("\r\n", "\r\n")
    s = socket.socket()
    s.settimeout(3)
    s.connect((host, port))
    s.send(payload.encode("latin1", errors="ignore"))
    out = b""
    try:
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            out += chunk
            if len(out) > 8000:
                break
    except socket.timeout:
        pass
    s.close()
    text = out.decode("latin1", errors="replace")
    flag = ""
    if "OK" in text or "+OK" in text:
        flag = read_flag("ssrf_redis")
    return jsonify({"gopher": True, "raw": text, "flag": flag})


# ---------------------------------------------------------------------------
# XML import — XXE
# ---------------------------------------------------------------------------
@app.route("/import/products", methods=["GET", "POST"])
def import_products():
    """XXE: lxml parser configured with resolve_entities=True and
    no_network=False (default-vulnerable)."""
    if request.method == "GET":
        return render_template("import.html", user=current_user())
    raw = request.get_data()
    try:
        parser = etree.XMLParser(resolve_entities=True, no_network=False,
                                 load_dtd=True)
        doc = etree.fromstring(raw, parser=parser)
        text = etree.tostring(doc, pretty_print=True).decode("utf-8", errors="replace")
    except Exception as e:
        return jsonify({"error": str(e)}), 400
    flag = ""
    if "/etc/passwd" in text or "root:" in text or "FLAG{" in text:
        flag = read_flag("xxe_external")
    return jsonify({"parsed": text[:4000], "flag": flag})


# ---------------------------------------------------------------------------
# Open redirect
# ---------------------------------------------------------------------------
@app.route("/redirect")
def open_redirect():
    nxt = request.args.get("next", "/")
    parsed = urlparse(nxt)
    flag = ""
    if parsed.netloc and parsed.netloc != request.host:
        flag = read_flag("open_redirect")
    resp = make_response(redirect(nxt, code=302))
    if flag:
        resp.headers["X-Flag"] = flag
    return resp


# ---------------------------------------------------------------------------
# Checkout — business logic flaws
# ---------------------------------------------------------------------------
@app.route("/checkout", methods=["POST"])
def checkout():
    """Business logic:
       - quantity is trusted from the client (negative qty allowed)
       - coupon stacking: multiple coupons applied additively
       - price field accepted from client (mass-assign-ish)"""
    items = request.json.get("items", [])
    coupons = request.json.get("coupons", [])
    total = 0
    for it in items:
        qty = int(it.get("qty", 1))
        price = int(it.get("price", 0))   # trusted!
        total += qty * price
    discount = 0
    for c in coupons:
        # Each coupon takes 30% — stackable bug
        discount += int(total * 0.3)
    final = total - discount
    flag = ""
    if final <= 0:
        flag = read_flag("business_logic")
    return jsonify({"final_cents": final, "flag": flag})


# ---------------------------------------------------------------------------
# Race-condition coupon redemption
# ---------------------------------------------------------------------------
COUPON_LOCK = threading.Lock()  # NOT used in the vulnerable path on purpose


@app.route("/coupons/redeem", methods=["POST"])
def redeem_coupon():
    """Race condition: read-then-write on Redis without WATCH/atomic."""
    user = current_user()
    code = (request.json or {}).get("code", "")
    if not user or not code:
        return jsonify({"error": "auth/code"}), 400
    key = f"coupon:{code}"
    used_key = f"coupon-used:{code}:{user['uid']}"
    remaining = rds.get(key)
    if remaining is None:
        return jsonify({"error": "no such coupon"}), 404
    remaining = int(remaining)
    # Vulnerable: TOCTOU — if 5 requests land here simultaneously they all
    # see remaining=1 and all proceed.
    if remaining <= 0:
        return jsonify({"error": "exhausted"}), 409
    time.sleep(0.05)  # widen the window
    rds.decr(key)
    rds.sadd(used_key, str(uuid.uuid4()))
    used_count = rds.scard(used_key)
    flag = ""
    if used_count > 1:
        flag = read_flag("race_condition")
    return jsonify({"ok": True, "uses_by_you": used_count, "flag": flag})


# ---------------------------------------------------------------------------
# .env exposure (information disclosure)
# ---------------------------------------------------------------------------
@app.route("/.env")
def dotenv():
    """Returns a fake .env, surfaces the info_disclosure_env flag when read."""
    body = (
        "# DO NOT COMMIT\n"
        f"DATABASE_URL={DATABASE_URL}\n"
        f"SECRET_KEY={SECRET_KEY}\n"
        "AWS_ACCESS_KEY_ID=AKIAEXAMPLEDONOTUSE\n"
        "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
        f"FLAG={read_flag('info_disclosure_env')}\n"
    )
    return body, 200, {"Content-Type": "text/plain"}


# ---------------------------------------------------------------------------
# Clickjacking target — no X-Frame-Options
# ---------------------------------------------------------------------------
@app.route("/clickjack-target", methods=["GET", "POST"])
def clickjack_target():
    if request.method == "POST":
        # If posted via cross-origin iframe (Sec-Fetch-Site=cross-site), award flag
        fetch_site = request.headers.get("Sec-Fetch-Site", "")
        flag = read_flag("clickjacking") if fetch_site == "cross-site" else ""
        return jsonify({"ok": True, "flag": flag})
    return render_template("clickjack.html", user=current_user())


# ---------------------------------------------------------------------------
# Static + utility
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# CSPT-to-CSRF chain
#
# /profile/<id> renders a page that does:
#     fetch("/api/v1/users/" + ID, {method:"POST", credentials:"include",
#                                   body: JSON.stringify({display_name: name})})
# where ID is taken from window.location.pathname.split('/').pop().
#
# Because the JS path-joins without canonicalisation, navigating to
#     /profile/..%2fadmin%2fpromote-self?display_name=foo
# pivots the fetch to /api/v1/admin/promote-self.
# ---------------------------------------------------------------------------
@app.route("/profile/", defaults={"slug": ""})
@app.route("/profile/<path:slug>")
def profile_page(slug):
    return render_template("profile.html", slug=slug, user=current_user())


@app.route("/api/v1/users/<int:uid>", methods=["GET", "POST"])
def api_users(uid):
    user = current_user()
    if not user:
        return jsonify({"error": "auth"}), 401
    if request.method == "POST":
        body = request.get_json(silent=True) or {}
        cur = db().cursor()
        cur.execute("UPDATE users SET display_name=%s WHERE id=%s",
                    (body.get("display_name", ""), uid))
        return jsonify({"ok": True})
    return jsonify({"id": uid})


@app.route("/api/v1/admin/promote-self", methods=["POST"])
def api_admin_promote_self():
    """Same JSON contract as /api/v1/users/<id> on purpose, so the CSPT pivot
    succeeds without changing the request shape."""
    user = current_user()
    if not user:
        return jsonify({"error": "auth"}), 401
    body = request.get_json(silent=True) or {}
    if body.get("display_name") == "promote":
        cur = db().cursor()
        cur.execute("UPDATE users SET role='admin' WHERE id=%s", (user["uid"],))
        return jsonify({"ok": True, "promoted": True,
                        "flag": read_flag("cspt_csrf")})
    return jsonify({"ok": False, "hint": "send display_name=promote"})


# ---------------------------------------------------------------------------
# CSPT-to-XSS chain
#
# /docs/<slug> fetches /api/v1/docs/<slug>/render and innerHTMLs the result.
# Slug is user-controlled and not canonicalised, so an attacker pivots the
# fetch to /api/v1/echo?html=<payload> which echoes raw HTML.
# ---------------------------------------------------------------------------
@app.route("/docs/", defaults={"slug": ""})
@app.route("/docs/<path:slug>")
def docs_page(slug):
    return render_template("docs.html", slug=slug, user=current_user())


@app.route("/api/v1/docs/<path:slug>/render")
def api_docs_render(slug):
    safe = re.sub(r"[^a-zA-Z0-9_-]", "", slug)
    return jsonify({"html": f"<h2>{safe}</h2><p>Help article placeholder.</p>"})


@app.route("/api/v1/echo")
def api_echo():
    """Same JSON shape as /docs render — but reflects raw HTML.  When the
    CSPT chain reroutes the docs fetch here and the resulting HTML contains
    a script tag that fires, the page surfaces the cspt_xss flag."""
    html = request.args.get("html", "")
    return jsonify({"html": html})


@app.route("/api/v1/cspt-xss-callback", methods=["POST"])
def cspt_xss_callback():
    """The XSS payload calls this endpoint to claim its flag."""
    return jsonify({"flag": read_flag("cspt_xss")})


@app.route("/api/v1/xss-callback", methods=["GET", "POST"])
def xss_callback():
    """Generic XSS confirmation endpoint.  Any payload that fires can fetch
    /api/v1/xss-callback?type=reflected|stored|dom to retrieve the flag."""
    kind = request.args.get("type", "reflected")
    if kind not in {"reflected", "stored", "dom"}:
        return jsonify({"error": "type must be one of reflected/stored/dom"}), 400
    return jsonify({"flag": read_flag(f"xss_{kind}")})


@app.route("/healthz")
def healthz():
    return "ok\n"


@app.route("/api/internal/admin-proxy", methods=["GET", "POST"])
def admin_proxy():
    """SSRF gadget: forwards to internal admin if the X-Internal-Token header
    matches.  Used in admin_rce chain — the token leaks via .env / git
    disclosure."""
    if request.headers.get("X-Internal-Token") != "internal-svc-token-do-not-leak":
        return "forbidden", 403
    path = request.args.get("path", "/")
    method = request.method
    r = requests.request(method, f"{ADMIN_INTERNAL_URL}{path}",
                         data=request.get_data(), timeout=5,
                         cookies=request.cookies, allow_redirects=False)
    return r.text, r.status_code, dict(r.headers)


def seed_flags_into_db():
    """Wait for postgres to be available, then push selected flag values into
    `app_secrets` so SQLi UNION attacks return real flag content, and into
    redis (coupons for race-condition challenge)."""
    import socket
    deadline = time.time() + 60
    while time.time() < deadline:
        try:
            conn = psycopg2.connect(DATABASE_URL)
            conn.autocommit = True
            break
        except Exception:
            time.sleep(1)
    else:
        log.error("postgres not reachable for seed")
        return
    cur = conn.cursor()
    cur.execute("DELETE FROM app_secrets WHERE name LIKE 'flag_%'")
    for name in ("sqli_union", "sqli_blind"):
        cur.execute("INSERT INTO app_secrets (name, value) VALUES (%s, %s)",
                    (f"flag_{name}", read_flag(name)))
    cur.close()
    conn.close()
    try:
        rds.set("coupon:LAUNCH50", 1)   # 1 use only — race-condition target
    except Exception as e:
        log.warning("redis seed: %s", e)


if __name__ == "__main__":
    seed_flags_into_db()
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
