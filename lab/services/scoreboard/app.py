"""
Scoreboard for the lab.  Players submit flags they extracted from each
challenge; the board tracks per-team progress.

State is in-memory (resets on container restart) — for a quick CTFd-lite UX.
"""
import os
import time
import hashlib
import threading
from flask import Flask, request, render_template, jsonify, session, redirect, url_for

FLAG_DIR = os.environ.get("FLAG_DIR", "/flags")
SECRET = os.environ.get("SCOREBOARD_SECRET", "dev")

app = Flask(__name__, template_folder="templates")
app.secret_key = SECRET

# challenge id -> (display name, points, category)
CHALLENGES = [
    ("xss_reflected",          "Reflected XSS",                    50, "Core"),
    ("xss_stored",             "Stored XSS in product reviews",    75, "Core"),
    ("xss_dom",                "DOM XSS via fragment",             75, "Core"),
    ("sqli_union",             "UNION-based SQLi",                100, "Core"),
    ("sqli_blind",             "Blind/time-based SQLi",           125, "Core"),
    ("ssti_jinja",             "Jinja2 SSTI",                     150, "Core"),
    ("ssrf_metadata",          "SSRF → cloud metadata",           150, "Cloud"),
    ("ssrf_redis",             "SSRF via gopher → Redis",         200, "Cloud"),
    ("idor_orders",            "IDOR: read another user's order",  75, "Core"),
    ("path_traversal",         "Path traversal in /download",      75, "Core"),
    ("cmd_injection",          "Command injection (admin diag)",  150, "Core"),
    ("file_upload",            "Malicious SVG avatar upload",     100, "Core"),
    ("jwt_confusion",          "JWT alg=none / confusion",        125, "Advanced"),
    ("proto_pollution",        "Prototype pollution",             175, "Advanced"),
    ("cors_reflect",           "CORS Origin reflection",          100, "Advanced"),
    ("graphql_introspect",     "GraphQL field abuse",             100, "Advanced"),
    ("nosql_inject",           "NoSQL operator injection",        125, "Advanced"),
    ("mass_assign",            "Mass assignment (role=admin)",    125, "Advanced"),
    ("open_redirect",          "Open redirect → token theft",      75, "Advanced"),
    ("oauth_takeover",         "OAuth client confusion",          200, "Advanced"),
    ("host_header",            "Host header poisoning",           125, "Advanced"),
    ("cache_poison",           "Web cache poisoning",             175, "Advanced"),
    ("req_smuggle",            "HTTP request smuggling (CL.TE)",  250, "Advanced"),
    ("deser_pickle",           "Python pickle deserialization",   200, "Advanced"),
    ("deser_php",              "PHP unserialize() gadget",        200, "Advanced"),
    ("admin_rce",              "Chain: SSRF → admin → RCE",       300, "Chain"),
    ("business_logic",         "Coupon stacking / negative price",125, "Logic"),
    ("xxe_external",           "XXE external entity",             150, "Core"),
    ("clickjacking",           "Clickjacking",                     50, "Core"),
    ("csrf",                   "CSRF on email change",             75, "Core"),
    ("race_condition",         "Race condition in coupons",       175, "Logic"),
    ("info_disclosure_git",    ".git directory leak",              50, "Core"),
    ("info_disclosure_env",    ".env exposure",                    50, "Core"),
    ("cspt_csrf",              "Client-side path traversal → CSRF",200, "Advanced"),
    ("cspt_xss",               "Client-side path traversal → XSS", 200, "Advanced"),
]

CHAL_BY_ID = {c[0]: c for c in CHALLENGES}
LOCK = threading.Lock()
SCORES = {}  # team -> {chal_id: ts}


def expected_flag(chal_id):
    p = os.path.join(FLAG_DIR, f"{chal_id}.flag")
    try:
        return open(p).read().strip()
    except OSError:
        return None


@app.route("/")
def index():
    team = session.get("team")
    rows = []
    for chal_id, name, pts, cat in CHALLENGES:
        solved = team and chal_id in SCORES.get(team, {})
        rows.append((chal_id, name, pts, cat, solved))
    leaderboard = []
    for t, solved_map in SCORES.items():
        score = sum(CHAL_BY_ID[c][2] for c in solved_map if c in CHAL_BY_ID)
        leaderboard.append((t, score, len(solved_map)))
    leaderboard.sort(key=lambda x: -x[1])
    return render_template("index.html", challenges=rows, team=team,
                           leaderboard=leaderboard)


@app.route("/team", methods=["POST"])
def set_team():
    name = request.form.get("name", "").strip()[:24]
    if not name:
        return redirect(url_for("index"))
    session["team"] = name
    SCORES.setdefault(name, {})
    return redirect(url_for("index"))


@app.route("/submit", methods=["POST"])
def submit():
    team = session.get("team")
    if not team:
        return jsonify({"error": "set team first"}), 400
    chal = request.form.get("chal", "")
    flag = request.form.get("flag", "").strip()
    expected = expected_flag(chal)
    if expected is None:
        return jsonify({"error": "no such challenge"}), 404
    if flag != expected:
        return jsonify({"ok": False, "msg": "incorrect"})
    with LOCK:
        SCORES.setdefault(team, {})[chal] = int(time.time())
    return jsonify({"ok": True, "msg": f"+{CHAL_BY_ID[chal][2]} pts"})


@app.route("/healthz")
def healthz(): return "ok"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8090, threaded=True)
