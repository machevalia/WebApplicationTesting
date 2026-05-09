"""
Insecure deserialization challenge (Python pickle).

A "remember me" cookie is base64(pickle(dict(...))) and the server calls
pickle.loads on it without integrity checking.  Classic gadget chain via
__reduce__ gives RCE; here we award the flag if a marker file is created
in /tmp by the gadget.
"""
import os
import base64
import pickle
import subprocess
from flask import Flask, request, jsonify, make_response

FLAG_DIR = os.environ.get("FLAG_DIR", "/flags")
MARKER = "/tmp/pwn_marker"
app = Flask(__name__)


def read_flag(name):
    p = os.path.join(FLAG_DIR, f"{name}.flag")
    return open(p).read().strip() if os.path.exists(p) else f"FLAG{{missing-{name}}}"


@app.route("/")
def index():
    return ("<h1>Remember-me service</h1>"
            "<p>POST /login then send the issued cookie back. The server"
            " trusts the cookie and pickle.loads() it.</p>"
            "<p>To win: trigger pickle RCE that creates "
            f"<code>{MARKER}</code>, then GET /flag.</p>")


@app.route("/login", methods=["POST"])
def login():
    user = (request.json or {}).get("user", "guest")
    cookie = base64.b64encode(pickle.dumps({"user": user})).decode()
    resp = make_response(jsonify({"ok": True, "cookie": cookie}))
    resp.set_cookie("rememberme", cookie)
    return resp


@app.route("/me")
def me():
    cookie = request.cookies.get("rememberme") or request.args.get("c", "")
    if not cookie:
        return jsonify({"error": "no cookie"}), 400
    try:
        data = pickle.loads(base64.b64decode(cookie))   # <-- vulnerable
    except Exception as e:
        return jsonify({"error": str(e)}), 400
    return jsonify({"data": str(data)})


@app.route("/flag")
def flag():
    if os.path.exists(MARKER):
        return read_flag("deser_pickle")
    return "marker not present yet — exploit /me first.", 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8093)
