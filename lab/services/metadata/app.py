"""
Mock AWS instance metadata service (IMDSv1-style — no token required).

Reachable at http://169.254.169.254/ from inside the metadata_net.
Reach via SSRF from /webhooks/test on the main app, since metadata is
also network-aliased on internal_net.
"""
import os
from flask import Flask, abort

FLAG_DIR = os.environ.get("FLAG_DIR", "/flags")
app = Flask(__name__)


def read_flag(name):
    p = os.path.join(FLAG_DIR, f"{name}.flag")
    return open(p).read().strip() if os.path.exists(p) else f"FLAG{{missing-{name}}}"


CREDS = {
    "Code": "Success",
    "LastUpdated": "2026-05-09T00:00:00Z",
    "Type": "AWS-HMAC",
    "AccessKeyId": "ASIA-LAB-KEY",
    "SecretAccessKey": "lab-secret-do-not-actually-use",
    "Token": "lab-token",
    "Expiration": "2099-01-01T00:00:00Z",
}


@app.route("/")
def root():
    return "latest\n"


@app.route("/latest/")
def latest():
    return "meta-data\ndynamic\nuser-data\n"


@app.route("/latest/meta-data/")
def meta_root():
    return "ami-id\nhostname\niam/\ninstance-id\ninstance-type\n"


@app.route("/latest/meta-data/ami-id")
def ami_id():
    return "ami-0lab2026deadbeef\n"


@app.route("/latest/meta-data/instance-id")
def instance_id():
    return "i-lab2026deadbeef\n"


@app.route("/latest/meta-data/iam/")
def iam_idx():
    return "info\nsecurity-credentials/\n"


@app.route("/latest/meta-data/iam/security-credentials/")
def iam_creds_idx():
    return "shopflux-prod-role\n"


@app.route("/latest/meta-data/iam/security-credentials/<role>")
def iam_creds(role):
    import json
    creds = dict(CREDS)
    creds["FLAG"] = read_flag("ssrf_metadata")
    return json.dumps(creds, indent=2), 200, {"Content-Type": "application/json"}


@app.route("/latest/dynamic/instance-identity/document")
def identity_doc():
    return ('{"region": "us-east-1", "accountId": "123456789012", '
            '"instanceId": "i-lab2026deadbeef"}\n')


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80)
