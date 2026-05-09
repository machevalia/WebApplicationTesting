// Internal notifications service.  Stand-in webhook target: emits sensitive
// data on /internal/secrets that an attacker reaches via SSRF.
const fs = require("fs");
const path = require("path");
const express = require("express");

const FLAG_DIR = process.env.FLAG_DIR || "/flags";
const app = express();

app.get("/healthz", (_req, res) => res.send("ok"));

app.get("/internal/secrets", (_req, res) => {
    let flag = "FLAG{missing}";
    try { flag = fs.readFileSync(path.join(FLAG_DIR, "ssrf_metadata.flag"), "utf8").trim(); }
    catch {}
    res.json({
        slack_webhook: "https://hooks.slack.example.com/T0/B0/abcXYZ",
        sentry_dsn: "https://abcd@sentry.example.com/123",
        deploy_key: "-----BEGIN OPENSSH PRIVATE KEY-----\nLAB\n-----END OPENSSH PRIVATE KEY-----",
        flag,
    });
});

app.listen(7000, "0.0.0.0", () => console.log("notifications on 7000"));
