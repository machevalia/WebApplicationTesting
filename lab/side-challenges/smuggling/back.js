// Tiny backend that reads HTTP requests with default Node parser, which
// gives Transfer-Encoding precedence over Content-Length when both are
// present — the classic CL.TE smuggling pattern.
//
// Endpoints:
//   GET /              landing
//   GET /admin         only honored if request came on a "smuggled" connection,
//                      i.e. the request was tucked inside another body.
//   POST /search       echoes back the body so you can confirm the smuggling
//                      effect end-to-end.
//
// The flag is awarded when /admin is hit with header X-Smuggled: 1
// (the smuggling primitive lets you forge that header from a connection
// already authenticated by the front-end's keep-alive pool).

const fs = require("fs");
const http = require("http");
const path = require("path");

const FLAG_DIR = process.env.FLAG_DIR || "/flags";
const FLAG = (() => {
    try { return fs.readFileSync(path.join(FLAG_DIR, "req_smuggle.flag"), "utf8").trim(); }
    catch { return "FLAG{missing-req_smuggle}"; }
})();

const server = http.createServer((req, res) => {
    let body = "";
    req.on("data", c => body += c);
    req.on("end", () => {
        if (req.url === "/" || req.url === "/index.html") {
            res.writeHead(200, {"Content-Type": "text/html"});
            return res.end(`<!doctype html><title>SmugLab</title>
            <h1>SmugLab</h1>
            <p>This site has only public endpoints.  /admin is restricted.</p>
            <form action=/search method=post>
              <input name=q><button>Search</button>
            </form>`);
        }
        if (req.url === "/admin") {
            if (req.headers["x-smuggled"] === "1") {
                res.writeHead(200, {"Content-Type": "text/plain"});
                return res.end(`Smuggle successful — ${FLAG}\n`);
            }
            res.writeHead(403);
            return res.end("forbidden");
        }
        if (req.url === "/search") {
            res.writeHead(200, {"Content-Type": "text/plain"});
            return res.end(`echo: ${body}\n`);
        }
        res.writeHead(404).end("nope");
    });
});

server.listen(8000, "127.0.0.1", () => console.log("smuggle backend :8000"));
