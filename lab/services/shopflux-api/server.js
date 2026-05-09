/*
 * ShopFlux API service.
 *
 * Vulnerabilities:
 *   - JWT confusion: accepts alg=none AND HS256 signed with public key value
 *   - Prototype pollution in PATCH /users/:id (recursive merge)
 *   - Mass assignment on PATCH /users/:id (role can be set by client)
 *   - GraphQL introspection enabled + admin field accessible to any auth user
 *   - NoSQL-style injection on POST /login (in-memory mongo-ish store)
 *   - CORS reflection of arbitrary Origin with credentials (compounded by edge)
 *
 * Flag retrieval pattern: when a route detects successful exploitation it
 * surfaces the flag value via response body / header.
 */

const fs        = require("fs");
const path      = require("path");
const express   = require("express");
const cookies   = require("cookie-parser");
const jwt       = require("jsonwebtoken");
const morgan    = require("morgan");
const { graphqlHTTP } = require("express-graphql");
const { buildSchema, GraphQLSchema, GraphQLObjectType,
        GraphQLString, GraphQLList } = require("graphql");

const PORT       = 3000;
const SECRET     = process.env.JWT_SECRET || "shopflux-super-secret-change-me";
const FLAG_DIR   = process.env.FLAG_DIR || "/flags";
const INT_TOKEN  = process.env.INTERNAL_TOKEN || "internal-svc-token-do-not-leak";

const readFlag = (name) => {
    try { return fs.readFileSync(path.join(FLAG_DIR, `${name}.flag`), "utf8").trim(); }
    catch { return `FLAG{missing-${name}}`; }
};

const app = express();
app.use(morgan("dev"));
app.use(express.json({ limit: "1mb" }));
app.use(cookies());

// In-memory user store (NoSQL-ish — accepts $-operators in login).
const users = [
    { id: 1, email: "admin@shopflux.local", password: "ShopFlux!Admin#2026",
      role: "admin",   tokens: ["int-debug-7c2a"] },
    { id: 2, email: "alice@shopflux.local", password: "alice123",
      role: "customer" },
    { id: 3, email: "bob@shopflux.local",   password: "bob123",
      role: "customer" },
];

// -------------------------------------------------------------------------
// JWT auth — deliberately permissive
// -------------------------------------------------------------------------
function authUser(req) {
    const h = req.get("Authorization") || "";
    const m = h.match(/^Bearer (.+)$/);
    if (!m) return null;
    const token = m[1];
    const parts = token.split(".");
    if (parts.length !== 3) return null;
    let header;
    try { header = JSON.parse(Buffer.from(parts[0], "base64url").toString()); }
    catch { return null; }
    // Vulnerable: trust the header's alg value
    if (header.alg === "none") {
        try { return JSON.parse(Buffer.from(parts[1], "base64url").toString()); }
        catch { return null; }
    }
    try { return jwt.verify(token, SECRET, { algorithms: ["HS256", "none"] }); }
    catch { return null; }
}

// -------------------------------------------------------------------------
// CORS reflection (compounds the edge nginx rule) — verifies via callback.
// -------------------------------------------------------------------------
app.use((req, res, next) => {
    const origin = req.get("Origin");
    if (origin) {
        res.set("Access-Control-Allow-Origin", origin);
        res.set("Access-Control-Allow-Credentials", "true");
        res.set("Vary", "Origin");
    }
    if (req.method === "OPTIONS") {
        res.set("Access-Control-Allow-Headers", "Content-Type, Authorization");
        res.set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS");
        return res.status(204).end();
    }
    next();
});

// -------------------------------------------------------------------------
// Login — NoSQL-style injection
// -------------------------------------------------------------------------
app.post("/login", (req, res) => {
    const { email, password } = req.body || {};
    // Vulnerable: allow object operators ({"$ne": null})
    const matches = users.filter(u => {
        const emailOk = (typeof email === "object" && email !== null)
                          ? !Object.is(u.email, email.$ne)
                          : u.email === email;
        const pwOk    = (typeof password === "object" && password !== null)
                          ? !Object.is(u.password, password.$ne)
                          : u.password === password;
        return emailOk && pwOk;
    });
    if (!matches.length) return res.status(401).json({ error: "invalid" });
    const u = matches[0];
    const token = jwt.sign({ uid: u.id, email: u.email, role: u.role },
                           SECRET, { algorithm: "HS256" });
    let flag = "";
    if (typeof email === "object" || typeof password === "object") {
        flag = readFlag("nosql_inject");
    }
    res.json({ token, role: u.role, flag });
});

// -------------------------------------------------------------------------
// Mass assignment + prototype pollution
// -------------------------------------------------------------------------
function deepMerge(dst, src) {           // <-- vulnerable recursive merge
    for (const k of Object.keys(src)) {
        if (src[k] && typeof src[k] === "object") {
            if (!dst[k] || typeof dst[k] !== "object") dst[k] = {};
            deepMerge(dst[k], src[k]);
        } else {
            dst[k] = src[k];
        }
    }
    return dst;
}

app.patch("/users/:id", (req, res) => {
    const me = authUser(req);
    if (!me) return res.status(401).json({ error: "auth" });
    const id = parseInt(req.params.id, 10);
    const u  = users.find(x => x.id === id);
    if (!u) return res.status(404).json({ error: "no user" });
    if (me.uid !== id && me.role !== "admin") {
        return res.status(403).json({ error: "forbidden" });
    }

    deepMerge(u, req.body || {});         // mass assignment + proto pollution

    let flag = "";
    if ({}.polluted) flag = readFlag("proto_pollution");
    else if (u.role === "admin" && me.uid === id && me.role !== "admin") {
        flag = readFlag("mass_assign");
    }
    res.json({ ok: true, user: u, flag });
});

app.get("/users/:id", (req, res) => {
    const id = parseInt(req.params.id, 10);
    const u = users.find(x => x.id === id);
    if (!u) return res.status(404).json({ error: "no user" });
    const { password, ...safe } = u;
    res.json(safe);
});

// -------------------------------------------------------------------------
// JWT-confusion confirmation endpoint
// -------------------------------------------------------------------------
app.get("/me", (req, res) => {
    const me = authUser(req);
    if (!me) return res.status(401).json({ error: "auth" });
    let flag = "";
    // If the token was minted with alg=none and is an admin, that's the
    // jwt_confusion challenge.
    const h = req.get("Authorization") || "";
    const tok = h.replace(/^Bearer /, "");
    try {
        const hdr = JSON.parse(Buffer.from(tok.split(".")[0], "base64url").toString());
        if (hdr.alg === "none" && me.role === "admin") {
            flag = readFlag("jwt_confusion");
        }
    } catch {}
    res.json({ user: me, flag });
});

// -------------------------------------------------------------------------
// CORS-reflection confirmation: returns sensitive data + flag if cross-origin
// -------------------------------------------------------------------------
app.get("/account/sensitive", (req, res) => {
    const me = authUser(req);
    if (!me) return res.status(401).json({ error: "auth" });
    const origin = req.get("Origin");
    let flag = "";
    if (origin && !/^https?:\/\/(localhost(:\d+)?|shopflux\.local)$/.test(origin)) {
        flag = readFlag("cors_reflect");
    }
    res.json({ email: me.email, role: me.role, flag });
});

// -------------------------------------------------------------------------
// GraphQL — introspection on, role check missing on `internalSecrets`
// -------------------------------------------------------------------------
const InternalSecretType = new GraphQLObjectType({
    name: "InternalSecret",
    fields: {
        name:  { type: GraphQLString },
        value: { type: GraphQLString },
    },
});

const QueryType = new GraphQLObjectType({
    name: "Query",
    fields: {
        ping: {
            type: GraphQLString,
            resolve: () => "pong",
        },
        me: {
            type: new GraphQLObjectType({
                name: "Me",
                fields: { email: {type:GraphQLString}, role:{type:GraphQLString} }
            }),
            resolve: (_, __, ctx) => ctx.user || null,
        },
        // --- broken access: any authenticated user can read ---
        internalSecrets: {
            type: new GraphQLList(InternalSecretType),
            resolve: (_, __, ctx) => {
                if (!ctx.user) return null;
                return [
                    { name: "internal_token", value: INT_TOKEN },
                    { name: "graphql_flag",   value: readFlag("graphql_introspect") },
                ];
            },
        },
    },
});

app.use("/graphql", graphqlHTTP((req) => ({
    schema: new GraphQLSchema({ query: QueryType }),
    graphiql: true,
    context: { user: authUser(req) },
})));

// -------------------------------------------------------------------------
// healthz
// -------------------------------------------------------------------------
app.get("/healthz", (_req, res) => res.send("ok"));

app.listen(PORT, "0.0.0.0", () => console.log(`shopflux-api listening on ${PORT}`));
