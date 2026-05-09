# ShopFlux — Bug Bounty Practice Lab

A Dockerised, multi-service web application built for practicing the
techniques in this repository plus harder bug-bounty patterns
(request smuggling, cache poisoning, deserialization, SSRF chains,
OAuth abuse, prototype pollution, JWT confusion, GraphQL, NoSQLi,
business logic flaws, CSPT-to-CSRF/XSS, etc.).

> **Lab use only.** Every service in here is intentionally vulnerable.
> Do **not** expose any of these ports to a network you do not control.

## Quick start

```bash
cd lab
docker compose up --build
```

Once everything is healthy:

| URL                              | What it is                                  |
| -------------------------------- | -------------------------------------------- |
| <http://localhost:8080>          | ShopFlux storefront (via edge nginx)         |
| <http://localhost:8080/api/...>  | ShopFlux API (Node/Express)                  |
| <http://localhost:8081>          | OAuth/OIDC provider                          |
| <http://localhost:8090>          | Scoreboard — submit flags here               |
| <http://localhost:8091>          | Side challenge: HTTP request smuggling       |
| <http://localhost:8092>          | Side challenge: web cache poisoning          |
| <http://localhost:8093>          | Side challenge: pickle deserialization       |

The internal admin panel (`shopflux-admin`), notifications service,
metadata service, redis, and postgres are **not** mapped to host ports —
you reach them via SSRF / smuggling / chained exploitation, exactly like
real bug bounty work.

## Architecture

```
            ┌──────────────────┐
            │  edge (nginx)    │  :8080
            │  • XFH trust     │
            │  • lax cache key │
            │  • CORS reflect  │
            │  • .git / backups│
            └─────┬───────────┘
                  │
    ┌─────────────┼─────────────────────────────────────┐
    ▼             ▼                                     ▼
shopflux-web  shopflux-api                            (everything below
(Flask)       (Express)                                is internal-only)
                                                      ▼
                                       ┌─ shopflux-admin (PHP)
                                       ├─ oauth (Flask)        :8081
                                       ├─ metadata (Flask, IMDS)
                                       ├─ notifications (Node)
                                       ├─ redis
                                       └─ postgres
```

A separate `metadata_net` pins the metadata service at
`169.254.169.254` so SSRF payloads using the AWS IMDS address resolve
naturally inside the network.

## Test accounts

| Role     | Email                       | Password               |
| -------- | --------------------------- | ---------------------- |
| admin    | admin@shopflux.local        | `ShopFlux!Admin#2026`  |
| customer | alice@shopflux.local        | `alice123`             |
| customer | bob@shopflux.local          | `bob123`               |
| vendor   | carol@vendor.local          | `carol123`             |

(The admin password is *findable* via SQLi/info-disclosure — try not to
peek if you're using the lab to practice.)

## Challenge index

The scoreboard at <http://localhost:8090> lists every challenge with its
identifier, category, and point value.  All flags share the format
`FLAG{<32 hex chars>}`.  Flags are mounted read-only inside each
container at `/flags/<challenge>.flag`; the apps surface them in
responses **only after the corresponding exploit succeeds**.

Categories:

- **Core** — XSS (reflected/stored/DOM), SQLi (union/blind), SSTI, IDOR,
  path traversal, command injection, file upload, XXE, CSRF,
  clickjacking, info disclosure (`.git`, `.env`).
- **Advanced** — JWT confusion, prototype pollution, CORS reflection,
  GraphQL field abuse, NoSQL injection, mass assignment, open redirect,
  OAuth client confusion, host header poisoning, cache poisoning,
  request smuggling (CL.TE), Python pickle deserialization, PHP
  unserialize gadget, CSPT→CSRF, CSPT→XSS.
- **Cloud** — SSRF→IMDS metadata, SSRF→Redis (gopher://).
- **Logic** — coupon stacking / negative price, race-condition coupon.
- **Chain** — `admin_rce`: full chain (info disclosure → SSRF → admin
  basic-auth → command injection).

## Suggested workflow (mirrors the repo methodology)

1. **Recon** at <http://localhost:8080>:
    - `robots.txt`, `/.git/`, `/backups/`, `/.env`
    - browser devtools — look for inline JS that takes user-controlled
      values into fetch URLs (CSPT) or DOM sinks (DOM XSS)
    - param fuzzing on `/products`, `/track`, `/search`, `/contact`

2. **Server-side surface** — every method in
   `Phase 4 — Server-side input testing` of the repo's
   `README.md` has a representative endpoint here.

3. **Auth/session** — register, observe the JWT cookie, then attack the
   API at `/api/me` with `alg=none` for `jwt_confusion`.

4. **Egress / SSRF chains** — `POST /webhooks/test` accepts arbitrary
   URLs and follows redirects.  Reach `metadata`, `redis` (gopher),
   `notifications/internal/secrets`, and ultimately the internal
   `shopflux-admin` panel.

5. **Side challenges** — once you have the basics, try the smuggling,
   cache-poisoning, and deserialization labs.

## Tear-down

```bash
docker compose down -v        # drops the postgres volume too
```

## Extending the lab

- Each vulnerable route is a single function in `services/shopflux-web/app.py`
  or `services/shopflux-api/server.js` — easy to clone for new variants.
- New flag files: drop a `<challenge>.flag` in `lab/flags/` and add the
  challenge to `services/scoreboard/app.py` (`CHALLENGES` list).
- Side challenges live under `side-challenges/` — copy a directory,
  edit the `Dockerfile`/`app.py`, and add a service block to
  `docker-compose.yml`.

## Solutions

`SOLUTIONS.md` (gitignored) contains a one-liner walk-through for every
challenge.  Generate it with:

```bash
make -C lab solutions   # if you wire up a Makefile, or just `cat SOLUTIONS.md`
```

Or open it directly — it's stored next to this README on disk but not
committed to the repo so the lab stays useful.
