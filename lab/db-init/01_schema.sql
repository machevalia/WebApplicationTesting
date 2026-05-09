-- ShopFlux DB schema + seed data.

CREATE TABLE users (
    id            SERIAL PRIMARY KEY,
    email         TEXT UNIQUE NOT NULL,
    password_md5  TEXT NOT NULL,                  -- weak hashing on purpose
    role          TEXT NOT NULL DEFAULT 'customer',
    display_name  TEXT,
    created_at    TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE products (
    id          SERIAL PRIMARY KEY,
    name        TEXT NOT NULL,
    description TEXT,
    price       INT NOT NULL,                     -- cents
    image       TEXT,
    category    TEXT,
    sku         TEXT
);

CREATE TABLE reviews (
    id         SERIAL PRIMARY KEY,
    product_id INT REFERENCES products(id),
    author     TEXT,
    body       TEXT,
    created_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE orders (
    id          SERIAL PRIMARY KEY,
    user_id     INT REFERENCES users(id),
    total_cents INT,
    status      TEXT DEFAULT 'pending',
    notes       TEXT,
    created_at  TIMESTAMPTZ DEFAULT now()
);

-- A "secrets" table to make union-based SQLi rewarding.
CREATE TABLE app_secrets (
    id     SERIAL PRIMARY KEY,
    name   TEXT,
    value  TEXT
);

-- Seed users.  Admin credentials are intentionally findable via SQLi.
INSERT INTO users (email, password_md5, role, display_name) VALUES
    ('admin@shopflux.local',
     md5('ShopFlux!Admin#2026'),
     'admin', 'Site Admin'),
    ('alice@shopflux.local', md5('alice123'), 'customer', 'Alice'),
    ('bob@shopflux.local',   md5('bob123'),   'customer', 'Bob'),
    ('carol@vendor.local',   md5('carol123'), 'vendor',   'Carol');

-- Seed products.
INSERT INTO products (name, description, price, image, category, sku) VALUES
    ('Indie Maker Tee', 'Soft cotton, runs small.', 2200,
     '/static/css/placeholder.svg', 'Apparel', 'TEE-001'),
    ('Ceramic Mug',     '12oz handthrown stoneware.', 1800,
     '/static/css/placeholder.svg', 'Home',    'MUG-001'),
    ('Sticker Pack',    'Pack of 10 vinyl stickers.', 600,
     '/static/css/placeholder.svg', 'Goodies', 'STK-001'),
    ('Tote Bag',        'Heavy canvas tote.', 1500,
     '/static/css/placeholder.svg', 'Apparel', 'TOT-001'),
    ('Hoodie',          'Fleece-lined hoodie.', 5800,
     '/static/css/placeholder.svg', 'Apparel', 'HOD-001'),
    ('Notebook',        'Lined dot-grid notebook.', 1200,
     '/static/css/placeholder.svg', 'Goodies', 'NB-001');

-- Order #1 is admin's; the Flask order_detail route will substitute in the
-- IDOR flag when the order belongs to the admin user.
INSERT INTO orders (user_id, total_cents, status, notes) VALUES
    (1, 9999, 'paid', '__IDOR_ADMIN_NOTES__'),
    (2, 2200, 'paid', 'thanks!'),
    (3,  600, 'pending', '');

-- Coupons (race condition challenge uses redis, but keep a record here).
INSERT INTO app_secrets (name, value) VALUES
    ('jwt_signing_key', 'shopflux-super-secret-change-me'),
    ('admin_internal_token', 'internal-svc-token-do-not-leak');

-- Seed a sample review with stored XSS bait.
INSERT INTO reviews (product_id, author, body) VALUES
    (1, 'happy_customer', 'Loved it!'),
    (2, 'mike',           'Good mug.');
