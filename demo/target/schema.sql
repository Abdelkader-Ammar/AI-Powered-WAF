-- Demo schema (DEMO ONLY). Seeded fixtures so runs are deterministic.
CREATE TABLE IF NOT EXISTS products (
    id   SERIAL PRIMARY KEY,
    name TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    id       SERIAL PRIMARY KEY,
    username TEXT NOT NULL,
    password TEXT NOT NULL          -- demo only; never store plaintext for real
);

-- A "secrets" table the product flow must never read (authorization demo).
CREATE TABLE IF NOT EXISTS secrets (
    id    SERIAL PRIMARY KEY,
    name  TEXT,
    value TEXT
);

INSERT INTO products (name) VALUES
    ('Quantum Mug'), ('Recursive Notebook'), ('Null Pointer Plush'),
    ('Segfault Socks'), ('Heisenbug Hoodie')
ON CONFLICT DO NOTHING;

INSERT INTO users (username, password) VALUES
    ('alice', 'correct horse'), ('bob', 'hunter2')
ON CONFLICT DO NOTHING;

INSERT INTO secrets (name, value) VALUES
    ('api_key', 'demo-secret-do-not-exfiltrate')
ON CONFLICT DO NOTHING;
