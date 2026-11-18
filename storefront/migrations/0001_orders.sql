CREATE TABLE orders (
    access_hash TEXT PRIMARY KEY,
    provider TEXT NOT NULL CHECK (provider IN ('stripe', 'paypal', 'venmo')),
    provider_id TEXT NOT NULL UNIQUE,
    payment_id TEXT UNIQUE,
    cents INTEGER NOT NULL CHECK (cents > 0),
    release_key TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'paid', 'revoked')),
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
);

-- Record reversals even if the order's checkout event has yet to arrive.
CREATE TABLE reversals (
    payment_id TEXT PRIMARY KEY
);
