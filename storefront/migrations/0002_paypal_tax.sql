ALTER TABLE orders ADD COLUMN tax_cents INTEGER NOT NULL DEFAULT 0 CHECK (tax_cents >= 0);
ALTER TABLE orders ADD COLUMN tax_calculation_id TEXT;
ALTER TABLE orders ADD COLUMN tax_quote_expires_at INTEGER;
ALTER TABLE orders ADD COLUMN tax_transaction_id TEXT;

CREATE INDEX orders_unreported_tax ON orders (tax_quote_expires_at)
    WHERE state = 'paid' AND tax_calculation_id IS NOT NULL AND tax_transaction_id IS NULL;
