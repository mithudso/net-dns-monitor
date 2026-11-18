ALTER TABLE orders ADD COLUMN stripe_price_id TEXT;
ALTER TABLE orders ADD COLUMN stripe_customer_id TEXT;
ALTER TABLE orders ADD COLUMN buyer_use TEXT CHECK (buyer_use IN ('personal', 'business'));
