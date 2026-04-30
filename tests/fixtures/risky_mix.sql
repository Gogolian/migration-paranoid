-- Various risky operations.
ALTER TABLE orders DROP COLUMN legacy_status;
DROP TABLE archived_users;
CREATE INDEX idx_users_email ON users (email);
ALTER TABLE accounts ALTER COLUMN balance TYPE numeric(20, 4);
ALTER TABLE products RENAME COLUMN price TO unit_price;
UPDATE invoices SET status = 'paid';
DELETE FROM sessions;
