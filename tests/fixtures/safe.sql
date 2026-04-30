-- Safe-ish: add nullable column, batched update with WHERE, concurrent index.
ALTER TABLE users ADD COLUMN nickname text;
UPDATE users SET nickname = 'guest' WHERE nickname IS NULL AND id < 1000;
CREATE INDEX CONCURRENTLY idx_users_nickname ON users (nickname);
