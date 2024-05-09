-- +migrate Up
ALTER TABLE claims ADD COLUMN is_banned BOOLEAN NOT NULL DEFAULT FALSE;

-- +migrate Down
ALTER TABLE claims DROP COLUMN is_banned;
