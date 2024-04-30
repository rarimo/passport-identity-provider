-- +migrate Up
ALTER TABLE claims
    RENAME COLUMN document_hash TO nullifier;

ALTER TABLE claims
    ADD COLUMN document_hash TEXT NOT NULL DEFAULT '',
    ADD COLUMN salt          TEXT NOT NULL DEFAULT '';

-- +migrate Down
ALTER TABLE claims
    DROP COLUMN document_hash;

ALTER TABLE claims
    RENAME COLUMN nullifier TO document_hash;
