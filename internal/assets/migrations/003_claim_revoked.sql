-- +migrate Up
alter table claims add column revoked boolean default false;

-- +migrate Down
alter table claims drop column revoked;