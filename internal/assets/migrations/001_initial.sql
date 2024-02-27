-- +migrate Up
create table claims(
    id            uuid primary key,
    user_did      text not null,
    issuer_did    text not null,
    document_hash text not null
);

-- +migrate Down
drop table claims;