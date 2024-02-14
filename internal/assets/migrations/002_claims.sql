-- +migrate Up
alter table proofs add column claim_id uuid;

create table claims(
    id         uuid primary key,
    user_did   text not null,
    issuer_did text not null,
    document   text not null unique
);

-- +migrate Down
alter table proofs drop column claim_id;
drop table claims;