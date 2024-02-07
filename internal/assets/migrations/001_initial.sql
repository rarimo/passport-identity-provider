-- +migrate Up
create table proofs(
    id          bigserial primary key,
    data        jsonb not null,
    pub_signals jsonb not null,
    id_card_sod jsonb not null
);

-- +migrate Down
drop table proofs;