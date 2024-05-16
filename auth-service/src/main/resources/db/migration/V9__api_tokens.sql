CREATE TABLE api_clients
(
    client_id     text NOT NULL,
    client_secret text NOT NULL,
    PRIMARY KEY(client_id)
);

CREATE TABLE api_tokens
(
    token_hash           bytea     NOT NULL UNIQUE,
    created_at           timestamp NOT NULL,
    created_by_user_cn   text      NOT NULL,
    created_by_user_guid text,
    created_by_client_id text      NOT NULL,
    CONSTRAINT fk_client_id FOREIGN KEY(created_by_client_id) REFERENCES api_clients(client_id)
);

CREATE UNIQUE INDEX token_hash_idx ON api_tokens (token_hash)
