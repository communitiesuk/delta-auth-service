CREATE TABLE api_clients
(
    client_id     text NOT NULL,
    client_secret text NOT NULL,
    UNIQUE (client_id, client_secret)
)

CREATE TABLE api_tokens
(
    token_hash        bytea     NOT NULL,
    created_at        timestamp NOT NULL,
    created_by_user   text      NOT NULL,-- username
    created_by_client text      NOT NULL-- client id
);

/* do we want an index and a way to look up the tokens faster? I don't know how many tokens and what kind of
turnaround speed we're expecting */
