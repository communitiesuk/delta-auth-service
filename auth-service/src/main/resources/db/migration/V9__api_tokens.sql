CREATE TABLE api_tokens
(
    token      bytea     NOT NULL,-- varchar? since it's a string
    created_at timestamp NOT NULL,
    created_by_user varchar(255) NOT NULL,-- username
    created_by_client varchar(255) NOT NULL-- client id
);

/* do we want an index and a way to look up the tokens faster? I don't know how many tokens and what kind of
turnaround speed we're expecting */
