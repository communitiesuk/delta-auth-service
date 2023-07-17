CREATE TABLE authorization_code
(
    username   text      NOT NULL,
    code_hash  bytea     NOT NULL,
    created_at timestamp NOT NULL,
    trace_id   text      NOT NULL
);

CREATE UNIQUE INDEX auth_code_code ON authorization_code (code_hash);
CREATE INDEX auth_code_created_at ON authorization_code (created_at);

CREATE TABLE delta_session
(
    id              SERIAL PRIMARY KEY,
    username        text      NOT NULL,
    auth_token_hash bytea     NOT NULL,
    created_at      timestamp NOT NULL,
    trace_id        text      NOT NULL
);

CREATE UNIQUE INDEX delta_session_auth_token ON delta_session (auth_token_hash);
CREATE INDEX delta_session_created_at ON delta_session (created_at);
