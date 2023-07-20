CREATE TABLE authorization_codes
(
    id         SERIAL PRIMARY KEY,
    username   text      NOT NULL,
    code       text      NOT NULL,
    created_at timestamp NOT NULL
);

CREATE UNIQUE INDEX auth_codes_code ON authorization_codes (code);
CREATE INDEX auth_codes_created_at ON authorization_codes (created_at);
