CREATE TABLE set_password_tokens
(
    user_cn    text PRIMARY KEY,
    token      bytea     NOT NULL,
    created_at timestamp NOT NULL
);

CREATE INDEX set_password_token ON set_password_tokens (token);
CREATE UNIQUE INDEX set_password_token_user_cn ON set_password_tokens (user_cn);