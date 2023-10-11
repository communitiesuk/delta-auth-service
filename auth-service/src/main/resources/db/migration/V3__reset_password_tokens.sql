CREATE TABLE reset_password_tokens
(
    user_cn    text PRIMARY KEY,
    token      bytea     NOT NULL,
    created_at timestamp NOT NULL
);

CREATE UNIQUE INDEX reset_password_token_user_cn ON reset_password_tokens (user_cn);