CREATE TABLE reset_password_tokens
(
    user_cn    text PRIMARY KEY,
    token      bytea     NOT NULL,
    created_at timestamp NOT NULL
);