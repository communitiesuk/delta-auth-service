ALTER TABLE authorization_code
    ADD COLUMN is_sso boolean NOT NULL DEFAULT FALSE;

ALTER TABLE delta_session
    ADD COLUMN is_sso boolean NOT NULL DEFAULT FALSE;