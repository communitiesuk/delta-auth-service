ALTER TABLE IF EXISTS authorization_code
    ADD COLUMN is_sso boolean NOT NULL DEFAULT FALSE;

ALTER TABLE IF EXISTS delta_session
    ADD COLUMN is_sso boolean NOT NULL DEFAULT FALSE;