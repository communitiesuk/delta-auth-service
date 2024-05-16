ALTER TABLE user_audit
    ADD COLUMN user_guid uuid;
ALTER TABLE user_audit
    ADD COLUMN editing_user_guid uuid;
ALTER TABLE authorization_code
    ADD COLUMN user_guid uuid;
ALTER TABLE delta_session
    ADD COLUMN user_guid uuid;
ALTER TABLE delta_session
    ADD COLUMN impersonated_user_guid uuid;
ALTER TABLE reset_password_tokens
    ADD COLUMN user_guid uuid;
ALTER TABLE set_password_tokens
    ADD COLUMN user_guid uuid;
