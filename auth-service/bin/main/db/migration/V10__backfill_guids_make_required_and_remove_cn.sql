UPDATE delta_session
SET user_guid = ugm.newguid
FROM user_guid_map ugm
WHERE delta_session.username = ugm.cn
  AND delta_session.user_guid IS NULL;

UPDATE delta_session
SET impersonated_user_guid = ugm.newguid
FROM user_guid_map ugm
WHERE delta_session.impersonated_user_cn IS NOT NULL
  AND delta_session.impersonated_user_cn = ugm.cn
  AND delta_session.impersonated_user_guid IS NULL;

UPDATE authorization_code
SET user_guid = ugm.newguid
FROM user_guid_map ugm
WHERE authorization_code.username = ugm.cn
  AND authorization_code.user_guid IS NULL;

UPDATE reset_password_tokens
SET user_guid = ugm.newguid
FROM user_guid_map ugm
WHERE reset_password_tokens.user_cn = ugm.cn
  AND reset_password_tokens.user_guid IS NULL;

UPDATE set_password_tokens
SET user_guid = ugm.newguid
FROM user_guid_map ugm
WHERE set_password_tokens.user_cn = ugm.cn
  AND set_password_tokens.user_guid IS NULL;

UPDATE user_audit
SET user_guid = ugm.newguid
FROM user_guid_map ugm
WHERE user_audit.user_cn = ugm.cn
  AND user_audit.user_guid IS NULL;

UPDATE user_audit
SET editing_user_guid = ugm.newguid
FROM user_guid_map ugm
WHERE user_audit.editing_user_cn IS NOT NULL
  AND user_audit.editing_user_guid IS NULL
  AND user_audit.editing_user_cn = ugm.cn;

ALTER TABLE delta_session
    ALTER COLUMN user_guid SET NOT NULL;
ALTER TABLE delta_session
    DROP COLUMN username;
ALTER TABLE delta_session
    DROP COLUMN impersonated_user_cn;

ALTER TABLE authorization_code
    ALTER COLUMN user_guid SET NOT NULL;
ALTER TABLE authorization_code
    DROP COLUMN username;

ALTER TABLE reset_password_tokens
    ALTER COLUMN user_guid SET NOT NULL;
ALTER TABLE reset_password_tokens
    DROP CONSTRAINT reset_password_tokens_pkey;
ALTER TABLE reset_password_tokens
    ADD PRIMARY KEY (user_guid);
ALTER TABLE reset_password_tokens
    DROP COLUMN user_cn;

ALTER TABLE set_password_tokens
    ALTER COLUMN user_guid SET NOT NULL;
ALTER TABLE set_password_tokens
    DROP CONSTRAINT set_password_tokens_pkey;
ALTER TABLE set_password_tokens
    ADD PRIMARY KEY (user_guid);
ALTER TABLE set_password_tokens
    DROP COLUMN user_cn;

ALTER TABLE user_audit
    ALTER COLUMN user_guid SET NOT NULL;
DROP INDEX user_audit_user_timestamp;
CREATE INDEX user_audit_user_guid_timestamp ON user_audit (user_guid, timestamp);
ALTER TABLE user_audit
    DROP COLUMN user_cn;
ALTER TABLE user_audit
    DROP COLUMN editing_user_cn;

ALTER TABLE user_guid_map
    DROP COLUMN oldguid;
ALTER TABLE user_guid_map
    RENAME COLUMN newguid TO user_guid;
ALTER TABLE user_guid_map
    RENAME COLUMN cn TO user_cn;
