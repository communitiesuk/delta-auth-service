CREATE TABLE user_audit
(
    action          text      NOT NULL,
    timestamp       timestamp NOT NULL,
    user_cn         text      NOT NULL,
    editing_user_cn text,
    request_id      text      NOT NULL,
    action_data     jsonb     NOT NULL
);

CREATE INDEX user_audit_user_timestamp ON user_audit (user_cn, timestamp);
