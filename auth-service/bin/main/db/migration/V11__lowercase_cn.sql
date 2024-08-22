ALTER TABLE user_guid_map
    ADD COLUMN lowercase_user_cn text NOT NULL GENERATED ALWAYS AS (LOWER(user_cn)) STORED;

CREATE UNIQUE INDEX user_guid_map_lowercase_cn ON user_guid_map (lowercase_user_cn);
