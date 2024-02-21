CREATE TABLE user_guid_map
(
    cn      text NOT NULL PRIMARY KEY,
    oldGuid text NOT NULL,
    newGuid uuid NOT NULL UNIQUE
);
