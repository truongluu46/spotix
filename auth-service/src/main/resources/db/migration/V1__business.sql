CREATE TABLE users (
    id uuid PRIMARY KEY,
    email varchar(254) NOT NULL UNIQUE,
    password_hash varchar(255) NOT NULL,
    display_name varchar(100) NOT NULL,
    role varchar(10) NOT NULL CHECK (role IN ('USER', 'ADMIN')),
    enabled boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK (email = lower(btrim(email)))
);
