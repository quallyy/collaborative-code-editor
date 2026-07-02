CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE users (
    id           UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    email        VARCHAR(255) UNIQUE NOT NULL,
    username     VARCHAR(30)  UNIQUE NOT NULL,
    password_hash VARCHAR     NOT NULL,
    display_name VARCHAR(50)  NOT NULL,
    avatar_url   VARCHAR(500),
    is_active    BOOLEAN      NOT NULL DEFAULT true,
    is_verified  BOOLEAN      NOT NULL DEFAULT false,
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at   TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_users_email    ON users(email);
CREATE INDEX idx_users_username ON users(username);
