-- +goose Up
CREATE TABLE users (
    id UUID PRIMARY KEY,
    password TEXT not null,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    is_chirpy_red boolean not null DEFAULT false,
    email TEXT UNIQUE NOT NULL
);

CREATE TABLE chirps (
    id UUID PRIMARY KEY,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    body TEXT NOT NULL,
    user_id UUID NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);
CREATE TABLE refresh_tokens (
    token TEXT PRIMARY KEY,                     -- The unique token string
    created_at TIMESTAMP NOT NULL DEFAULT now(), -- When the token was created
    updated_at TIMESTAMP NOT NULL DEFAULT now(), -- Last update time for the token
    user_id UUID NOT NULL,                      -- User to whom the token belongs
    expires_at TIMESTAMP NOT NULL,              -- Expiry time of the token
    revoked_at TIMESTAMP,                       -- When the token was revoked (NULL if active)
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE -- Enforce user-token relationship
);



-- +goose Down
DROP TABLE refresh_tokens;
DROP Table chirps;
DROP TABLE users;