CREATE TABLE password_resets (
    id UUID PRIMARY KEY,

    user_id UUID NOT NULL,

    token_hash TEXT UNIQUE NOT NULL,

    expires_at TIMESTAMP NOT NULL,
    consumed_at TIMESTAMP,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_password_reset_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_password_resets_token_hash ON password_resets(token_hash);
CREATE INDEX idx_password_resets_user_id ON password_resets(user_id);
