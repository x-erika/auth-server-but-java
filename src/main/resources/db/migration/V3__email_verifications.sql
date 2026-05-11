CREATE TABLE email_verifications (
    id UUID PRIMARY KEY,

    user_id UUID NOT NULL,

    token_hash TEXT UNIQUE NOT NULL,

    expires_at TIMESTAMP NOT NULL,
    consumed_at TIMESTAMP,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_email_verification_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_email_verifications_token_hash ON email_verifications(token_hash);
CREATE INDEX idx_email_verifications_user_id ON email_verifications(user_id);
