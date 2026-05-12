CREATE TABLE user_consents (
    id UUID PRIMARY KEY,

    user_id UUID NOT NULL,
    client_id UUID NOT NULL,

    scopes TEXT NOT NULL,

    granted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_consent_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT fk_consent_client FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE,
    CONSTRAINT uq_user_consent UNIQUE (user_id, client_id)
);

CREATE INDEX idx_user_consents_user_id ON user_consents(user_id);
CREATE INDEX idx_user_consents_client_id ON user_consents(client_id);
