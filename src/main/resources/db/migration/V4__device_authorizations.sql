CREATE TABLE device_authorizations (
    id UUID PRIMARY KEY,

    device_code VARCHAR(255) UNIQUE NOT NULL,
    user_code VARCHAR(20) UNIQUE NOT NULL,

    client_id VARCHAR(255) NOT NULL,
    scope TEXT,

    status VARCHAR(20) NOT NULL DEFAULT 'pending',

    user_id UUID,
    session_id UUID,

    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_device_auth_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT fk_device_auth_session FOREIGN KEY (session_id) REFERENCES user_sessions(id) ON DELETE CASCADE
);

CREATE INDEX idx_device_authorizations_user_code ON device_authorizations(user_code);
CREATE INDEX idx_device_authorizations_status ON device_authorizations(status);
CREATE INDEX idx_device_authorizations_expires_at ON device_authorizations(expires_at);
