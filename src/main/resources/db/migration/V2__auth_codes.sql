CREATE TABLE auth_codes (
    code VARCHAR(255) PRIMARY KEY,

    client_id VARCHAR(255) NOT NULL,
    user_id UUID NOT NULL,
    session_id UUID NOT NULL,

    redirect_uri TEXT NOT NULL,

    scope TEXT,
    state TEXT,
    nonce TEXT,

    code_challenge TEXT,
    code_challenge_method VARCHAR(50),

    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_auth_codes_expires_at ON auth_codes(expires_at);
