CREATE TABLE users (
    id UUID PRIMARY KEY,

    email VARCHAR(255) UNIQUE NOT NULL,
    email_verified BOOLEAN DEFAULT FALSE,

    username VARCHAR(255) UNIQUE NOT NULL,

    first_name VARCHAR(255),
    last_name VARCHAR(255),

    enabled BOOLEAN DEFAULT TRUE,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_username ON users(username);

CREATE TABLE credentials (
    id UUID PRIMARY KEY,

    type VARCHAR(50) NOT NULL,

    secret_data TEXT,
    credential_data TEXT,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    user_id UUID NOT NULL,

    CONSTRAINT fk_credentials_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_credentials_user_id ON credentials(user_id);

CREATE TABLE roles (
    id UUID PRIMARY KEY,

    name VARCHAR(100) UNIQUE NOT NULL,
    description TEXT,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE user_roles (
    user_id UUID NOT NULL,
    role_id UUID NOT NULL,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_user_roles_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,

    CONSTRAINT fk_user_roles_role FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,

    CONSTRAINT pk_user_roles PRIMARY KEY (user_id, role_id)
);

CREATE INDEX idx_user_roles_role_id ON user_roles(role_id);

CREATE TABLE user_sessions (
    id UUID PRIMARY KEY,

    user_id UUID NOT NULL,

    session_token TEXT UNIQUE NOT NULL,

    ip_address VARCHAR(100),
    user_agent TEXT,

    expires_at TIMESTAMP,
    last_accessed_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_session_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_user_sessions_user_id ON user_sessions(user_id);
CREATE INDEX idx_user_sessions_expires_at ON user_sessions(expires_at);

CREATE TABLE clients (
    id UUID PRIMARY KEY,

    client_id VARCHAR(255) UNIQUE NOT NULL,
    client_secret TEXT,

    name VARCHAR(255),

    type VARCHAR(50) CHECK (type IN ('confidential', 'public')),

    grant_types TEXT,
    response_types TEXT,
    scopes TEXT,

    pkce_required BOOLEAN DEFAULT TRUE,

    enabled BOOLEAN DEFAULT TRUE,
    base_url TEXT,
    description TEXT,

    access_token_ttl INT,
    refresh_token_ttl INT,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_clients_client_id ON clients(client_id);

CREATE TABLE redirect_uris (
    id UUID PRIMARY KEY,

    client_id UUID NOT NULL,
    uri TEXT NOT NULL,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_redirect_client FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE,

    CONSTRAINT uq_client_uri UNIQUE (client_id, uri)
);

CREATE INDEX idx_redirect_uris_client_id ON redirect_uris(client_id);

CREATE TABLE refresh_tokens (
    id UUID PRIMARY KEY,

    user_id UUID NOT NULL,
    client_id UUID NOT NULL,
    session_id UUID NOT NULL,

    token_hash TEXT UNIQUE NOT NULL,

    expires_at TIMESTAMP,
    revoked BOOLEAN DEFAULT FALSE,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_refresh_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,

    CONSTRAINT fk_refresh_client FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE,

    CONSTRAINT fk_refresh_session FOREIGN KEY (session_id) REFERENCES user_sessions(id) ON DELETE CASCADE
);

CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens(user_id);
CREATE INDEX idx_refresh_tokens_session_id ON refresh_tokens(session_id);
CREATE INDEX idx_refresh_tokens_expires_at ON refresh_tokens(expires_at);