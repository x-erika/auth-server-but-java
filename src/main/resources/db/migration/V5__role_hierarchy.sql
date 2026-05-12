ALTER TABLE roles
    ADD COLUMN parent_id UUID,
    ADD CONSTRAINT fk_role_parent FOREIGN KEY (parent_id) REFERENCES roles(id) ON DELETE SET NULL;

CREATE INDEX idx_roles_parent_id ON roles(parent_id);
