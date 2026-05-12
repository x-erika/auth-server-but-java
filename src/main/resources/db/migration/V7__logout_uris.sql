ALTER TABLE clients
    ADD COLUMN frontchannel_logout_uri TEXT,
    ADD COLUMN backchannel_logout_uri TEXT;
