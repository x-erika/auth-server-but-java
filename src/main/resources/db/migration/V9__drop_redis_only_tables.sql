-- auth_codes and device_authorizations are now Redis-only (see AuthCodeStore,
-- DeviceAuthorizationRepository). The Postgres tables have been unused since
-- Phase 1/2 of the Redis migration; drop them to keep the schema honest.
DROP TABLE IF EXISTS auth_codes;
DROP TABLE IF EXISTS device_authorizations;
