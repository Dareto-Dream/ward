-- Resource servers: a client may introspect other clients' access tokens, but
-- only tokens carrying one of these scopes (e.g. DeltaTime for `deltatime`).
ALTER TABLE clients ADD COLUMN resource_scopes text[] NOT NULL DEFAULT '{}';
