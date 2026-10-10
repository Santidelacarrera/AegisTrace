-- Schema actually used by the API's PostgreSQL persistence (api/src/persistence.ts).
-- Domain objects are stored as JSONB documents keyed by (organization_id, collection, id);
-- the audit log is a real append-only table. db/schema.sql is the fully relational target design.
CREATE TABLE IF NOT EXISTS aegis_doc (
  organization_id text  NOT NULL,
  collection      text  NOT NULL,
  id              text  NOT NULL,
  body            jsonb NOT NULL,
  updated_at      timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, collection, id)
);

CREATE TABLE IF NOT EXISTS aegis_audit (
  organization_id text   NOT NULL,
  seq             bigint NOT NULL,
  body            jsonb  NOT NULL,
  PRIMARY KEY (organization_id, seq)
);

-- Recommended hardening for the application role (run as owner after creating role aegis_app):
--   REVOKE UPDATE, DELETE, TRUNCATE ON aegis_audit FROM aegis_app;
