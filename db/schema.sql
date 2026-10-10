-- Target PostgreSQL schema (design reference). The MVP API uses an in-memory store behind the same
-- org-scoped access pattern; wiring Postgres is the next step (see docs/adr/0002-in-memory-store-for-mvp.md).
-- Every tenant table carries organization_id and every query must filter by it (optionally enforced with RLS).

CREATE TABLE organization (id text PRIMARY KEY, name text NOT NULL);
CREATE TABLE app_user (id text PRIMARY KEY, organization_id text NOT NULL REFERENCES organization(id), role text NOT NULL
  CHECK (role IN ('viewer','ingestor','analyst','approver','auditor','admin')));

CREATE TABLE event (
  organization_id text NOT NULL REFERENCES organization(id), id text NOT NULL,
  occurred_at timestamptz NOT NULL, source text NOT NULL, type text NOT NULL,
  user_name text, ip inet, resource text, severity text NOT NULL, attrs jsonb NOT NULL DEFAULT '{}',
  PRIMARY KEY (organization_id, id));
CREATE INDEX event_time ON event (organization_id, occurred_at);
CREATE INDEX event_user ON event (organization_id, user_name);
CREATE INDEX event_ip ON event (organization_id, ip);

CREATE TABLE alert (
  organization_id text NOT NULL REFERENCES organization(id), id text NOT NULL, rule_id text NOT NULL, severity text NOT NULL,
  title text NOT NULL, explanation text NOT NULL, subject text NOT NULL, first_seen timestamptz NOT NULL, last_seen timestamptz NOT NULL,
  incident_id text, PRIMARY KEY (organization_id, id));

CREATE TABLE incident (
  organization_id text NOT NULL REFERENCES organization(id), id text NOT NULL, title text NOT NULL, severity text NOT NULL,
  status text NOT NULL CHECK (status IN ('open','triaging','contained','resolved','false_positive')),
  assignee text, labels text[] NOT NULL DEFAULT '{}', link_reasons text[] NOT NULL DEFAULT '{}',
  created_at timestamptz NOT NULL, triaged_at timestamptz, closed_at timestamptz, PRIMARY KEY (organization_id, id));

CREATE TABLE incident_event (
  organization_id text NOT NULL, incident_id text NOT NULL, event_id text NOT NULL,
  PRIMARY KEY (organization_id, incident_id, event_id),
  FOREIGN KEY (organization_id, incident_id) REFERENCES incident(organization_id, id),
  FOREIGN KEY (organization_id, event_id) REFERENCES event(organization_id, id));

CREATE TABLE recommendation (
  organization_id text NOT NULL, id text NOT NULL, incident_id text NOT NULL, kind text NOT NULL, target text NOT NULL,
  rationale text NOT NULL, evidence_event_ids text[] NOT NULL CHECK (cardinality(evidence_event_ids) > 0), PRIMARY KEY (organization_id, id));

CREATE TABLE response_action (
  organization_id text NOT NULL, id text NOT NULL, incident_id text NOT NULL, type text NOT NULL, target text NOT NULL,
  mode text NOT NULL DEFAULT 'simulated' CHECK (mode = 'simulated'),
  status text NOT NULL CHECK (status IN ('pending_approval','executed','rejected')),
  proposed_by text NOT NULL, decided_by text, created_at timestamptz NOT NULL, decided_at timestamptz,
  CHECK (decided_by IS NULL OR decided_by <> proposed_by), PRIMARY KEY (organization_id, id));

-- Append-only, hash-chained audit log: no UPDATE/DELETE for the application role.
CREATE TABLE audit_entry (
  organization_id text NOT NULL, seq bigint NOT NULL, at timestamptz NOT NULL, actor text NOT NULL, role text NOT NULL,
  action text NOT NULL, resource_type text NOT NULL, resource_id text NOT NULL, outcome text NOT NULL, detail text,
  prev_hash text NOT NULL, hash text NOT NULL, PRIMARY KEY (organization_id, seq));
