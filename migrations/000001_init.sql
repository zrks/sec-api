create table if not exists organizations (
  id uuid primary key,
  name text not null,
  created_at timestamptz not null default now()
);

create table if not exists domains (
  id uuid primary key,
  -- organization_id is optional in the MVP; if provided it may reference organizations(id)
  organization_id uuid,
  domain text not null,
  verified boolean not null default false,
  verification_token text,
  created_at timestamptz not null default now(),
  unique (domain)
);

create table if not exists scan_runs (
  id uuid primary key,
  domain_id uuid not null references domains(id) on delete cascade,
  status text not null,
  started_at timestamptz not null default now(),
  finished_at timestamptz,
  error text
);

create table if not exists observations (
  id uuid primary key,
  scan_run_id uuid not null references scan_runs(id) on delete cascade,
  domain_id uuid not null references domains(id) on delete cascade,
  category text not null,
  subject text not null,
  key text not null,
  value jsonb not null,
  observed_at timestamptz not null default now()
);

create table if not exists reports (
  id uuid primary key,
  scan_run_id uuid not null references scan_runs(id) on delete cascade,
  domain_id uuid not null references domains(id) on delete cascade,
  score integer not null,
  html_url text,
  pdf_url text,
  emailed_at timestamptz,
  created_at timestamptz not null default now()
);