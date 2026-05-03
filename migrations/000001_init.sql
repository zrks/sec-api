create extension if not exists pg_stat_statements;

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
  normalized_domain text,
  status text not null default 'active',
  verified boolean not null default false,
  verification_token text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  last_scan_at timestamptz,
  last_error text,
  unique (domain)
);

create table if not exists scan_runs (
  id uuid primary key,
  domain_id uuid not null references domains(id) on delete cascade,
  status text not null,
  scan_type text not null default 'manual',
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

create table if not exists observation_diffs (
  id uuid primary key,
  domain_id uuid not null references domains(id) on delete cascade,
  scan_run_id uuid not null references scan_runs(id) on delete cascade,
  change_type text not null,
  category text not null,
  subject text not null,
  key text not null,
  old_value jsonb,
  new_value jsonb,
  created_at timestamptz not null default now()
);

create table if not exists findings (
  id uuid primary key,
  scan_run_id uuid not null references scan_runs(id) on delete cascade,
  domain_id uuid not null references domains(id) on delete cascade,
  severity text not null,
  title text not null,
  description text not null,
  recommendation text not null,
  evidence jsonb not null,
  created_at timestamptz not null default now()
);

create table if not exists reports (
  id uuid primary key,
  scan_run_id uuid not null references scan_runs(id) on delete cascade,
  domain_id uuid not null references domains(id) on delete cascade,
  score integer not null,
  data jsonb not null default '{}'::jsonb,
  html_url text,
  pdf_url text,
  emailed_at timestamptz,
  created_at timestamptz not null default now()
);

alter table if exists reports add column if not exists data jsonb not null default '{}'::jsonb;
alter table if exists scan_runs add column if not exists scan_type text not null default 'manual';
alter table if exists domains add column if not exists normalized_domain text;
alter table if exists domains add column if not exists status text not null default 'active';
alter table if exists domains add column if not exists updated_at timestamptz not null default now();
alter table if exists domains add column if not exists last_scan_at timestamptz;
alter table if exists domains add column if not exists last_error text;
update domains set normalized_domain = lower(domain) where normalized_domain is null;
create unique index if not exists domains_normalized_domain_key on domains (normalized_domain);
