create table if not exists risk_events (
    id uuid primary key,
    event_type text not null,
    credential_type text,
    identity_id uuid references identities(id) on delete set null,
    email text,
    subject_role text,
    ip text,
    user_agent text,
    detail text not null,
    created_at timestamptz not null
);

create index if not exists idx_risk_events_created_at on risk_events(created_at desc);
create index if not exists idx_risk_events_event_type on risk_events(event_type, created_at desc);
create index if not exists idx_risk_events_email_role on risk_events(email, subject_role, created_at desc);