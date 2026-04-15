create table if not exists identities (
    id uuid primary key,
    email text not null unique,
    created_at timestamptz not null,
    updated_at timestamptz not null
);

create table if not exists subjects (
    id uuid primary key,
    identity_id uuid not null references identities(id) on delete cascade,
    role text not null,
    display_name text not null,
    totp_secret text,
    created_at timestamptz not null,
    unique(identity_id, role)
);

create table if not exists password_credentials (
    id uuid primary key,
    identity_id uuid not null references identities(id) on delete cascade,
    password_hash text not null,
    created_at timestamptz not null
);

create table if not exists passkey_credentials (
    id uuid primary key,
    subject_id uuid not null references subjects(id) on delete cascade,
    external_id text not null unique,
    label text not null,
    verifier_data text not null,
    created_at timestamptz not null
);

create table if not exists sessions (
    id uuid primary key,
    identity_id uuid not null references identities(id) on delete cascade,
    subject_role text not null,
    token_hash text not null unique,
    device_name text not null,
    user_agent text,
    ip text,
    mfa_level text not null,
    remember_device boolean not null default false,
    expires_at timestamptz not null,
    last_seen_at timestamptz not null,
    created_at timestamptz not null,
    revoked_at timestamptz
);

create index if not exists idx_sessions_identity_role on sessions(identity_id, subject_role);
create index if not exists idx_sessions_token_hash on sessions(token_hash);
