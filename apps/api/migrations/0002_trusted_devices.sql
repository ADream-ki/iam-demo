create table if not exists trusted_devices (
    id uuid primary key,
    identity_id uuid not null references identities(id) on delete cascade,
    subject_role text not null,
    token_hash text not null unique,
    device_name text not null,
    user_agent text,
    ip text,
    expires_at timestamptz not null,
    last_seen_at timestamptz not null,
    created_at timestamptz not null,
    revoked_at timestamptz
);

create index if not exists idx_trusted_devices_identity_role on trusted_devices(identity_id, subject_role);
create index if not exists idx_trusted_devices_token_hash on trusted_devices(token_hash);

delete from password_credentials
where id in (
    select id
    from (
        select id,
               row_number() over (partition by identity_id order by created_at desc, id desc) as row_num
        from password_credentials
    ) ranked
    where ranked.row_num > 1
);

create unique index if not exists ux_password_credentials_identity_id on password_credentials(identity_id);
