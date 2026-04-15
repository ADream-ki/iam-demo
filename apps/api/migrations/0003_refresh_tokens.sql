alter table sessions
    add column if not exists refresh_token_hash text,
    add column if not exists access_expires_at timestamptz;

update sessions
set refresh_token_hash = token_hash
where refresh_token_hash is null;

update sessions
set access_expires_at = expires_at
where access_expires_at is null;

alter table sessions
    alter column refresh_token_hash set not null,
    alter column access_expires_at set not null;

create unique index if not exists idx_sessions_refresh_token_hash on sessions(refresh_token_hash);
create index if not exists idx_sessions_access_expires_at on sessions(access_expires_at);
