-- migration 0007: index cleanup and partial index optimization
-- 1. Remove redundant plain indexes where a UNIQUE index already covers the column
drop index if exists idx_sessions_token_hash;
drop index if exists idx_trusted_devices_token_hash;
drop index if exists idx_sessions_subject_id;
drop index if exists idx_trusted_devices_subject_id;

-- 2. Add partial indexes for active-session queries (revoked_at IS NULL filter)
--    These replace the full idx_sessions_subject_id / idx_trusted_devices_subject_id
--    for the list_sessions / revoke_others hot paths.
create index if not exists idx_sessions_subject_active
    on sessions(subject_id, expires_at)
    where revoked_at is null;

create index if not exists idx_trusted_devices_subject_active
    on trusted_devices(subject_id, expires_at)
    where revoked_at is null;
