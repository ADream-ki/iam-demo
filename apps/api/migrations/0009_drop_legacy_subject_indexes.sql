-- migration 0009: drop legacy subject_id indexes superseded by partial active indexes
drop index if exists idx_sessions_subject_id;
drop index if exists idx_trusted_devices_subject_id;
