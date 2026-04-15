do $$
begin
    if not exists (
        select 1
        from pg_constraint
        where conname = 'uq_subjects_id_identity_role'
    ) then
        alter table subjects
            add constraint uq_subjects_id_identity_role
            unique (id, identity_id, role);
    end if;
end
$$;

do $$
begin
    if not exists (
        select 1
        from pg_constraint
        where conname = 'fk_sessions_subject_denorm_consistency'
    ) then
        alter table sessions
            add constraint fk_sessions_subject_denorm_consistency
            foreign key (subject_id, identity_id, subject_role)
            references subjects(id, identity_id, role)
            on delete cascade;
    end if;
end
$$;

do $$
begin
    if not exists (
        select 1
        from pg_constraint
        where conname = 'fk_trusted_devices_subject_denorm_consistency'
    ) then
        alter table trusted_devices
            add constraint fk_trusted_devices_subject_denorm_consistency
            foreign key (subject_id, identity_id, subject_role)
            references subjects(id, identity_id, role)
            on delete cascade;
    end if;
end
$$;