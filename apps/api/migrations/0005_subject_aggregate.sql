alter table sessions
    add column if not exists subject_id uuid;

update sessions as se
set subject_id = su.id
from subjects as su
where se.subject_id is null
  and su.identity_id = se.identity_id
  and su.role = se.subject_role;

alter table trusted_devices
    add column if not exists subject_id uuid;

update trusted_devices as td
set subject_id = su.id
from subjects as su
where td.subject_id is null
  and su.identity_id = td.identity_id
  and su.role = td.subject_role;

alter table sessions
    alter column subject_id set not null;

alter table trusted_devices
    alter column subject_id set not null;

do $$
begin
    if not exists (
        select 1
        from pg_constraint
        where conname = 'fk_sessions_subject'
    ) then
        alter table sessions
            add constraint fk_sessions_subject
            foreign key (subject_id) references subjects(id) on delete cascade;
    end if;
end
$$;

do $$
begin
    if not exists (
        select 1
        from pg_constraint
        where conname = 'fk_trusted_devices_subject'
    ) then
        alter table trusted_devices
            add constraint fk_trusted_devices_subject
            foreign key (subject_id) references subjects(id) on delete cascade;
    end if;
end
$$;

create index if not exists idx_sessions_subject_id on sessions(subject_id);
create index if not exists idx_trusted_devices_subject_id on trusted_devices(subject_id);