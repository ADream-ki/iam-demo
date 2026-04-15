-- migration 0008: add email_verified_at to identities
-- This column tracks when the identity's email address was first verified
-- via OTP. NULL means the identity was seeded or registered but not yet
-- verified through an OTP flow.
alter table identities
    add column if not exists email_verified_at timestamptz null;
