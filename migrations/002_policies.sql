-- Which Terms / Privacy Policy version each account agreed to, and when.
ALTER TABLE users
  ADD COLUMN terms_version text,
  ADD COLUMN privacy_version text,
  ADD COLUMN policies_accepted_at timestamptz;
