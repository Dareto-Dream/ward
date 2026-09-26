-- Staff level for DeltaVDevs admin tools (Telescreen, Analytics). NULL for everyone
-- else. Apps only see it with the `admin` scope, which only admin tools are allowed.
--   viewer: read-only admin tools    admin: runs things    owner: everything, incl. levels
ALTER TABLE users ADD COLUMN admin_level text
  CONSTRAINT admin_level_known CHECK (admin_level IN ('viewer', 'admin', 'owner'));
