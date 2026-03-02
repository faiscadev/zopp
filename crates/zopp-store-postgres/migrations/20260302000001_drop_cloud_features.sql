-- Drop cloud features: organizations, billing, and related infrastructure
-- This migration reverses 20260126000001_add_organizations.sql and 20260126000002_add_billing.sql

-- Drop tables in FK order (children before parents)
-- CASCADE automatically handles triggers, indexes, and FK constraints
DROP TABLE IF EXISTS payments CASCADE;
DROP TABLE IF EXISTS subscriptions CASCADE;
DROP TABLE IF EXISTS organization_settings CASCADE;
DROP TABLE IF EXISTS organization_invites CASCADE;
DROP TABLE IF EXISTS organization_members CASCADE;

-- Drop organization_id column from workspaces
ALTER TABLE workspaces DROP COLUMN IF EXISTS organization_id;

-- Drop organizations table last (parent)
DROP TABLE IF EXISTS organizations CASCADE;
