-- Drop cloud features: organizations, billing, and related infrastructure
-- This migration reverses 20260126000001_add_organizations.sql and 20260126000002_add_billing.sql

-- Drop triggers first
DROP TRIGGER IF EXISTS subscriptions_updated_at;
DROP TRIGGER IF EXISTS organization_settings_updated_at;
DROP TRIGGER IF EXISTS organizations_updated_at;

-- Drop indexes
DROP INDEX IF EXISTS idx_payments_created_at;
DROP INDEX IF EXISTS idx_payments_organization;
DROP INDEX IF EXISTS idx_subscriptions_stripe_id;
DROP INDEX IF EXISTS idx_subscriptions_organization;
DROP INDEX IF EXISTS idx_organization_invites_email;
DROP INDEX IF EXISTS idx_workspaces_organization;
DROP INDEX IF EXISTS idx_organization_members_user;

-- Drop tables in FK order (children before parents)
DROP TABLE IF EXISTS payments;
DROP TABLE IF EXISTS subscriptions;
DROP TABLE IF EXISTS organization_settings;
DROP TABLE IF EXISTS organization_invites;
DROP TABLE IF EXISTS organization_members;
DROP TABLE IF EXISTS organizations;

-- Drop organization_id column from workspaces (supported in SQLite 3.35.0+)
ALTER TABLE workspaces DROP COLUMN organization_id;
