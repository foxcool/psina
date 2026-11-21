-- Modify "users" table
ALTER TABLE "public"."users" ADD COLUMN "credentials_changed_at" timestamptz NULL;
