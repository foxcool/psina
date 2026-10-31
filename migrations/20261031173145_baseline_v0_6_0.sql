-- Create "auth_challenges" table
CREATE TABLE "public"."auth_challenges" (
  "nonce" character varying(255) NOT NULL,
  "message" text NOT NULL DEFAULT '',
  "chain" character varying(50) NOT NULL DEFAULT '',
  "address" character varying(255) NOT NULL DEFAULT '',
  "code_verifier" text NOT NULL DEFAULT '',
  "oauth_nonce" text NOT NULL DEFAULT '',
  "binding_hash" character varying(64) NOT NULL DEFAULT '',
  "expires_at" timestamptz NOT NULL,
  "created_at" timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY ("nonce")
);
-- Create index "idx_auth_challenges_expires_at" to table: "auth_challenges"
CREATE INDEX "idx_auth_challenges_expires_at" ON "public"."auth_challenges" ("expires_at");
-- Create "users" table
CREATE TABLE "public"."users" (
  "id" uuid NOT NULL,
  "email" character varying(255) NULL,
  "roles" text[] NOT NULL DEFAULT '{}',
  "created_at" timestamptz NOT NULL DEFAULT now(),
  "updated_at" timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY ("id")
);
-- Create index "idx_users_email" to table: "users"
CREATE UNIQUE INDEX "idx_users_email" ON "public"."users" ("email") WHERE (email IS NOT NULL);
-- Create "local_credentials" table
CREATE TABLE "public"."local_credentials" (
  "user_id" uuid NOT NULL,
  "password_hash" text NOT NULL,
  "created_at" timestamptz NOT NULL DEFAULT now(),
  "updated_at" timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY ("user_id"),
  CONSTRAINT "fk_user" FOREIGN KEY ("user_id") REFERENCES "public"."users" ("id") ON UPDATE NO ACTION ON DELETE CASCADE
);
-- Create "oauth_identities" table
CREATE TABLE "public"."oauth_identities" (
  "id" uuid NOT NULL DEFAULT gen_random_uuid(),
  "user_id" uuid NOT NULL,
  "provider" character varying(50) NOT NULL,
  "external_id" character varying(255) NOT NULL,
  "email" character varying(255) NOT NULL DEFAULT '',
  "created_at" timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY ("id"),
  CONSTRAINT "fk_user" FOREIGN KEY ("user_id") REFERENCES "public"."users" ("id") ON UPDATE NO ACTION ON DELETE CASCADE
);
-- Create index "idx_oauth_identities_provider_external_id" to table: "oauth_identities"
CREATE UNIQUE INDEX "idx_oauth_identities_provider_external_id" ON "public"."oauth_identities" ("provider", "external_id");
-- Create index "idx_oauth_identities_user_id" to table: "oauth_identities"
CREATE INDEX "idx_oauth_identities_user_id" ON "public"."oauth_identities" ("user_id");
-- Create "personal_access_tokens" table
CREATE TABLE "public"."personal_access_tokens" (
  "id" uuid NOT NULL DEFAULT gen_random_uuid(),
  "hash" character varying(255) NOT NULL,
  "user_id" uuid NOT NULL,
  "name" text NOT NULL DEFAULT '',
  "scopes" text[] NOT NULL DEFAULT '{}',
  "expires_at" timestamptz NULL,
  "last_used_at" timestamptz NULL,
  "created_at" timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY ("id"),
  CONSTRAINT "fk_user" FOREIGN KEY ("user_id") REFERENCES "public"."users" ("id") ON UPDATE NO ACTION ON DELETE CASCADE
);
-- Create index "idx_personal_access_tokens_hash" to table: "personal_access_tokens"
CREATE UNIQUE INDEX "idx_personal_access_tokens_hash" ON "public"."personal_access_tokens" ("hash");
-- Create index "idx_personal_access_tokens_user_id" to table: "personal_access_tokens"
CREATE INDEX "idx_personal_access_tokens_user_id" ON "public"."personal_access_tokens" ("user_id");
-- Create "refresh_tokens" table
CREATE TABLE "public"."refresh_tokens" (
  "hash" character varying(255) NOT NULL,
  "user_id" uuid NOT NULL,
  "parent" character varying(255) NOT NULL DEFAULT '',
  "expires_at" timestamptz NOT NULL,
  "created_at" timestamptz NOT NULL DEFAULT now(),
  "revoked" boolean NOT NULL DEFAULT false,
  "rotated_at" timestamptz NULL,
  "ended_at" timestamptz NULL,
  PRIMARY KEY ("hash"),
  CONSTRAINT "fk_user" FOREIGN KEY ("user_id") REFERENCES "public"."users" ("id") ON UPDATE NO ACTION ON DELETE CASCADE
);
-- Create index "idx_refresh_tokens_expires_at" to table: "refresh_tokens"
CREATE INDEX "idx_refresh_tokens_expires_at" ON "public"."refresh_tokens" ("expires_at");
-- Create index "idx_refresh_tokens_parent" to table: "refresh_tokens"
CREATE INDEX "idx_refresh_tokens_parent" ON "public"."refresh_tokens" ("parent");
-- Create index "idx_refresh_tokens_user_id" to table: "refresh_tokens"
CREATE INDEX "idx_refresh_tokens_user_id" ON "public"."refresh_tokens" ("user_id");
-- Create "wallet_identities" table
CREATE TABLE "public"."wallet_identities" (
  "id" uuid NOT NULL DEFAULT gen_random_uuid(),
  "user_id" uuid NOT NULL,
  "chain" character varying(50) NOT NULL,
  "address" character varying(255) NOT NULL,
  "created_at" timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY ("id"),
  CONSTRAINT "fk_user" FOREIGN KEY ("user_id") REFERENCES "public"."users" ("id") ON UPDATE NO ACTION ON DELETE CASCADE
);
-- Create index "idx_wallet_identities_chain_address" to table: "wallet_identities"
CREATE UNIQUE INDEX "idx_wallet_identities_chain_address" ON "public"."wallet_identities" ("chain", "address");
-- Create index "idx_wallet_identities_user_id" to table: "wallet_identities"
CREATE INDEX "idx_wallet_identities_user_id" ON "public"."wallet_identities" ("user_id");
