// psina database schema
// Declarative schema for Atlas

schema "public" {}

table "users" {
  schema = schema.public

  column "id" {
    type = uuid
    null = false
  }

  column "email" {
    type = varchar(255)
    null = false
  }

  // Opaque role strings emitted in JWT claims and Verify responses.
  // psina stores them without interpretation; authorization stays in the application.
  column "roles" {
    type    = sql("text[]")
    null    = false
    default = sql("'{}'")
  }

  column "created_at" {
    type    = timestamptz
    null    = false
    default = sql("now()")
  }

  column "updated_at" {
    type    = timestamptz
    null    = false
    default = sql("now()")
  }

  primary_key {
    columns = [column.id]
  }

  index "idx_users_email" {
    columns = [column.email]
    unique  = true
  }
}

table "local_credentials" {
  schema = schema.public

  column "user_id" {
    type = uuid
    null = false
  }

  column "password_hash" {
    type = text
    null = false
  }

  column "created_at" {
    type    = timestamptz
    null    = false
    default = sql("now()")
  }

  column "updated_at" {
    type    = timestamptz
    null    = false
    default = sql("now()")
  }

  primary_key {
    columns = [column.user_id]
  }

  foreign_key "fk_user" {
    columns     = [column.user_id]
    ref_columns = [table.users.column.id]
    on_delete   = CASCADE
  }
}

table "refresh_tokens" {
  schema = schema.public

  column "hash" {
    type = varchar(255)
    null = false
  }

  column "user_id" {
    type = uuid
    null = false
  }

  column "parent" {
    type    = varchar(255)
    null    = false
    default = ""
  }

  column "expires_at" {
    type = timestamptz
    null = false
  }

  column "created_at" {
    type    = timestamptz
    null    = false
    default = sql("now()")
  }

  column "revoked" {
    type    = boolean
    null    = false
    default = false
  }

  primary_key {
    columns = [column.hash]
  }

  foreign_key "fk_user" {
    columns     = [column.user_id]
    ref_columns = [table.users.column.id]
    on_delete   = CASCADE
  }

  index "idx_refresh_tokens_user_id" {
    columns = [column.user_id]
  }

  index "idx_refresh_tokens_expires_at" {
    columns = [column.expires_at]
  }

  index "idx_refresh_tokens_parent" {
    columns = [column.parent]
  }
}

table "oauth_identities" {
  schema = schema.public

  column "id" {
    type    = uuid
    null    = false
    default = sql("gen_random_uuid()")
  }

  column "user_id" {
    type = uuid
    null = false
  }

  column "provider" {
    type = varchar(50)
    null = false
  }

  // Provider's stable account id (e.g. OIDC "sub").
  column "external_id" {
    type = varchar(255)
    null = false
  }

  // Email reported by the provider; may differ from users.email.
  column "email" {
    type    = varchar(255)
    null    = false
    default = ""
  }

  column "created_at" {
    type    = timestamptz
    null    = false
    default = sql("now()")
  }

  primary_key {
    columns = [column.id]
  }

  foreign_key "fk_user" {
    columns     = [column.user_id]
    ref_columns = [table.users.column.id]
    on_delete   = CASCADE
  }

  index "idx_oauth_identities_provider_external_id" {
    columns = [column.provider, column.external_id]
    unique  = true
  }

  index "idx_oauth_identities_user_id" {
    columns = [column.user_id]
  }
}

// Single-use, expiring nonces: wallet sign-in challenges and OAuth CSRF state.
// No user FK — challenges are issued before the user is known.
table "auth_challenges" {
  schema = schema.public

  column "nonce" {
    type = varchar(255)
    null = false
  }

  column "message" {
    type    = text
    null    = false
    default = ""
  }

  // Wallet binding; empty for OAuth state.
  column "chain" {
    type    = varchar(50)
    null    = false
    default = ""
  }

  column "address" {
    type    = varchar(255)
    null    = false
    default = ""
  }

  column "expires_at" {
    type = timestamptz
    null = false
  }

  column "created_at" {
    type    = timestamptz
    null    = false
    default = sql("now()")
  }

  primary_key {
    columns = [column.nonce]
  }

  index "idx_auth_challenges_expires_at" {
    columns = [column.expires_at]
  }
}

table "personal_access_tokens" {
  schema = schema.public

  // Public handle for list/revoke; the token hash stays internal.
  column "id" {
    type    = uuid
    null    = false
    default = sql("gen_random_uuid()")
  }

  column "hash" {
    type = varchar(255)
    null = false
  }

  column "user_id" {
    type = uuid
    null = false
  }

  column "name" {
    type    = text
    null    = false
    default = ""
  }

  // scopes are stored for forward-compat; enforcement is not yet implemented.
  column "scopes" {
    type    = sql("text[]")
    null    = false
    default = sql("'{}'")
  }

  // null = token never expires.
  column "expires_at" {
    type = timestamptz
    null = true
  }

  column "last_used_at" {
    type = timestamptz
    null = true
  }

  column "created_at" {
    type    = timestamptz
    null    = false
    default = sql("now()")
  }

  primary_key {
    columns = [column.id]
  }

  foreign_key "fk_user" {
    columns     = [column.user_id]
    ref_columns = [table.users.column.id]
    on_delete   = CASCADE
  }

  index "idx_personal_access_tokens_hash" {
    columns = [column.hash]
    unique  = true
  }

  index "idx_personal_access_tokens_user_id" {
    columns = [column.user_id]
  }
}
