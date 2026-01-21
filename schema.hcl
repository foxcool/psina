// psina database schema
// Declarative schema for Atlas

schema "public" {}

table "users" {
  schema = schema.public

  column "id" {
    type = varchar(255)
    null = false
  }

  column "email" {
    type = varchar(255)
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
    type = varchar(255)
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
    type = varchar(255)
    null = false
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
}
