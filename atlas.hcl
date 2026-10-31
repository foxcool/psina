variable "database_url" {
  type    = string
  default = getenv("PSINA_DB_URL")
}

// schema.hcl is the authoring surface; migrations/ is what instances run.
env "local" {
  src = "file://schema.hcl"
  url = var.database_url
  dev = "docker://postgres/17/psina?search_path=public"
  migration {
    dir = "file://migrations"
  }
}

env "prod" {
  src = "file://schema.hcl"
  url = var.database_url
  migration {
    dir = "file://migrations"
  }
}

env "test" {
  src = "file://schema.hcl"
  url = var.database_url
  migration {
    dir = "file://migrations"
  }
}
