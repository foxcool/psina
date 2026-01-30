variable "database_url" {
  type    = string
  default = getenv("PSINA_DB_URL")
}

env "local" {
  src = "file://schema.hcl"
  url = var.database_url
  dev = "docker://postgres/17/psina?search_path=public"
}

env "prod" {
  src = "file://schema.hcl"
  url = var.database_url
}
