data "keycloak_realm" "bcregistry_realm" {
  realm = var.environment.realm
}
