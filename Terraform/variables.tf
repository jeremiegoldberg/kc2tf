variable "environment" {
  type = object({
    name     = string
    base_url = string
    realm    = string
  })
  description = "Basic Keycloak environment configuration"

  default = {
    name      = "dev"
    base_url  = "https://dev.loginproxy.gov.bc.ca/auth"
    realm     = "bcregistry"
  }
}

variable "keycloak_terraform_client" {
  type = object({
    id     = string
    secret = string
  })
  sensitive   = true
  description = "The keycloak client and secret used by Terraform to create resources"
}

variable "keycloak_idp_bcsc" {
  type = object({
    base_url      = optional(string, "https://idtest.gov.bc.ca")
    auth_path     = optional(string, "/login/oidc/authorize/")
    token_path    = optional(string, "/oauth2/token")
    userinfo_path = optional(string, "/oauth2/userinfo")
    client_id     = string
    client_secret = string
    issuer_path   = optional(string, "/oauth2/")
    jwks_path     = optional(string, "/oauth2/jwk.json")
  })
  sensitive   = true
  description = "The configuration settings for the BCSC IDP"
}

variable "keycloak_idp_idir_client" {
  type = object({
    id     = string
    secret = string
  })
  sensitive   = true
  description = "The keycloak client and secret used for the IDIR IDP"
}

variable "keycloak_idp_bceid_client" {
  type = object({
    id     = string
    secret = string
  })
  sensitive   = true
  description = "The keycloak client and secret used for the BCeID IDP"
}

variable "keycloak_idp_github_client" {
  type = object({
    id     = string
    secret = string
  })
  sensitive   = true
  description = "The keycloak client and secret used for the GitHub IDP"
}
