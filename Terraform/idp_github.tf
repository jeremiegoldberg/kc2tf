resource "keycloak_oidc_identity_provider" "github" {
  realm                         = data.keycloak_realm.bcregistry_realm.id
  alias                         = "github"
  display_name                  = "GitHub"
  enabled                       = true
  store_token                   = false
  trust_email                   = false
  first_broker_login_flow_alias = "first broker login"
  sync_mode                     = "FORCE"
  authorization_url             = "${var.environment.base_url}/realms/standard/protocol/openid-connect/auth?kc_idp_hint=githubbcgov"
  token_url                     = "${var.environment.base_url}/realms/standard/protocol/openid-connect/token"
  logout_url                    = "${var.environment.base_url}/realms/standard/protocol/openid-connect/logout"
  backchannel_supported         = true
  user_info_url                 = "${var.environment.base_url}/realms/standard/protocol/openid-connect/userinfo"
  client_id                     = var.keycloak_idp_github_client.id
  client_secret                 = var.keycloak_idp_github_client.secret
  issuer                        = "${var.environment.base_url}/realms/standard"
  validate_signature            = true
  default_scopes                = ""

  jwks_url = "${var.environment.base_url}/realms/standard/protocol/openid-connect/certs"
  extra_config = {
    "clientAuthMethod" = "client_secret_post"
    "prompt"           = "unspecified"
  }
}

resource "keycloak_attribute_importer_identity_provider_mapper" "github_displayname" {
  realm                   = data.keycloak_realm.bcregistry_realm.id
  name                    = "displayName"
  claim_name              = "display_name"
  identity_provider_alias = keycloak_oidc_identity_provider.github.alias
  user_attribute          = "displayName"
  extra_config = {
    syncMode = "FORCE"
  }
}

resource "keycloak_user_template_importer_identity_provider_mapper" "github_username_importer" {
  realm                   = data.keycloak_realm.bcregistry_realm.id
  name                    = "username"
  identity_provider_alias = keycloak_oidc_identity_provider.github.alias
  template                = "$${CLAIM.github_username}@$${ALIAS}"
  extra_config = {
    syncMode = "FORCE"
  }
}
