resource "keycloak_oidc_identity_provider" "bcsc" {
  realm                         = data.keycloak_realm.bcregistry_realm.id
  alias                         = "bcsc"
  display_name                  = "BC Services Card"
  enabled                       = true
  store_token                   = false
  trust_email                   = false
  hide_on_login_page            = false
  first_broker_login_flow_alias = keycloak_authentication_flow.flow_bcsc_first_broker_login.alias
  sync_mode                     = "FORCE"
  authorization_url             = "${var.keycloak_idp_bcsc.base_url}${var.keycloak_idp_bcsc.auth_path}"
  token_url                     = "${var.keycloak_idp_bcsc.base_url}${var.keycloak_idp_bcsc.token_path}"
  backchannel_supported         = false
  user_info_url                 = "${var.keycloak_idp_bcsc.base_url}${var.keycloak_idp_bcsc.userinfo_path}"
  client_id                     = var.keycloak_idp_bcsc.client_id
  client_secret                 = var.keycloak_idp_bcsc.client_secret
  issuer                        = "${var.keycloak_idp_bcsc.base_url}${var.keycloak_idp_bcsc.issuer_path}"
  default_scopes                = "openid profile"
  validate_signature            = true
  jwks_url                      = "${var.keycloak_idp_bcsc.base_url}${var.keycloak_idp_bcsc.jwks_path}"
  extra_config = {
    "clientAuthMethod" = "client_secret_post"
    "prompt"           = "login"
  }
  depends_on = [
    keycloak_authentication_flow.flow_bcsc_first_broker_login
  ]
}

resource "keycloak_attribute_importer_identity_provider_mapper" "bcs_displayname" {
  realm                   = data.keycloak_realm.bcregistry_realm.id
  name                    = "displayName"
  claim_name              = "display_name"
  identity_provider_alias = keycloak_oidc_identity_provider.bcsc.alias
  user_attribute          = "displayName"
  extra_config = {
    syncMode = "INHERIT"
  }
}

resource "keycloak_attribute_importer_identity_provider_mapper" "bcs_firstname" {
  realm                   = data.keycloak_realm.bcregistry_realm.id
  name                    = "firstName"
  claim_name              = "given_names"
  identity_provider_alias = keycloak_oidc_identity_provider.bcsc.alias
  user_attribute          = "firstName"
  extra_config = {
    syncMode = "INHERIT"
  }
}

resource "keycloak_hardcoded_attribute_identity_provider_mapper" "bcs_loginsource" {
  realm                   = data.keycloak_realm.bcregistry_realm.id
  name                    = "loginSource"
  identity_provider_alias = keycloak_oidc_identity_provider.bcsc.alias
  attribute_name          = "source"
  attribute_value         = "BCSC"
  user_session            = false
  extra_config = {
    syncMode = "INHERIT"
  }
}

resource "keycloak_attribute_importer_identity_provider_mapper" "bcs_lastname" {
  realm                   = data.keycloak_realm.bcregistry_realm.id
  name                    = "lastName"
  claim_name              = "family_name"
  identity_provider_alias = keycloak_oidc_identity_provider.bcsc.alias
  user_attribute          = "lastName"
  extra_config = {
    syncMode = "INHERIT"
  }
}

resource "keycloak_user_template_importer_identity_provider_mapper" "bcs_username" {
  realm                   = data.keycloak_realm.bcregistry_realm.id
  name                    = "username"
  identity_provider_alias = keycloak_oidc_identity_provider.bcsc.alias
  template                = "$${ALIAS}/$${CLAIM.sub}"
  extra_config = {
    syncMode = "INHERIT"
  }
}

resource "keycloak_attribute_importer_identity_provider_mapper" "bcsc_did" {
  realm                   = data.keycloak_realm.bcregistry_realm.id
  name                    = "bcsc_did"
  claim_name              = "sub"
  identity_provider_alias = keycloak_oidc_identity_provider.bcsc.alias
  user_attribute          = "idp_userid"
  extra_config = {
    syncMode = "INHERIT"
  }
}
