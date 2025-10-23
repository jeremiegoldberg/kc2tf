
    #!/usr/bin/env python3
"""
Script pour transformer un export Keycloak en code Terraform
Provider: keycloak/keycloak
Version: 1.0.0
"""

import json
import os
import sys
import argparse
from typing import Dict, List, Any, Optional
import urllib3

# Désactiver les warnings SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class KeycloakToTerraform:
    """Classe principale pour la conversion Keycloak vers Terraform"""
    
    def __init__(self, debug: bool = False):
        self.debug = debug
        self.realm_data = None
        self.output_dir = "terraform_output"
        
        # Objets automatiquement créés par Keycloak (ne pas recréer pour éviter les erreurs 409)
        # Basé sur l'analyse du fichier realm-export.json du realm master
        self.auto_created_objects = {
            # Clients par défaut créés automatiquement
            'default_clients': [
                'account', 'account-console', 'admin-cli', 'broker', 
                'master-realm', 'security-admin-console'
            ],
            
            # Rôles par défaut créés automatiquement
            'default_roles': [
                'create-realm', 'default-roles-master', 'uma_authorization', 
                'offline_access', 'admin'
            ],
            
            # Groupes par défaut créés automatiquement
            'default_groups': [
            ],
            
            # Scopes OpenID Connect par défaut créés automatiquement
            'default_oidc_scopes': [
                'roles', 'acr', 'offline_access', 'email', 'microprofile-jwt',
                'address', 'service_account', 'phone', 'web-origins', 
                'organization', 'profile', 'basic'
            ],
            
            # Scopes SAML par défaut créés automatiquement
            'default_saml_scopes': [
                'saml_organization', 'role_list'
            ],
            
            # Flows d'authentification par défaut créés automatiquement
            'default_flows': [
                # Flows principaux (topLevel: true, builtIn: true)
                'browser', 'clients', 'direct grant', 'docker auth', 
                'first broker login', 'registration', 'reset credentials', 'saml ecp',
                
                # Subflows (topLevel: false, builtIn: true)
                'Account verification options', 'Browser - Conditional 2FA',
                'Direct Grant - Conditional OTP', 'First broker login - Conditional 2FA',
                'Handle Existing Account', 'Reset - Conditional OTP',
                'User creation or linking', 'Verify Existing Account by Re-authentication',
                'forms', 'registration form',
                
                # Variantes communes
                'browser-conditional-otp', 'browser_conditional_otp', 'browser conditional otp',
                'direct-grant-conditional-otp', 'direct_grant_conditional_otp', 'direct grant conditional otp',
                'first-broker-login-conditional-otp', 'first_broker_login_conditional_otp', 'first broker login conditional otp',
                'reset-conditional-otp', 'reset_conditional_otp', 'reset conditional otp',
                'browser-conditional-2fa', 'browser_conditional_2fa', 'browser conditional 2fa',
                'first-broker-login-conditional-2fa', 'first_broker_login_conditional_2fa', 'first broker login conditional 2fa'
            ],
            
            # Configurations d'authenticateurs par défaut créées automatiquement
            'default_authenticator_configs': [
                'browser-conditional-credential', 'create unique user config',
                'first-broker-login-conditional-credential', 'review profile config'
            ],
            
            # Mappers par défaut créés automatiquement
            'default_mappers': [
                'Client ID', 'Client IP Address', 'Client Host'
            ],
            
            # Groupes d'utilisateurs publics créés automatiquement
            'public_user_groups': [
                'account_holders', 'public_users'
            ]
        }
        
    def log_debug(self, message: str):
        """Affiche un message de debug si le mode debug est activé"""
        if self.debug:
            print(f"[DEBUG] {message}")
    
    def is_auto_created_object(self, name: str, object_type: str) -> bool:
        """Vérifie si un objet est automatiquement créé par Keycloak"""
        if not name or not object_type:
            return False
        
        # Nettoyer le nom pour la comparaison
        clean_name = name.lower().strip()
        
        if object_type == 'client':
            return clean_name in [c.lower() for c in self.auto_created_objects['default_clients']]
        elif object_type == 'role':
            # Vérifier les rôles par défaut
            if clean_name in [r.lower() for r in self.auto_created_objects['default_roles']]:
                return True
            
            # Vérifier le pattern default-roles-{realm_name}
            if self.realm_data and 'realm' in self.realm_data:
                realm_name = self.realm_data['realm'].lower()
                if clean_name == f'default-roles-{realm_name}':
                    return True
            
            return False
        elif object_type == 'group':
            return clean_name in [g.lower() for g in self.auto_created_objects['default_groups']]
        elif object_type == 'scope':
            # Vérifier les scopes OpenID Connect par défaut
            if clean_name in [s.lower() for s in self.auto_created_objects['default_oidc_scopes']]:
                return True
            # Vérifier les scopes SAML par défaut
            if clean_name in [s.lower() for s in self.auto_created_objects['default_saml_scopes']]:
                return True
            return False
        elif object_type == 'flow':
            return clean_name in [f.lower() for f in self.auto_created_objects['default_flows']]
        elif object_type == 'authenticator_config':
            return clean_name in [a.lower() for a in self.auto_created_objects['default_authenticator_configs']]
        elif object_type == 'mapper':
            return clean_name in [m.lower() for m in self.auto_created_objects['default_mappers']]
        elif object_type == 'public_group':
            return clean_name in [g.lower() for g in self.auto_created_objects['public_user_groups']]
        
        return False
    
    def clean_resource_name(self, name):
        """Nettoie un nom pour qu'il soit valide comme nom de ressource Terraform"""
        # Remplacer les caractères non valides par des underscores
        import re
        cleaned = re.sub(r'[^a-zA-Z0-9_]', '_', name)
        # S'assurer que le nom commence par une lettre
        if cleaned and not cleaned[0].isalpha():
            cleaned = 'r_' + cleaned
        return cleaned
    
    def replace_variables(self, content):
        """Remplace les variables ${variable} par leurs valeurs dans le contenu"""
        import re
        
        # Chercher toutes les variables ${variable}
        variables = re.findall(r'\$\{([^}]+)\}', content)
        
        for variable in variables:
            # Déterminer le type de variable et sa valeur
            if variable.startswith('role_'):
                # Variable de rôle
                role_name = variable[5:]  # Enlever 'role_'
                # Chercher le rôle correspondant dans les données
                if self.realm_data and 'roles' in self.realm_data and 'realm' in self.realm_data['roles']:
                    for role in self.realm_data['roles']['realm']:
                        if role.get('name') == role_name:
                            # Remplacer par la référence Terraform
                            role_resource_name = self.clean_resource_name(role_name)
                            replacement = f'keycloak_role.{role_resource_name}.id'
                            content = content.replace(f'${{{variable}}}', replacement)
                            break
                    else:
                        # Rôle non trouvé, remplacer par une chaîne vide
                        content = content.replace(f'${{{variable}}}', '')
                else:
                    content = content.replace(f'${{{variable}}}', '')
            
            elif variable.startswith('client_'):
                # Variable de client
                client_id = variable[7:]  # Enlever 'client_'
                # Chercher le client correspondant dans les données
                if self.realm_data and 'clients' in self.realm_data:
                    for client in self.realm_data['clients']:
                        if client.get('clientId') == client_id:
                            # Remplacer par la référence Terraform
                            client_resource_name = client_id.replace('-', '_').replace(' ', '_')
                            replacement = f'keycloak_openid_client.{client_resource_name}.id'
                            content = content.replace(f'${{{variable}}}', replacement)
                            break
                    else:
                        # Client non trouvé, remplacer par une chaîne vide
                        content = content.replace(f'${{{variable}}}', '')
                else:
                    content = content.replace(f'${{{variable}}}', '')
            
            elif variable.startswith('group_'):
                # Variable de groupe
                group_name = variable[6:]  # Enlever 'group_'
                # Chercher le groupe correspondant dans les données
                if self.realm_data and 'groups' in self.realm_data:
                    for group in self.realm_data['groups']:
                        if group.get('name') == group_name:
                            # Remplacer par la référence Terraform
                            group_path = group.get('path', f'/{group_name}')
                            group_resource_name = group_path.replace('/', '_').replace('-', '_').replace(' ', '_').lstrip('_')
                            replacement = f'keycloak_group.{group_resource_name}.id'
                            content = content.replace(f'${{{variable}}}', replacement)
                            break
                    else:
                        # Groupe non trouvé, remplacer par une chaîne vide
                        content = content.replace(f'${{{variable}}}', '')
                else:
                    content = content.replace(f'${{{variable}}}', '')
            
            elif variable.startswith('user_'):
                # Variable d'utilisateur
                username = variable[5:]  # Enlever 'user_'
                # Chercher l'utilisateur correspondant dans les données
                if self.realm_data and 'users' in self.realm_data:
                    for user in self.realm_data['users']:
                        if user.get('username') == username:
                            # Remplacer par la référence Terraform
                            user_resource_name = username.replace('@', '_').replace('.', '_').replace('-', '_').replace(' ', '_')
                            replacement = f'keycloak_user.{user_resource_name}.id'
                            content = content.replace(f'${{{variable}}}', replacement)
                            break
                    else:
                        # Utilisateur non trouvé, remplacer par une chaîne vide
                        content = content.replace(f'${{{variable}}}', '')
                else:
                    content = content.replace(f'${{{variable}}}', '')
            
            elif variable.startswith('scope_'):
                # Variable de scope
                scope_name = variable[6:]  # Enlever 'scope_'
                # Vérifier si c'est un scope SAML builtin
                if scope_name in self.auto_created_objects['default_saml_scopes']:
                    # Scope SAML builtin - remplacer par la valeur directe
                    content = content.replace(f'${{{variable}}}', scope_name)
                else:
                    # Chercher le scope correspondant dans les données
                    if self.realm_data and 'clientScopes' in self.realm_data:
                        for scope in self.realm_data['clientScopes']:
                            if scope.get('name') == scope_name:
                                # Déterminer le type de scope
                                protocol = scope.get('protocol', 'openid-connect')
                                scope_resource_name = scope_name.replace('@', '_').replace('.', '_').replace('-', '_').replace(' ', '_')
                                if protocol == 'openid-connect':
                                    replacement = f'keycloak_openid_client_scope.{scope_resource_name}.id'
                                elif protocol == 'saml':
                                    replacement = f'keycloak_saml_client_scope.{scope_resource_name}.id'
                                else:
                                    replacement = scope_name
                                content = content.replace(f'${{{variable}}}', replacement)
                                break
                        else:
                            # Scope non trouvé, remplacer par la valeur directe
                            content = content.replace(f'${{{variable}}}', scope_name)
                    else:
                        # Pas de scopes, remplacer par la valeur directe
                        content = content.replace(f'${{{variable}}}', scope_name)
            
            else:
                # Variable inconnue, remplacer par une chaîne vide
                content = content.replace(f'${{{variable}}}', '')
        
        return content
    
    def get_realm_resource_name(self):
        """Retourne le nom de ressource nettoyé du realm"""
        if not self.realm_data:
            return ""
        realm = self.realm_data.get('realm', '')
        return self.clean_resource_name(realm)
    
    def load_realm_export(self, file_path: str) -> Dict[str, Any]:
        """Charge l'export Keycloak depuis un fichier JSON"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                self.realm_data = json.load(f)
            self.log_debug(f"Export Keycloak chargé depuis {file_path}")
            return self.realm_data
        except FileNotFoundError:
            print(f"Erreur: Fichier {file_path} non trouvé")
            sys.exit(1)
        except json.JSONDecodeError as e:
            print(f"Erreur: Fichier JSON invalide - {e}")
            sys.exit(1)
    
    def create_output_directory(self):
        """Crée le répertoire de sortie s'il n'existe pas"""
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
            self.log_debug(f"Répertoire {self.output_dir} créé")
    
    def generate_terraform_provider(self):
        """Génère la configuration du provider Terraform"""
        provider_config = f'''terraform {{
  required_providers {{
    keycloak = {{
      source  = "keycloak/keycloak"
      version = "~> 4.0"
    }}
  }}
}}

# Configuration du provider Keycloak
# Remplacez les valeurs par vos paramètres de connexion
provider "keycloak" {{
  client_id = "admin-cli"
  username  = "admin"  # Remplacez par votre nom d'utilisateur
  password  = "password"  # Remplacez par votre mot de passe
  url       = "https://keycloak.example.com"  # Remplacez par votre URL Keycloak
}}
'''
        return provider_config
    
    def generate_realm_config(self) -> str:
        """Génère la configuration du realm"""
        if not self.realm_data:
            return ""
        
        realm = self.realm_data.get('realm', '')
        display_name = self.realm_data.get('displayName', realm)
        enabled = self.realm_data.get('enabled', True)
        
        # Nettoyer le nom du realm pour le nom de ressource
        realm_resource_name = self.get_realm_resource_name()
        
        config = f'''resource "keycloak_realm" "{realm_resource_name}" {{
  realm                = "{realm}"
  display_name         = "{display_name}"
  enabled              = {str(enabled).lower()}
}}
'''
        return config
    
    def generate_clients_config(self) -> str:
        """Génère la configuration des clients"""
        if not self.realm_data or 'clients' not in self.realm_data:
            return ""
        
        config = ""
        clients = self.realm_data['clients']
        
        for client in clients:
            client_id = client.get('clientId', '')
            
            # Vérifier si c'est un client automatiquement créé par Keycloak
            if self.is_auto_created_object(client_id, 'client'):
                self.log_debug(f"Client '{client_id}' ignoré (créé automatiquement par Keycloak)")
                continue
            
            name = client.get('name', '')
            # S'assurer que le nom n'est pas vide
            if not name or name.strip() == '':
                name = client_id
            enabled = client.get('enabled', True)
            client_authenticator_type = client.get('clientAuthenticatorType', 'client-secret')
            standard_flow_enabled = client.get('standardFlowEnabled', False)
            implicit_flow_enabled = client.get('implicitFlowEnabled', False)
            direct_access_grants_enabled = client.get('directAccessGrantsEnabled', False)
            service_accounts_enabled = client.get('serviceAccountsEnabled', False)
            public_client = client.get('publicClient', False)
            bearer_only = client.get('bearerOnly', False)
            
            # URLs de redirection
            redirect_uris = client.get('redirectUris', [])
            web_origins = client.get('webOrigins', [])
            admin_url = client.get('adminUrl', '')
            base_url = client.get('baseUrl', '')
            root_url = client.get('rootUrl', '')
            
            # Rôles par défaut
            default_client_scopes = client.get('defaultClientScopes', [])
            optional_client_scopes = client.get('optionalClientScopes', [])
            
            # Déterminer le type d'accès basé sur les attributs du client
            if bearer_only:
                access_type = "BEARER-ONLY"
            elif public_client:
                access_type = "PUBLIC"
            else:
                access_type = "CONFIDENTIAL"
            
            # Générer le nom de ressource client de manière cohérente
            client_resource_name = client_id.replace('-', '_').replace(' ', '_')
            
            config += f'''
resource "keycloak_openid_client" "{client_resource_name}" {{
        realm_id                     = keycloak_realm.{self.get_realm_resource_name()}.id
  client_id                    = "{client_id}"
  name                         = "{name}"
  enabled                      = {str(enabled).lower()}
  access_type                  = "{access_type}"
  standard_flow_enabled        = {str(standard_flow_enabled).lower()}
  implicit_flow_enabled        = {str(implicit_flow_enabled).lower()}
  direct_access_grants_enabled = {str(direct_access_grants_enabled).lower()}
  service_accounts_enabled     = {str(service_accounts_enabled).lower()}
'''
            
            # Ne générer valid_redirect_uris que si standard_flow ou implicit_flow est activé
            if redirect_uris and (standard_flow_enabled or implicit_flow_enabled):
                config += f'  valid_redirect_uris = {json.dumps(redirect_uris)}\n'
            
            # Ne générer web_origins que si standard_flow ou implicit_flow est activé
            if web_origins and (standard_flow_enabled or implicit_flow_enabled):
                config += f'  web_origins = {json.dumps(web_origins)}\n'
            
            # Gestion des attributs ACR to LOA via extra_config
            attributes = client.get('attributes', {})
            acr_loa_map = attributes.get('acr.loa.map', '')
            acr_loa_default = attributes.get('acr.loa.map.default', '')
            acr_loa_force = attributes.get('acr.loa.map.force', '')
            
            # Ajouter les attributs ACR to LOA via extra_config s'ils existent
            if acr_loa_map or acr_loa_default or acr_loa_force:
                config += '\n  # Configuration ACR to LOA mapping\n'
                config += '  extra_config = {\n'
                
                if acr_loa_map:
                    # Échapper correctement les guillemets pour Terraform
                    escaped_acr_loa_map = acr_loa_map.replace('"', '\\"')
                    config += f'    "acr.loa.map" = "{escaped_acr_loa_map}"\n'
                
                if acr_loa_default:
                    config += f'    "acr.loa.map.default" = "{acr_loa_default}"\n'
                
                if acr_loa_force:
                    config += f'    "acr.loa.map.force" = "{acr_loa_force.lower()}"\n'
                
                config += '  }\n'
            
            # Authentication flow binding overrides (bloc spécifique du provider)
            auth_flow_overrides = client.get('authenticationFlowBindingOverrides', {})
            if auth_flow_overrides:
                config += '\n  # Authentication flow binding overrides\n'
                config += '  authentication_flow_binding_overrides {\n'
                
                # Créer un mapping des flows pour trouver les noms de ressources
                flow_resource_mapping = {}
                flow_id_to_alias_mapping = {}
                if self.realm_data and 'authenticationFlows' in self.realm_data:
                    for flow in self.realm_data['authenticationFlows']:
                        flow_id = flow.get('id', '')
                        alias = flow.get('alias', '')
                        if alias and alias.strip():
                            # Nettoyer le nom pour créer le nom de ressource (même logique que generate_authentication_flows_config)
                            resource_name = alias.replace('@', '_').replace('.', '_').replace('-', '_').replace(' ', '_')
                            flow_resource_mapping[alias] = resource_name
                            # Créer aussi un mapping ID -> alias
                            if flow_id:
                                flow_id_to_alias_mapping[flow_id] = alias
                
                # Gérer browser_id avec référence Terraform
                browser_flow = auth_flow_overrides.get('browser')
                if browser_flow:
                    # Vérifier si c'est un ID ou un alias
                    if browser_flow in flow_id_to_alias_mapping:
                        # C'est un ID, récupérer l'alias puis le nom de ressource
                        browser_alias = flow_id_to_alias_mapping[browser_flow]
                        browser_resource_name = flow_resource_mapping.get(browser_alias, browser_alias.replace('@', '_').replace('.', '_').replace('-', '_').replace(' ', '_'))
                    else:
                        # C'est un alias, utiliser directement
                        browser_resource_name = flow_resource_mapping.get(browser_flow, browser_flow.replace('@', '_').replace('.', '_').replace('-', '_').replace(' ', '_'))
                    config += f'    browser_id = keycloak_authentication_flow.{browser_resource_name}.id\n'
                else:
                    config += '    browser_id = null\n'
                
                # Gérer direct_grant_id avec référence Terraform
                direct_grant_flow = auth_flow_overrides.get('direct_grant')
                if direct_grant_flow:
                    # Vérifier si c'est un ID ou un alias
                    if direct_grant_flow in flow_id_to_alias_mapping:
                        # C'est un ID, récupérer l'alias puis le nom de ressource
                        direct_grant_alias = flow_id_to_alias_mapping[direct_grant_flow]
                        direct_grant_resource_name = flow_resource_mapping.get(direct_grant_alias, direct_grant_alias.replace('@', '_').replace('.', '_').replace('-', '_').replace(' ', '_'))
                    else:
                        # C'est un alias, utiliser directement
                        direct_grant_resource_name = flow_resource_mapping.get(direct_grant_flow, direct_grant_flow.replace('@', '_').replace('.', '_').replace('-', '_').replace(' ', '_'))
                    config += f'    direct_grant_id = keycloak_authentication_flow.{direct_grant_resource_name}.id\n'
                else:
                    config += '    direct_grant_id = null\n'
                
                # Gérer d'autres types de flow avec références Terraform
                for flow_type, flow_identifier in auth_flow_overrides.items():
                    if flow_type not in ['browser', 'direct_grant']:
                        # Vérifier si c'est un ID ou un alias
                        if flow_identifier in flow_id_to_alias_mapping:
                            # C'est un ID, récupérer l'alias puis le nom de ressource
                            flow_alias = flow_id_to_alias_mapping[flow_identifier]
                            flow_resource_name = flow_resource_mapping.get(flow_alias, flow_alias.replace('@', '_').replace('.', '_').replace('-', '_').replace(' ', '_'))
                        else:
                            # C'est un alias, utiliser directement
                            flow_resource_name = flow_resource_mapping.get(flow_identifier, flow_identifier.replace('@', '_').replace('.', '_').replace('-', '_').replace(' ', '_'))
                        config += f'    {flow_type}_id = keycloak_authentication_flow.{flow_resource_name}.id\n'
                
                config += '  }\n'
            
            config += "}\n"
            
            # Scopes par défaut
            if default_client_scopes:
                config += f'''
resource "keycloak_openid_client_default_scopes" "{client_resource_name}_default_scopes" {{
        realm_id   = keycloak_realm.{self.get_realm_resource_name()}.id
  client_id  = keycloak_openid_client.{client_resource_name}.id
  default_scopes = {json.dumps(default_client_scopes)}
}}
'''
            
            # Scopes optionnels
            if optional_client_scopes:
                config += f'''
resource "keycloak_openid_client_optional_scopes" "{client_resource_name}_optional_scopes" {{
        realm_id   = keycloak_realm.{self.get_realm_resource_name()}.id
  client_id  = keycloak_openid_client.{client_resource_name}.id
  optional_scopes = {json.dumps(optional_client_scopes)}
}}
'''
        
        return config
    
    def generate_roles_config(self) -> str:
        """Génère la configuration des rôles"""
        if not self.realm_data or 'roles' not in self.realm_data:
            return ""
        
        config = ""
        roles = self.realm_data['roles']
        
        # Rôles du realm
        if 'realm' in roles:
            for role in roles['realm']:
                role_name = role.get('name', '')
                description = role.get('description', '')
                composite = role.get('composite', False)
                
                # S'assurer que le nom du rôle n'est pas vide
                if not role_name or role_name.strip() == '':
                    continue
                
                # Vérifier si c'est un rôle automatiquement créé par Keycloak
                if self.is_auto_created_object(role_name, 'role'):
                    self.log_debug(f"Rôle '{role_name}' ignoré (créé automatiquement par Keycloak)")
                    continue
                
                # S'assurer que la description n'est pas vide
                if not description or description.strip() == '':
                    description = f"Role {role_name}"
                
                # Nettoyer le nom du rôle pour le nom de ressource
                resource_name = role_name.replace('-', '_').replace(' ', '_').replace(':', '_').replace('.', '_')
                
                config += f'''
resource "keycloak_role" "{resource_name}" {{
        realm_id    = keycloak_realm.{self.get_realm_resource_name()}.id
  name        = "{role_name}"
'''
                if description and description.strip():
                    config += f'  description = "{description}"\n'
                config += "}\n"
        
        return config
    
    def generate_groups_config(self) -> str:
        """Génère la configuration des groupes"""
        if not self.realm_data or 'groups' not in self.realm_data:
            return ""
        
        config = ""
        groups = self.realm_data['groups']
        
        def process_group(group, parent_id=None):
            group_name = group.get('name', '')
            group_path = group.get('path', '')
            group_id = group.get('id', '')
            
            # S'assurer que le nom du groupe n'est pas vide
            if not group_name or group_name.strip() == '':
                return ""
            
            # Vérifier si c'est un groupe automatiquement créé par Keycloak
            if self.is_auto_created_object(group_name, 'group') or self.is_auto_created_object(group_name, 'public_group'):
                self.log_debug(f"Groupe '{group_name}' ignoré (créé automatiquement par Keycloak)")
                return ""
            
            # S'assurer que le path du groupe n'est pas vide
            if not group_path or group_path.strip() == '':
                group_path = f"/{group_name}"
            
            resource_name = group_path.replace('/', '_').replace('-', '_').replace(' ', '_').lstrip('_')
            
            config = f'''
resource "keycloak_group" "{resource_name}" {{
        realm_id  = keycloak_realm.{self.get_realm_resource_name()}.id
  name      = "{group_name}"
'''
            
            if parent_id:
                config += f'  parent_id = keycloak_group.{parent_id}.id\n'
            
            config += "}\n"
            
            # Traiter les sous-groupes
            if 'subGroups' in group:
                for subgroup in group['subGroups']:
                    config += process_group(subgroup, resource_name)
            
            return config
        
        for group in groups:
            config += process_group(group)
        
        return config
    
    def generate_auto_created_data_sources(self) -> str:
        """Génère des data sources pour les objets automatiquement créés par Keycloak"""
        config = ""
        
        # Data sources pour les clients par défaut
        config += "\n# Data sources pour les clients automatiquement créés par Keycloak\n"
        for client in self.auto_created_objects['default_clients']:
            client_resource_name = client.replace('-', '_').replace(' ', '_')
            config += f'''
data "keycloak_openid_client" "{client_resource_name}" {{
  realm_id  = keycloak_realm.{self.get_realm_resource_name()}.id
  client_id = "{client}"
}}
'''
        
        # Data sources pour les rôles par défaut
        config += "\n# Data sources pour les rôles automatiquement créés par Keycloak\n"
        for role in self.auto_created_objects['default_roles']:
            role_resource_name = role.replace('-', '_').replace(' ', '_')
            config += f'''
data "keycloak_role" "realm_role_{role_resource_name}" {{
  realm_id = keycloak_realm.{self.get_realm_resource_name()}.id
  name     = "{role}"
}}
'''
        
        # Ajouter le rôle default-roles-{realm_name} si le realm est défini
        if self.realm_data and 'realm' in self.realm_data:
            realm_name = self.realm_data['realm']
            default_roles_realm = f'default-roles-{realm_name}'
            role_resource_name = default_roles_realm.replace('-', '_').replace(' ', '_')
            config += f'''
data "keycloak_role" "realm_role_{role_resource_name}" {{
  realm_id = keycloak_realm.{self.get_realm_resource_name()}.id
  name     = "{default_roles_realm}"
}}
'''
        
        # Data sources pour les groupes par défaut
        config += "\n# Data sources pour les groupes automatiquement créés par Keycloak\n"
        for group in self.auto_created_objects['default_groups']:
            group_resource_name = group.replace('-', '_').replace(' ', '_')
            config += f'''
data "keycloak_group" "{group_resource_name}" {{
  realm_id = keycloak_realm.{self.get_realm_resource_name()}.id
  name     = "{group}"
}}
'''
        
        # Data sources pour les scopes OpenID Connect par défaut
        config += "\n# Data sources pour les scopes OpenID Connect automatiquement créés par Keycloak\n"
        for scope in self.auto_created_objects['default_oidc_scopes']:
            scope_resource_name = scope.replace('-', '_').replace(' ', '_')
            config += f'''
data "keycloak_openid_client_scope" "default_scope_{scope_resource_name}" {{
  realm_id = keycloak_realm.{self.get_realm_resource_name()}.id
  name     = "{scope}"
}}
'''
        
        # Note: Les scopes SAML builtin ne sont pas supportés comme data sources
        # par le provider keycloak/keycloak, ils sont référencés directement par leur nom
        
        return config
    
    def generate_users_config(self) -> str:
        """Génère la configuration des utilisateurs"""
        if not self.realm_data or 'users' not in self.realm_data:
            return ""
        
        config = ""
        users = self.realm_data['users']
        
        # Vérifier s'il y a des utilisateurs dans l'export
        if not users or len(users) == 0:
            self.log_debug("Aucun utilisateur trouvé dans l'export - aucun utilisateur généré")
            return ""
        
        for user in users:
            username = user.get('username', '')
            if not username or username.strip() == '':
                continue
            
            # Exclure les comptes de service automatiquement créés par Keycloak
            if username.startswith('service-account-'):
                self.log_debug(f"Utilisateur '{username}' ignoré (compte de service automatiquement créé)")
                continue
            
            first_name = user.get('firstName', '')
            last_name = user.get('lastName', '')
            email = user.get('email', '')
            enabled = user.get('enabled', True)
            
            # S'assurer que les noms ne sont pas vides
            if not first_name or first_name.strip() == '':
                first_name = ''
            if not last_name or last_name.strip() == '':
                last_name = ''
            if not email or email.strip() == '':
                email = ''
            
            # Nettoyer le nom d'utilisateur pour le nom de ressource
            resource_name = username.replace('@', '_').replace('.', '_').replace('-', '_').replace(' ', '_')
            
            config += f'''
resource "keycloak_user" "{resource_name}" {{
        realm_id   = keycloak_realm.{self.get_realm_resource_name()}.id
  username   = "{username}"
  enabled    = {str(enabled).lower()}
'''
            
            if first_name:
                config += f'  first_name = "{first_name}"\n'
            
            if last_name:
                config += f'  last_name = "{last_name}"\n'
            
            if email:
                config += f'  email = "{email}"\n'
            
            config += "}\n"
        
        return config
    
    def generate_identity_providers_config(self) -> str:
        """Génère la configuration des fournisseurs d'identité"""
        if not self.realm_data or 'identityProviders' not in self.realm_data:
            return ""
        
        config = ""
        idps = self.realm_data['identityProviders']
        
        for idp in idps:
            alias = idp.get('alias', '')
            provider_id = idp.get('providerId', '')
            enabled = idp.get('enabled', True)
            display_name = idp.get('displayName', '')
            
            # S'assurer que l'alias n'est pas vide
            if not alias or alias.strip() == '':
                continue
            
            # S'assurer que le display_name n'est pas vide
            if not display_name or display_name.strip() == '':
                display_name = alias
            
            # Récupérer les valeurs de configuration
            config_data = idp.get('config', {})
            authorization_url = config_data.get('authorizationUrl', 'https://example.com/auth')
            token_url = config_data.get('tokenUrl', 'https://example.com/token')
            client_id = config_data.get('clientId', '')
            client_secret = config_data.get('clientSecret', '')
            default_scopes = config_data.get('defaultScope', 'openid')
            
            config += f'''
resource "keycloak_oidc_identity_provider" "{alias}" {{
        realm             = keycloak_realm.{self.get_realm_resource_name()}.id
  alias             = "{alias}"
  enabled           = {str(enabled).lower()}
  display_name      = "{display_name}"
  
  # Configuration OIDC
  authorization_url = "{authorization_url}"
  token_url         = "{token_url}"
'''
            if client_id:
                config += f'  client_id         = "{client_id}"\n'
            if client_secret:
                config += f'  client_secret     = "{client_secret}"\n'
            if default_scopes:
                config += f'  default_scopes    = "{default_scopes}"\n'
            
            # Ajouter access_type via extra_config
            config += '\n  # Configuration supplémentaire\n'
            config += '  extra_config = {\n'
            config += '    "access_type" = "PUBLIC"\n'
            config += '  }\n'
            
            config += "}\n"
        
        return config

    def generate_client_scopes_config(self) -> str:
        """Génère la configuration des scopes de clients (OpenID Connect et SAML)"""
        if not self.realm_data or 'clientScopes' not in self.realm_data:
            return ""
        
        config = ""
        client_scopes = self.realm_data['clientScopes']
        
        for scope in client_scopes:
            name = scope.get('name', '')
            if not name or name.strip() == '':
                continue
            
            # Exclure les scopes par défaut
            if self.is_auto_created_object(name, 'scope'):
                self.log_debug(f"Scope '{name}' ignoré (créé automatiquement par Keycloak)")
                continue
            
            # Exclure explicitement les scopes SAML builtin même s'ils sont dans l'export
            if name in self.auto_created_objects['default_saml_scopes']:
                self.log_debug(f"Scope SAML '{name}' ignoré (scope SAML builtin)")
                continue
            
            description = scope.get('description', '')
            protocol = scope.get('protocol', 'openid-connect')
            protocol_mappers = scope.get('protocolMappers', [])
            
            # Nettoyer le nom pour le nom de ressource
            resource_name = name.replace('@', '_').replace('.', '_').replace('-', '_').replace(' ', '_')
            
            # Échapper les guillemets dans les chaînes
            escaped_name = name.replace('"', '\\"').replace("'", "\\'")
            escaped_description = description.replace('"', '\\"').replace("'", "\\'")
            
            if protocol == 'openid-connect':
                # Scope OpenID Connect
                config += f'''
resource "keycloak_openid_client_scope" "{resource_name}" {{
  realm_id    = keycloak_realm.{self.get_realm_resource_name()}.id
  name        = "{escaped_name}"
  description = "{escaped_description}"
'''
                config += "}\n"
                
            elif protocol == 'saml':
                # Scope SAML
                config += f'''
resource "keycloak_saml_client_scope" "{resource_name}" {{
  realm_id    = keycloak_realm.{self.get_realm_resource_name()}.id
  name        = "{escaped_name}"
  description = "{escaped_description}"
'''
                config += "}\n"
                
            else:
                # Protocole non supporté
                self.log_debug(f"Scope '{name}' ignoré (protocole {protocol} non supporté)")
                continue
            
            # Note: Les protocol mappers ne sont pas supportés par le provider keycloak/keycloak
            # Ils doivent être configurés manuellement dans Keycloak
            if protocol_mappers:
                self.log_debug(f"Scope '{name}' a {len(protocol_mappers)} protocol mappers (non supportés par le provider)")
        
        return config

    def generate_authentication_flows_config(self) -> str:
        """Génère la configuration des flows d'authentification"""
        if not self.realm_data or 'authenticationFlows' not in self.realm_data:
            return ""
        
        config = ""
        flows = self.realm_data['authenticationFlows']
        
        # Créer un mapping des flows pour faciliter la recherche des parents
        flow_mapping = {}
        for flow in flows:
            alias = flow.get('alias', '')
            if alias and alias.strip():
                flow_mapping[alias] = flow
        
        for flow in flows:
            alias = flow.get('alias', '')
            if not alias or alias.strip() == '':
                continue
            
            # Exclure les flows par défaut
            if self.is_auto_created_object(alias, 'flow'):
                self.log_debug(f"Flow '{alias}' ignoré (créé automatiquement par Keycloak)")
                continue
            
            description = flow.get('description', '')
            provider_id = flow.get('providerId', 'basic-flow')
            top_level = flow.get('topLevel', True)
            
            # Nettoyer le nom pour le nom de ressource
            resource_name = alias.replace('@', '_').replace('.', '_').replace('-', '_').replace(' ', '_')
            
            if top_level:
                # Flow principal
                config += f'''
resource "keycloak_authentication_flow" "{resource_name}" {{
  realm_id    = keycloak_realm.{self.get_realm_resource_name()}.id
  alias       = "{alias}"
  description = "{description}"
  provider_id = "{provider_id}"
}}
'''
            else:
                # Subflow - améliorer la recherche du flow parent
                parent_flow_alias = flow.get('parentFlowAlias', '')
                requirement = flow.get('requirement', 'REQUIRED')
                
                # Si parentFlowAlias est vide, essayer de trouver le parent via d'autres moyens
                if not parent_flow_alias or parent_flow_alias.strip() == '':
                    # Chercher dans les executions pour trouver le flow parent
                    executions = flow.get('authenticationExecutions', [])
                    for execution in executions:
                        flow_alias = execution.get('flowAlias', '')
                        if flow_alias and flow_alias in flow_mapping:
                            parent_flow_alias = flow_alias
                            break
                    
                    # Si toujours pas trouvé, chercher dans les flows parents qui ont ce flow comme subflow
                    if not parent_flow_alias or parent_flow_alias.strip() == '':
                        for parent_alias, parent_flow in flow_mapping.items():
                            if parent_flow.get('topLevel', True):
                                parent_executions = parent_flow.get('authenticationExecutions', [])
                                for parent_execution in parent_executions:
                                    # Si l'exécution du parent a un flowAlias qui correspond à ce subflow
                                    if parent_execution.get('flowAlias') == alias:
                                        parent_flow_alias = parent_alias
                                        break
                                if parent_flow_alias:
                                    break
                    
                    # Si toujours pas trouvé, essayer de déduire du nom ou de la description
                    if not parent_flow_alias or parent_flow_alias.strip() == '':
                        # Chercher un flow parent probable basé sur le nom
                        for parent_alias, parent_flow in flow_mapping.items():
                            if parent_flow.get('topLevel', True) and alias.lower() in parent_alias.lower():
                                parent_flow_alias = parent_alias
                                break
                
                # Si toujours pas de parent trouvé, ignorer ce subflow
                if not parent_flow_alias or parent_flow_alias.strip() == '':
                    self.log_debug(f"Subflow '{alias}' ignoré (aucun flow parent trouvé)")
                    continue
                
                # Nettoyer le nom du flow parent pour la référence
                parent_flow_resource_name = parent_flow_alias.replace('@', '_').replace('.', '_').replace('-', '_').replace(' ', '_')
                
                config += f'''
resource "keycloak_authentication_subflow" "{resource_name}" {{
  realm_id           = keycloak_realm.{self.get_realm_resource_name()}.id
  alias              = "{alias}"
  parent_flow_alias  = keycloak_authentication_flow.{parent_flow_resource_name}.alias
  requirement        = "{requirement}"
  provider_id        = "{provider_id}"
}}
'''
        
        return config

    def generate_authentication_executions_config(self) -> str:
        """Génère la configuration des exécutions d'authentification"""
        if not self.realm_data or 'authenticationFlows' not in self.realm_data:
            return ""
        
        config = ""
        flows = self.realm_data['authenticationFlows']
        
        for flow in flows:
            alias = flow.get('alias', '')
            if not alias or alias.strip() == '':
                continue
            
            # Exclure les flows par défaut
            if self.is_auto_created_object(alias, 'flow'):
                continue
            
            executions = flow.get('authenticationExecutions', [])
            if not executions:
                continue
            
            # Nettoyer le nom pour le nom de ressource
            flow_resource_name = alias.replace('@', '_').replace('.', '_').replace('-', '_').replace(' ', '_')
            top_level = flow.get('topLevel', True)
            
            for i, execution in enumerate(executions):
                authenticator = execution.get('authenticator', '')
                if not authenticator:
                    continue
                
                requirement = execution.get('requirement', 'REQUIRED')
                flow_alias = execution.get('flowAlias', '')
                
                # Nettoyer le nom de l'authenticator pour le nom de ressource
                authenticator_resource_name = authenticator.replace('@', '_').replace('.', '_').replace('-', '_').replace(' ', '_')
                execution_resource_name = f"{flow_resource_name}_{authenticator_resource_name}_{i}"
                
                # Déterminer la ressource parente correcte
                if flow_alias:
                    # Exécution dans un subflow - utiliser le flow parent
                    parent_flow_alias = f"keycloak_authentication_subflow.{flow_resource_name}.alias"
                elif top_level:
                    # Exécution dans un flow principal
                    parent_flow_alias = f"keycloak_authentication_flow.{flow_resource_name}.alias"
                else:
                    # Exécution dans un subflow
                    parent_flow_alias = f"keycloak_authentication_subflow.{flow_resource_name}.alias"
                
                # Vérifier que parent_flow_alias n'est pas vide
                if not parent_flow_alias or parent_flow_alias.strip() == '':
                    self.log_debug(f"Exécution '{authenticator}' ignorée (parent_flow_alias vide)")
                    continue
                
                config += f'''
resource "keycloak_authentication_execution" "{execution_resource_name}" {{
  realm_id           = keycloak_realm.{self.get_realm_resource_name()}.id
  parent_flow_alias  = {parent_flow_alias}
  authenticator      = "{authenticator}"
  requirement        = "{requirement}"
}}
'''
        
        return config

    def generate_authenticator_configs_config(self) -> str:
        """Génère la configuration des configurations d'authenticateurs"""
        if not self.realm_data or 'authenticatorConfig' not in self.realm_data:
            return ""
        
        config = ""
        authenticator_configs = self.realm_data['authenticatorConfig']
        
        # Créer un mapping des alias de config vers les exécutions
        execution_mapping = {}
        if 'authenticationFlows' in self.realm_data:
            for flow in self.realm_data['authenticationFlows']:
                if self.is_auto_created_object(flow.get('alias', ''), 'flow'):
                    continue
                
                flow_resource_name = flow.get('alias', '').replace('@', '_').replace('.', '_').replace('-', '_').replace(' ', '_')
                executions = flow.get('authenticationExecutions', [])
                
                for i, execution in enumerate(executions):
                    authenticator = execution.get('authenticator', '')
                    if not authenticator:
                        continue
                    
                    authenticator_resource_name = authenticator.replace('@', '_').replace('.', '_').replace('-', '_').replace(' ', '_')
                    execution_resource_name = f"{flow_resource_name}_{authenticator_resource_name}_{i}"
                    
                    # Mapper l'alias de config vers l'exécution
                    config_alias = execution.get('authenticatorConfig', '')
                    if config_alias:
                        execution_mapping[config_alias] = execution_resource_name
        
        for auth_config in authenticator_configs:
            alias = auth_config.get('alias', '')
            if not alias or alias.strip() == '':
                continue
            
            # Vérifier si c'est une configuration automatiquement créée par Keycloak
            if self.is_auto_created_object(alias, 'authenticator_config'):
                self.log_debug(f"Configuration d'authenticateur '{alias}' ignorée (créée automatiquement par Keycloak)")
                continue
            
            config_data = auth_config.get('config', {})
            if not config_data:
                continue
            
            # Trouver l'exécution correspondante
            execution_id = execution_mapping.get(alias, '')
            if not execution_id:
                self.log_debug(f"Configuration '{alias}' ignorée (aucune exécution correspondante trouvée)")
                continue
            
            # Nettoyer le nom pour le nom de ressource
            resource_name = alias.replace('@', '_').replace('.', '_').replace('-', '_').replace(' ', '_')
            
            config += f'''
resource "keycloak_authentication_execution_config" "{resource_name}" {{
  realm_id     = keycloak_realm.{self.get_realm_resource_name()}.id
  alias        = "{alias}"
  execution_id = keycloak_authentication_execution.{execution_id}.id
  config       = {{
'''
            
            for key, value in config_data.items():
                config += f'    "{key}" = "{value}"\n'
            
            config += "  }\n}\n"
        
        return config
    
    def generate_all_configs(self):
        """Génère toutes les configurations Terraform"""
        self.create_output_directory()
        
        # Provider
        provider_config = self.generate_terraform_provider()
        
        # Realm
        realm_config = self.generate_realm_config()
        
        # Clients
        clients_config = self.generate_clients_config()
        
        # Rôles
        roles_config = self.generate_roles_config()
        
        # Groupes
        groups_config = self.generate_groups_config()
        
        # Utilisateurs
        users_config = self.generate_users_config()
        
        # Fournisseurs d'identité
        idps_config = self.generate_identity_providers_config()
        
        # Scopes de clients
        client_scopes_config = self.generate_client_scopes_config()
        
        # Flows d'authentification
        auth_flows_config = self.generate_authentication_flows_config()
        
        # Exécutions d'authentification
        auth_executions_config = self.generate_authentication_executions_config()
        
        # Configurations d'authenticateurs
        auth_configs_config = self.generate_authenticator_configs_config()
        
        # Data sources pour les objets automatiquement créés
        auto_created_data_sources = self.generate_auto_created_data_sources()
        
        # Écrire les fichiers avec remplacement des variables
        with open(f"{self.output_dir}/provider.tf", "w", encoding="utf-8") as f:
            f.write(self.replace_variables(provider_config))
        
        with open(f"{self.output_dir}/realm.tf", "w", encoding="utf-8") as f:
            f.write(self.replace_variables(realm_config))
        
        with open(f"{self.output_dir}/clients.tf", "w", encoding="utf-8") as f:
            f.write(self.replace_variables(clients_config))
        
        with open(f"{self.output_dir}/roles.tf", "w", encoding="utf-8") as f:
            f.write(self.replace_variables(roles_config))
        
        with open(f"{self.output_dir}/groups.tf", "w", encoding="utf-8") as f:
            f.write(self.replace_variables(groups_config))
        
        with open(f"{self.output_dir}/users.tf", "w", encoding="utf-8") as f:
            f.write(self.replace_variables(users_config))
        
        with open(f"{self.output_dir}/identity_providers.tf", "w", encoding="utf-8") as f:
            f.write(self.replace_variables(idps_config))
        
        with open(f"{self.output_dir}/client_scopes.tf", "w", encoding="utf-8") as f:
            f.write(self.replace_variables(client_scopes_config))
        
        with open(f"{self.output_dir}/authentication_flows.tf", "w", encoding="utf-8") as f:
            f.write(self.replace_variables(auth_flows_config))
        
        with open(f"{self.output_dir}/authentication_executions.tf", "w", encoding="utf-8") as f:
            f.write(self.replace_variables(auth_executions_config))
        
        with open(f"{self.output_dir}/authenticator_configs.tf", "w", encoding="utf-8") as f:
            f.write(self.replace_variables(auth_configs_config))
        
        with open(f"{self.output_dir}/auto_created_data_sources.tf", "w", encoding="utf-8") as f:
            f.write(self.replace_variables(auto_created_data_sources))
        
        print(f"✅ Configurations Terraform générées dans le répertoire '{self.output_dir}'")
        print("📁 Fichiers créés:")
        print("   - provider.tf")
        print("   - realm.tf")
        print("   - clients.tf")
        print("   - roles.tf")
        print("   - groups.tf")
        print("   - users.tf")
        print("   - identity_providers.tf")
        print("   - client_scopes.tf")
        print("   - authentication_flows.tf")
        print("   - authentication_executions.tf")
        print("   - authenticator_configs.tf")
        print("   - auto_created_data_sources.tf")

def main():
    """Fonction principale"""
    parser = argparse.ArgumentParser(description="Convertir un export Keycloak en code Terraform")
    parser.add_argument("export_file", help="Fichier d'export Keycloak (JSON)")
    parser.add_argument("--output-dir", default="terraform_output", help="Répertoire de sortie")
    parser.add_argument("--debug", action="store_true", help="Mode debug")
    
    args = parser.parse_args()
    
    # Créer l'instance du convertisseur
    converter = KeycloakToTerraform(debug=args.debug)
    converter.output_dir = args.output_dir
    
    # Charger l'export Keycloak
    print(f"📥 Chargement de l'export Keycloak depuis {args.export_file}...")
    converter.load_realm_export(args.export_file)
    
    # Générer les configurations Terraform
    print("🔄 Génération des configurations Terraform...")
    converter.generate_all_configs()
    
    print("🎉 Conversion terminée avec succès!")
    print("\n📝 Prochaines étapes:")
    print("1. Modifiez les paramètres de connexion dans provider.tf")
    print("2. Exécutez 'terraform init' dans le répertoire de sortie")
    print("3. Exécutez 'terraform plan' pour vérifier la configuration")
    print("4. Exécutez 'terraform apply' pour déployer")
    print("\n⚠️  IMPORTANT:")
    print("   • Les objets automatiquement créés par Keycloak sont exclus pour éviter les erreurs 409")
    print("   • Ces objets sont disponibles via des data sources dans auto_created_data_sources.tf")
    print("   • Seuls les objets personnalisés sont créés comme resources Terraform")

if __name__ == "__main__":
    main()
