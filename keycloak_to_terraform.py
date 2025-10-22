
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
        
    def log_debug(self, message: str):
        """Affiche un message de debug si le mode debug est activé"""
        if self.debug:
            print(f"[DEBUG] {message}")
    
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
        
        config = f'''resource "keycloak_realm" "{realm}" {{
  realm                = "{realm}"
  displayName          = "{display_name}"
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
        
        # Clients par défaut à ignorer
        default_clients = ['account', 'account-console', 'admin-cli', 'broker', 'realm-management']
        
        for client in clients:
            client_id = client.get('clientId', '')
            if client_id in default_clients:
                continue
            
            name = client.get('name', client_id)
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
            
            config += f'''
resource "keycloak_openid_client" "{client_id.replace('-', '_').replace(' ', '_')}" {{
  realmId                      = keycloak_realm.{self.realm_data.get('realm', '')}.id
  clientId                     = "{client_id}"
  name                         = "{name}"
  enabled                      = {str(enabled).lower()}
  standardFlowEnabled          = {str(standard_flow_enabled).lower()}
  implicitFlowEnabled          = {str(implicit_flow_enabled).lower()}
  directAccessGrantsEnabled    = {str(direct_access_grants_enabled).lower()}
  serviceAccountsEnabled      = {str(service_accounts_enabled).lower()}
  publicClient                 = {str(public_client).lower()}
  bearerOnly                   = {str(bearer_only).lower()}
'''
            
            if redirect_uris:
                config += f'  validRedirectUris = {json.dumps(redirect_uris)}\n'
            
            if web_origins:
                config += f'  webOrigins = {json.dumps(web_origins)}\n'
            
            config += "}\n"
            
            # Scopes par défaut
            if default_client_scopes:
                client_resource_name = client_id.replace('-', '_').replace(' ', '_')
                config += f'''
resource "keycloak_openid_client_default_scopes" "{client_resource_name}_default_scopes" {{
  realmId   = keycloak_realm.{self.realm_data.get('realm', '')}.id
  clientId  = keycloak_openid_client.{client_resource_name}.id
  defaultScopes = {json.dumps(default_client_scopes)}
}}
'''
            
            # Scopes optionnels
            if optional_client_scopes:
                client_resource_name = client_id.replace('-', '_').replace(' ', '_')
                config += f'''
resource "keycloak_openid_client_optional_scopes" "{client_resource_name}_optional_scopes" {{
  realmId   = keycloak_realm.{self.realm_data.get('realm', '')}.id
  clientId  = keycloak_openid_client.{client_resource_name}.id
  optionalScopes = {json.dumps(optional_client_scopes)}
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
                
                # Nettoyer le nom du rôle pour le nom de ressource
                resource_name = role_name.replace('-', '_').replace(' ', '_').replace(':', '_').replace('.', '_')
                
                config += f'''
resource "keycloak_role" "{resource_name}" {{
  realmId     = keycloak_realm.{self.realm_data.get('realm', '')}.id
  name        = "{role_name}"
  description = "{description}"
  composite   = {str(composite).lower()}
}}
'''
        
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
            
            resource_name = group_path.replace('/', '_').replace('-', '_').replace(' ', '_').lstrip('_')
            
            config = f'''
resource "keycloak_group" "{resource_name}" {{
  realmId   = keycloak_realm.{self.realm_data.get('realm', '')}.id
  name      = "{group_name}"
'''
            
            if parent_id:
                config += f'  parentId = keycloak_group.{parent_id}.id\n'
            
            config += "}\n"
            
            # Traiter les sous-groupes
            if 'subGroups' in group:
                for subgroup in group['subGroups']:
                    config += process_group(subgroup, resource_name)
            
            return config
        
        for group in groups:
            config += process_group(group)
        
        return config
    
    def generate_users_config(self) -> str:
        """Génère la configuration des utilisateurs"""
        if not self.realm_data or 'users' not in self.realm_data:
            return ""
        
        config = ""
        users = self.realm_data['users']
        
        for user in users:
            username = user.get('username', '')
            if not username:
                continue
            
            first_name = user.get('firstName', '')
            last_name = user.get('lastName', '')
            email = user.get('email', '')
            enabled = user.get('enabled', True)
            
            # Nettoyer le nom d'utilisateur pour le nom de ressource
            resource_name = username.replace('@', '_').replace('.', '_').replace('-', '_').replace(' ', '_')
            
            config += f'''
resource "keycloak_user" "{resource_name}" {{
  realmId    = keycloak_realm.{self.realm_data.get('realm', '')}.id
  username   = "{username}"
  enabled    = {str(enabled).lower()}
'''
            
            if first_name:
                config += f'  firstName = "{first_name}"\n'
            
            if last_name:
                config += f'  lastName = "{last_name}"\n'
            
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
            display_name = idp.get('displayName', alias)
            
            config += f'''
resource "keycloak_oidc_identity_provider" "{alias}" {{
  realm             = keycloak_realm.{self.realm_data.get('realm', '')}.id
  alias             = "{alias}"
  enabled           = {str(enabled).lower()}
  displayName       = "{display_name}"
  
  # Configuration OIDC
  authorizationUrl  = "{idp.get('config', {}).get('authorizationUrl', 'https://example.com/auth')}"
  tokenUrl          = "{idp.get('config', {}).get('tokenUrl', 'https://example.com/token')}"
  clientId          = "{idp.get('config', {}).get('clientId', '')}"
  clientSecret      = "{idp.get('config', {}).get('clientSecret', '')}"
  defaultScopes     = "{idp.get('config', {}).get('defaultScope', 'openid')}"
}}
'''
        
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
        
        # Écrire les fichiers
        with open(f"{self.output_dir}/provider.tf", "w", encoding="utf-8") as f:
            f.write(provider_config)
        
        with open(f"{self.output_dir}/realm.tf", "w", encoding="utf-8") as f:
            f.write(realm_config)
        
        with open(f"{self.output_dir}/clients.tf", "w", encoding="utf-8") as f:
            f.write(clients_config)
        
        with open(f"{self.output_dir}/roles.tf", "w", encoding="utf-8") as f:
            f.write(roles_config)
        
        with open(f"{self.output_dir}/groups.tf", "w", encoding="utf-8") as f:
            f.write(groups_config)
        
        with open(f"{self.output_dir}/users.tf", "w", encoding="utf-8") as f:
            f.write(users_config)
        
        with open(f"{self.output_dir}/identity_providers.tf", "w", encoding="utf-8") as f:
            f.write(idps_config)
        
        print(f"✅ Configurations Terraform générées dans le répertoire '{self.output_dir}'")
        print("📁 Fichiers créés:")
        print("   - provider.tf")
        print("   - realm.tf")
        print("   - clients.tf")
        print("   - roles.tf")
        print("   - groups.tf")
        print("   - users.tf")
        print("   - identity_providers.tf")

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

if __name__ == "__main__":
    main()
