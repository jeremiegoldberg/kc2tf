
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
                        content = content.replace(f'${{{variable}}}', '""')
                else:
                    content = content.replace(f'${{{variable}}}', '""')
            
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
                        content = content.replace(f'${{{variable}}}', '""')
                else:
                    content = content.replace(f'${{{variable}}}', '""')
            
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
                        content = content.replace(f'${{{variable}}}', '""')
                else:
                    content = content.replace(f'${{{variable}}}', '""')
            
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
                        content = content.replace(f'${{{variable}}}', '""')
                else:
                    content = content.replace(f'${{{variable}}}', '""')
            
            else:
                # Variable inconnue, remplacer par une chaîne vide
                content = content.replace(f'${{{variable}}}', '""')
        
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
        
        # Clients par défaut à ignorer
        default_clients = ['account', 'account-console', 'admin-cli', 'broker', 'realm-management']
        
        for client in clients:
            client_id = client.get('clientId', '')
            if client_id in default_clients:
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
            
            if redirect_uris:
                config += f'  valid_redirect_uris = {json.dumps(redirect_uris)}\n'
            
            if web_origins:
                config += f'  web_origins = {json.dumps(web_origins)}\n'
            
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
                
                # S'assurer que la description n'est pas vide
                if not description or description.strip() == '':
                    description = f"Role {role_name}"
                
                # Nettoyer le nom du rôle pour le nom de ressource
                resource_name = role_name.replace('-', '_').replace(' ', '_').replace(':', '_').replace('.', '_')
                
                config += f'''
resource "keycloak_role" "{resource_name}" {{
        realm_id    = keycloak_realm.{self.get_realm_resource_name()}.id
  name        = "{role_name}"
  description = "{description}"
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
            
            # S'assurer que le nom du groupe n'est pas vide
            if not group_name or group_name.strip() == '':
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
    
    def generate_users_config(self) -> str:
        """Génère la configuration des utilisateurs"""
        if not self.realm_data or 'users' not in self.realm_data:
            return ""
        
        config = ""
        users = self.realm_data['users']
        
        for user in users:
            username = user.get('username', '')
            if not username or username.strip() == '':
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
            
            config += f'''
resource "keycloak_oidc_identity_provider" "{alias}" {{
        realm             = keycloak_realm.{self.get_realm_resource_name()}.id
  alias             = "{alias}"
  enabled           = {str(enabled).lower()}
  display_name      = "{display_name}"
  access_type        = "PUBLIC"
  
  # Configuration OIDC
  authorization_url = "{idp.get('config', {}).get('authorizationUrl', 'https://example.com/auth')}"
  token_url         = "{idp.get('config', {}).get('tokenUrl', 'https://example.com/token')}"
  client_id         = "{idp.get('config', {}).get('clientId', '')}"
  client_secret     = "{idp.get('config', {}).get('clientSecret', '')}"
  default_scopes    = "{idp.get('config', {}).get('defaultScope', 'openid')}"
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
