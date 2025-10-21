#!/usr/bin/env python3
"""
Script de démonstration pour l'analyseur Terraform
Montre comment utiliser l'analyseur avec différents exemples
"""

import os
import json
import tempfile
import subprocess
import shutil

def create_test_export():
    """Crée un export Keycloak de test"""
    return {
        'realm': 'demo-realm',
        'displayName': 'Demo Realm',
        'enabled': True,
        'clients': [
            {
                'clientId': 'demo-client',
                'name': 'Demo Client',
                'enabled': True,
                'standardFlowEnabled': True,
                'implicitFlowEnabled': False,
                'directAccessGrantsEnabled': False,
                'serviceAccountsEnabled': False,
                'publicClient': False,
                'bearerOnly': False,
                'redirectUris': ['http://localhost:3000/*'],
                'webOrigins': ['http://localhost:3000'],
                'defaultClientScopes': ['profile', 'email'],
                'optionalClientScopes': ['address', 'phone']
            }
        ],
        'roles': {
            'realm': [
                {
                    'name': 'demo-role',
                    'description': 'Demo Role',
                    'composite': False
                }
            ]
        },
        'groups': [
            {
                'name': 'demo-group',
                'path': '/demo-group',
                'id': 'demo-group-id',
                'subGroups': []
            }
        ],
        'users': [
            {
                'username': 'demouser',
                'firstName': 'Jane',
                'lastName': 'Smith',
                'email': 'jane.smith@example.com',
                'enabled': True
            }
        ],
        'identityProviders': [
            {
                'alias': 'demo-idp',
                'providerId': 'oidc',
                'enabled': True,
                'displayName': 'Demo IDP',
                'config': {
                    'authorizationUrl': 'https://demo.example.com/auth',
                    'tokenUrl': 'https://demo.example.com/token',
                    'clientId': 'demo-client-id',
                    'clientSecret': 'demo-secret',
                    'defaultScope': 'openid'
                }
            }
        ]
    }

def create_problematic_terraform():
    """Crée un fichier Terraform avec des problèmes"""
    return '''# Fichier Terraform avec des problèmes pour démonstration

resource "keycloak_realm" "demo-realm" {
  realm                = "demo-realm"
  display_name         = "Demo Realm"
  enabled              = true
  # Attribut non supporté
  unsupported_attr     = "value"
}

resource "keycloak_user" "demouser" {
  # Attribut requis manquant: username
  realm_id   = keycloak_realm.demo-realm.id
  enabled    = true
  first_name = "Jane"
  last_name  = "Smith"
  email      = "jane.smith@example.com"
  # Attribut non supporté
  invalid_attr = "value"
}

resource "keycloak_openid_client" "demo_client" {
  realm_id                     = keycloak_realm.demo-realm.id
  client_id                    = "demo-client"
  name                         = "Demo Client"
  enabled                      = true
  standard_flow_enabled        = true
  implicit_flow_enabled        = false
  direct_access_grants_enabled = false
  service_accounts_enabled     = false
  public_client                = false
  bearer_only                  = false
  valid_redirect_uris = ["http://localhost:3000/*"]
  web_origins = ["http://localhost:3000"]
  # Attribut non supporté
  invalid_client_attr = "value"
}

resource "keycloak_oidc_identity_provider" "demo-idp" {
  realm             = keycloak_realm.demo-realm.id
  alias             = "demo-idp"
  enabled           = true
  display_name      = "Demo IDP"
  # URLs OIDC manquantes (erreur)
  client_id         = "demo-client-id"
  client_secret     = "demo-secret"
  default_scopes    = "openid"
}'''

def run_demo():
    """Exécute la démonstration complète"""
    print("🚀 DÉMONSTRATION DE L'ANALYSEUR TERRAFORM")
    print("=" * 50)
    
    # Créer les répertoires de test
    test_dirs = ['demo_valid', 'demo_problematic']
    for dir_name in test_dirs:
        if os.path.exists(dir_name):
            shutil.rmtree(dir_name)
        os.makedirs(dir_name)
    
    try:
        # 1. Test avec du code Terraform valide
        print("\n📝 1. Génération de code Terraform valide...")
        
        # Créer l'export de test
        test_export = create_test_export()
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(test_export, f)
            temp_file = f.name
        
        # Générer le code Terraform
        result = subprocess.run(['python3', 'keycloak_to_terraform.py', temp_file, '--output-dir', 'demo_valid'], 
                              capture_output=True, text=True)
        
        if result.returncode != 0:
            print(f"❌ Erreur lors de la génération: {result.stderr}")
            return
        
        print("✅ Code Terraform valide généré")
        
        # Analyser le code valide
        print("\n🔍 Analyse du code valide...")
        result = subprocess.run(['python3', 'analyze_terraform.py', 'demo_valid'], 
                              capture_output=True, text=True)
        print(result.stdout)
        
        # 2. Test avec du code Terraform problématique
        print("\n📝 2. Création de code Terraform problématique...")
        
        problematic_tf = create_problematic_terraform()
        with open('demo_problematic/problematic.tf', 'w') as f:
            f.write(problematic_tf)
        
        print("✅ Code Terraform problématique créé")
        
        # Analyser le code problématique
        print("\n🔍 Analyse du code problématique...")
        result = subprocess.run(['python3', 'analyze_terraform.py', 'demo_problematic'], 
                              capture_output=True, text=True)
        print(result.stdout)
        
        # 3. Test avec sortie JSON
        print("\n📊 Analyse en format JSON...")
        result = subprocess.run(['python3', 'analyze_terraform.py', 'demo_problematic', '--json'], 
                              capture_output=True, text=True)
        
        # Parser et afficher le JSON de manière lisible
        try:
            json_data = json.loads(result.stdout)
            print("📋 Résumé JSON:")
            print(f"   • Total ressources: {json_data['stats']['total_resources']}")
            print(f"   • Ressources valides: {json_data['stats']['valid_resources']}")
            print(f"   • Erreurs: {json_data['stats']['errors']}")
            print(f"   • Avertissements: {json_data['stats']['warnings']}")
        except:
            print("❌ Erreur lors du parsing JSON")
        
        # 4. Sauvegarder un rapport
        print("\n💾 Sauvegarde d'un rapport...")
        result = subprocess.run(['python3', 'analyze_terraform.py', 'demo_problematic', '--output', 'rapport_analyse.txt'], 
                              capture_output=True, text=True)
        
        if os.path.exists('rapport_analyse.txt'):
            print("✅ Rapport sauvegardé dans 'rapport_analyse.txt'")
            with open('rapport_analyse.txt', 'r') as f:
                print("\n📄 Contenu du rapport:")
                print(f.read())
        
        print("\n🎉 Démonstration terminée avec succès!")
        print("\n📚 UTILISATION DE L'ANALYSEUR:")
        print("   • python3 analyze_terraform.py <répertoire>")
        print("   • python3 analyze_terraform.py <répertoire> --json")
        print("   • python3 analyze_terraform.py <répertoire> --output rapport.txt")
        print("   • python3 analyze_terraform.py <répertoire> --verbose")
        
    finally:
        # Nettoyage
        os.unlink(temp_file)
        for dir_name in test_dirs:
            if os.path.exists(dir_name):
                shutil.rmtree(dir_name)
        if os.path.exists('rapport_analyse.txt'):
            os.unlink('rapport_analyse.txt')

if __name__ == "__main__":
    run_demo()
