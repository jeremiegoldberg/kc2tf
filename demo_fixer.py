#!/usr/bin/env python3
"""
Script de démonstration pour le correcteur Terraform
Montre comment utiliser le correcteur avec différents exemples
"""

import os
import json
import tempfile
import subprocess
import shutil

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
}

resource "keycloak_group" "demo-group" {
  # Attribut requis manquant: name
  realm_id = keycloak_realm.demo-realm.id
  # Attribut non supporté
  invalid_group_attr = "value"
}

resource "keycloak_role" "demo-role" {
  # Attribut requis manquant: name
  realm_id = keycloak_realm.demo-realm.id
  description = "Demo Role"
  composite = false
  # Attribut non supporté
  invalid_role_attr = "value"
}'''

def run_demo():
    """Exécute la démonstration complète"""
    print("🚀 DÉMONSTRATION DU CORRECTEUR TERRAFORM")
    print("=" * 50)
    
    # Créer le répertoire de test
    test_dir = 'demo_fix'
    if os.path.exists(test_dir):
        shutil.rmtree(test_dir)
    os.makedirs(test_dir)
    
    try:
        # 1. Créer du code Terraform problématique
        print("\n📝 1. Création de code Terraform problématique...")
        
        problematic_tf = create_problematic_terraform()
        with open(f'{test_dir}/problematic.tf', 'w') as f:
            f.write(problematic_tf)
        
        print("✅ Code Terraform problématique créé")
        
        # Afficher le contenu avant correction
        print("\n📄 Contenu AVANT correction:")
        print("-" * 40)
        with open(f'{test_dir}/problematic.tf', 'r') as f:
            print(f.read())
        
        # 2. Analyser le code problématique (sans correction)
        print("\n🔍 2. Analyse du code problématique...")
        result = subprocess.run(['python3', 'analyze_terraform.py', test_dir], 
                              capture_output=True, text=True)
        print("Résultat de l'analyse:")
        print(result.stdout)
        
        # 3. Corriger le code
        print("\n🔧 3. Correction automatique du code...")
        result = subprocess.run(['python3', 'fix_terraform.py', test_dir], 
                              capture_output=True, text=True)
        print("Résultat de la correction:")
        print(result.stdout)
        
        # 4. Afficher le contenu après correction
        print("\n📄 Contenu APRÈS correction:")
        print("-" * 40)
        with open(f'{test_dir}/problematic.tf', 'r') as f:
            print(f.read())
        
        # 5. Vérifier que le code est maintenant conforme
        print("\n✅ 5. Vérification de la conformité...")
        result = subprocess.run(['python3', 'analyze_terraform.py', test_dir], 
                              capture_output=True, text=True)
        print("Résultat de la vérification:")
        print(result.stdout)
        
        # 6. Test avec format JSON
        print("\n📊 6. Test avec format JSON...")
        result = subprocess.run(['python3', 'fix_terraform.py', test_dir, '--json'], 
                              capture_output=True, text=True)
        
        try:
            json_data = json.loads(result.stdout)
            print("📋 Résumé JSON:")
            print(f"   • Fichiers traités: {json_data['stats']['files_processed']}")
            print(f"   • Ressources corrigées: {json_data['stats']['resources_fixed']}")
            print(f"   • Corrections appliquées: {json_data['stats']['fixes_applied']}")
        except:
            print("❌ Erreur lors du parsing JSON")
        
        # 7. Sauvegarder un rapport
        print("\n💾 7. Sauvegarde d'un rapport...")
        result = subprocess.run(['python3', 'fix_terraform.py', test_dir, '--output', 'rapport_correction.txt'], 
                              capture_output=True, text=True)
        
        if os.path.exists('rapport_correction.txt'):
            print("✅ Rapport sauvegardé dans 'rapport_correction.txt'")
            with open('rapport_correction.txt', 'r') as f:
                print("\n📄 Contenu du rapport:")
                print(f.read())
        
        print("\n🎉 Démonstration terminée avec succès!")
        print("\n📚 UTILISATION DU CORRECTEUR:")
        print("   • python3 fix_terraform.py <répertoire>")
        print("   • python3 fix_terraform.py <répertoire> --json")
        print("   • python3 fix_terraform.py <répertoire> --output rapport.txt")
        print("   • python3 fix_terraform.py <répertoire> --verbose")
        
        print("\n🔧 TYPES DE CORRECTIONS APPLIQUÉES:")
        print("   • Suppression des attributs non supportés")
        print("   • Ajout des attributs requis manquants")
        print("   • Correction des URLs OIDC manquantes")
        print("   • Résolution des incohérences logiques")
        print("   • Génération de valeurs par défaut intelligentes")
        
    finally:
        # Nettoyage
        if os.path.exists(test_dir):
            shutil.rmtree(test_dir)
        if os.path.exists('rapport_correction.txt'):
            os.unlink('rapport_correction.txt')

if __name__ == "__main__":
    run_demo()
