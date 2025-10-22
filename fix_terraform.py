#!/usr/bin/env python3
"""
Script pour corriger automatiquement le code Terraform généré
Version: 1.0.0
"""

import os
import re
import json
import argparse
from typing import Dict, List, Any
from pathlib import Path

class TerraformFixer:
    """Classe pour corriger automatiquement le code Terraform"""
    
    def __init__(self, terraform_dir: str):
        self.terraform_dir = Path(terraform_dir)
        self.fixes_applied = []
        self.stats = {
            'files_processed': 0,
            'fixes_applied': 0,
            'resources_fixed': 0
        }
        
        # Attributs supportés par chaque ressource
        self.supported_attributes = {
            'keycloak_realm': [
                'realm', 'display_name', 'enabled', 'password_policy',
                'sso_session_idle_timeout', 'sso_session_max_lifespan',
                'offline_session_idle_timeout', 'offline_session_max_lifespan_enabled',
                'offline_session_max_lifespan', 'access_token_lifespan',
                'access_token_lifespan_for_implicit_flow', 'login_theme',
                'account_theme', 'admin_theme', 'email_theme'
            ],
            'keycloak_user': [
                'realm_id', 'username', 'enabled', 'first_name', 'last_name',
                'email', 'attributes', 'initial_password'
            ],
            'keycloak_group': [
                'realm_id', 'name', 'parent_id', 'attributes'
            ],
            'keycloak_role': [
                'realm_id', 'name', 'description', 'attributes'
            ],
            'keycloak_openid_client': [
                'realm_id', 'client_id', 'name', 'enabled', 'client_authenticator_type',
                'standard_flow_enabled', 'implicit_flow_enabled', 'direct_access_grants_enabled',
                'service_accounts_enabled', 'public_client', 'bearer_only',
                'valid_redirect_uris', 'web_origins', 'admin_url', 'base_url', 'root_url',
                'access_type', 'consent_required', 'frontchannel_logout_enabled'
            ],
            'keycloak_oidc_identity_provider': [
                'realm', 'alias', 'enabled', 'display_name', 'provider_id',
                'authorization_url', 'token_url', 'client_id', 'client_secret',
                'default_scopes', 'hide_on_login_page', 'trust_email', 'store_token',
                'add_read_token_role_on_create', 'extra_config'
            ],
            'keycloak_openid_client_default_scopes': [
                'realm_id', 'client_id', 'default_scopes'
            ],
            'keycloak_openid_client_optional_scopes': [
                'realm_id', 'client_id', 'optional_scopes'
            ]
        }
        
        # Attributs requis pour chaque ressource
        self.required_attributes = {
            'keycloak_realm': ['realm'],
            'keycloak_user': ['realm_id', 'username'],
            'keycloak_group': ['realm_id', 'name'],
            'keycloak_role': ['realm_id', 'name'],
            'keycloak_openid_client': ['realm_id', 'client_id'],
            'keycloak_oidc_identity_provider': ['realm', 'alias'],
            'keycloak_openid_client_default_scopes': ['realm_id', 'client_id', 'default_scopes'],
            'keycloak_openid_client_optional_scopes': ['realm_id', 'client_id', 'optional_scopes']
        }
    
    def fix_file(self, file_path: Path) -> bool:
        """Corrige un fichier Terraform"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            original_content = content
            fixed_content = self.fix_terraform_content(content)
            
            if fixed_content != original_content:
                # Sauvegarder le fichier corrigé
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(fixed_content)
                
                self.stats['files_processed'] += 1
                return True
            
            return False
            
        except Exception as e:
            print(f"❌ Erreur lors de la correction de {file_path}: {e}")
            return False
    
    def fix_terraform_content(self, content: str) -> str:
        """Corrige le contenu Terraform"""
        lines = content.split('\n')
        fixed_lines = []
        i = 0
        
        while i < len(lines):
            line = lines[i]
            
            # Détecter le début d'une ressource
            if line.strip().startswith('resource '):
                resource_block = self.extract_resource_block(lines, i)
                if resource_block:
                    fixed_block = self.fix_resource_block(resource_block)
                    fixed_lines.extend(fixed_block)
                    i = resource_block['end_line'] + 1
                else:
                    fixed_lines.append(line)
                    i += 1
            else:
                fixed_lines.append(line)
                i += 1
        
        return '\n'.join(fixed_lines)
    
    def extract_resource_block(self, lines: List[str], start_line: int) -> Dict[str, Any]:
        """Extrait un bloc de ressource complet"""
        if start_line >= len(lines):
            return None
        
        # Parser la ligne de déclaration
        resource_line = lines[start_line]
        match = re.match(r'resource\s+"([^"]+)"\s+"([^"]+)"', resource_line)
        if not match:
            return None
        
        resource_type = match.group(1)
        resource_name = match.group(2)
        
        # Trouver la fin du bloc
        brace_count = 0
        end_line = start_line
        
        for i in range(start_line, len(lines)):
            line = lines[i]
            brace_count += line.count('{')
            brace_count -= line.count('}')
            
            if brace_count == 0 and i > start_line:
                end_line = i
                break
        
        return {
            'type': resource_type,
            'name': resource_name,
            'start_line': start_line,
            'end_line': end_line,
            'lines': lines[start_line:end_line + 1]
        }
    
    def fix_resource_block(self, resource_block: Dict[str, Any]) -> List[str]:
        """Corrige un bloc de ressource"""
        resource_type = resource_block['type']
        resource_name = resource_block['name']
        lines = resource_block['lines']
        
        # Extraire les attributs
        attributes = self.extract_attributes_from_lines(lines)
        
        # Appliquer les corrections
        fixed_attributes = self.apply_fixes(resource_type, resource_name, attributes)
        
        # Régénérer le bloc
        return self.generate_resource_block(resource_type, resource_name, fixed_attributes)
    
    def extract_attributes_from_lines(self, lines: List[str]) -> Dict[str, str]:
        """Extrait les attributs d'un bloc de ressource"""
        attributes = {}
        
        for line in lines[1:-1]:  # Ignorer la première et dernière ligne
            line = line.strip()
            if '=' in line and not line.startswith('#'):
                # Parser l'attribut
                parts = line.split('=', 1)
                if len(parts) == 2:
                    attr_name = parts[0].strip()
                    attr_value = parts[1].strip()
                    attributes[attr_name] = attr_value
        
        return attributes
    
    def apply_fixes(self, resource_type: str, resource_name: str, attributes: Dict[str, str]) -> Dict[str, str]:
        """Applique les corrections à une ressource"""
        fixed_attributes = attributes.copy()
        
        # 1. Supprimer les attributs non supportés
        if resource_type in self.supported_attributes:
            supported = self.supported_attributes[resource_type]
            unsupported = [attr for attr in fixed_attributes.keys() if attr not in supported]
            
            for attr in unsupported:
                del fixed_attributes[attr]
                self.fixes_applied.append({
                    'resource': f"{resource_type}.{resource_name}",
                    'fix': f"Suppression de l'attribut non supporté: {attr}"
                })
                self.stats['fixes_applied'] += 1
        
        # 2. Ajouter les attributs requis manquants
        if resource_type in self.required_attributes:
            required = self.required_attributes[resource_type]
            missing_required = [attr for attr in required if attr not in fixed_attributes]
            
            for attr in missing_required:
                default_value = self.get_default_value(resource_type, attr, fixed_attributes)
                fixed_attributes[attr] = default_value
                self.fixes_applied.append({
                    'resource': f"{resource_type}.{resource_name}",
                    'fix': f"Ajout de l'attribut requis: {attr} = {default_value}"
                })
                self.stats['fixes_applied'] += 1
        
        # 3. Corrections spécifiques
        if resource_type == 'keycloak_oidc_identity_provider':
            if 'authorization_url' not in fixed_attributes:
                fixed_attributes['authorization_url'] = '"https://example.com/auth"'
                self.fixes_applied.append({
                    'resource': f"{resource_type}.{resource_name}",
                    'fix': "Ajout de l'URL d'autorisation manquante"
                })
                self.stats['fixes_applied'] += 1
            
            if 'token_url' not in fixed_attributes:
                fixed_attributes['token_url'] = '"https://example.com/token"'
                self.fixes_applied.append({
                    'resource': f"{resource_type}.{resource_name}",
                    'fix': "Ajout de l'URL de token manquante"
                })
                self.stats['fixes_applied'] += 1
        
        # 4. Corriger les incohérences
        if resource_type == 'keycloak_openid_client':
            if (fixed_attributes.get('bearer_only') == 'true' and 
                fixed_attributes.get('public_client') == 'true'):
                fixed_attributes['public_client'] = 'false'
                self.fixes_applied.append({
                    'resource': f"{resource_type}.{resource_name}",
                    'fix': "Correction de l'incohérence bearer_only/public_client"
                })
                self.stats['fixes_applied'] += 1
        
        if self.fixes_applied:
            self.stats['resources_fixed'] += 1
        
        return fixed_attributes
    
    def get_default_value(self, resource_type: str, attr: str, existing_attributes: Dict[str, str]) -> str:
        """Génère une valeur par défaut pour un attribut requis"""
        if attr == 'username' and resource_type == 'keycloak_user':
            first_name = existing_attributes.get('first_name', 'user')
            return f'"{first_name.lower()}"'
        elif attr == 'name' and resource_type in ['keycloak_group', 'keycloak_role']:
            return f'"{resource_type}"'
        elif attr == 'client_id' and resource_type == 'keycloak_openid_client':
            name = existing_attributes.get('name', 'client')
            return f'"{name.lower().replace(" ", "-")}"'
        elif attr == 'alias' and resource_type == 'keycloak_oidc_identity_provider':
            display_name = existing_attributes.get('display_name', 'idp')
            return f'"{display_name.lower().replace(" ", "-")}"'
        elif attr == 'default_scopes' and resource_type == 'keycloak_openid_client_default_scopes':
            return '["profile", "email"]'
        elif attr == 'optional_scopes' and resource_type == 'keycloak_openid_client_optional_scopes':
            return '["address", "phone"]'
        else:
            return f'"{attr}"'
    
    def generate_resource_block(self, resource_type: str, resource_name: str, attributes: Dict[str, str]) -> List[str]:
        """Génère un bloc de ressource corrigé"""
        lines = [f'resource "{resource_type}" "{resource_name}" {{']
        
        for attr_name, attr_value in attributes.items():
            lines.append(f'  {attr_name} = {attr_value}')
        
        lines.append('}')
        lines.append('')
        
        return lines
    
    def fix_directory(self) -> Dict[str, Any]:
        """Corrige tous les fichiers Terraform du répertoire"""
        if not self.terraform_dir.exists():
            return {
                'error': f"Le répertoire {self.terraform_dir} n'existe pas",
                'stats': self.stats,
                'fixes_applied': self.fixes_applied
            }
        
        # Trouver tous les fichiers .tf
        tf_files = list(self.terraform_dir.glob('*.tf'))
        
        if not tf_files:
            return {
                'error': f"Aucun fichier .tf trouvé dans {self.terraform_dir}",
                'stats': self.stats,
                'fixes_applied': self.fixes_applied
            }
        
        # Corriger chaque fichier
        for tf_file in tf_files:
            self.fix_file(tf_file)
        
        return {
            'stats': self.stats,
            'fixes_applied': self.fixes_applied,
            'files_processed': len(tf_files)
        }
    
    def generate_report(self, results: Dict[str, Any]) -> str:
        """Génère un rapport de correction"""
        report = []
        report.append("=" * 60)
        report.append("RAPPORT DE CORRECTION TERRAFORM")
        report.append("=" * 60)
        
        if 'error' in results:
            report.append(f"❌ ERREUR: {results['error']}")
            return "\n".join(report)
        
        stats = results['stats']
        
        # Statistiques
        report.append(f"📊 STATISTIQUES:")
        report.append(f"   • Fichiers traités: {stats['files_processed']}")
        report.append(f"   • Ressources corrigées: {stats['resources_fixed']}")
        report.append(f"   • Corrections appliquées: {stats['fixes_applied']}")
        report.append("")
        
        # Corrections appliquées
        if self.fixes_applied:
            report.append("🔧 CORRECTIONS APPLIQUÉES:")
            for fix in self.fixes_applied:
                report.append(f"   • {fix['resource']}: {fix['fix']}")
            report.append("")
        
        # Résumé
        if stats['fixes_applied'] > 0:
            report.append(f"✅ {stats['fixes_applied']} correction(s) appliquée(s) avec succès!")
        else:
            report.append("ℹ️  Aucune correction nécessaire.")
        
        return "\n".join(report)

def main():
    """Fonction principale"""
    parser = argparse.ArgumentParser(description="Corriger automatiquement le code Terraform")
    parser.add_argument("terraform_dir", help="Répertoire contenant les fichiers Terraform")
    parser.add_argument("--output", "-o", help="Fichier de sortie pour le rapport")
    parser.add_argument("--json", action="store_true", help="Sortie en format JSON")
    parser.add_argument("--verbose", "-v", action="store_true", help="Mode verbeux")
    
    args = parser.parse_args()
    
    # Créer le correcteur
    fixer = TerraformFixer(args.terraform_dir)
    
    # Corriger le répertoire
    results = fixer.fix_directory()
    
    # Générer le rapport
    if args.json:
        print(json.dumps(results, indent=2, ensure_ascii=False))
    else:
        report = fixer.generate_report(results)
        print(report)
        
        # Sauvegarder le rapport si demandé
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(report)
            print(f"\n📄 Rapport sauvegardé dans: {args.output}")

if __name__ == "__main__":
    main()
