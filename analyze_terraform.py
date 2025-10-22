#!/usr/bin/env python3
"""
Script pour analyser le code Terraform généré
Vérifie la conformité avec la documentation officielle du provider keycloak/keycloak
Version: 1.0.0
"""

import os
import re
import json
import argparse
from typing import Dict, List, Any, Tuple
from pathlib import Path

class TerraformAnalyzer:
    """Classe pour analyser et corriger le code Terraform généré"""
    
    def __init__(self, terraform_dir: str, fix_mode: bool = False):
        self.terraform_dir = Path(terraform_dir)
        self.fix_mode = fix_mode
        self.issues = []
        self.fixes_applied = []
        self.stats = {
            'total_resources': 0,
            'valid_resources': 0,
            'invalid_resources': 0,
            'warnings': 0,
            'errors': 0,
            'fixes_applied': 0
        }
        
        # Attributs supportés par chaque ressource selon la documentation officielle
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
    
    def analyze_file(self, file_path: Path) -> List[Dict[str, Any]]:
        """Analyse un fichier Terraform"""
        issues = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Extraire les ressources
            resources = self.extract_resources(content)
            
            for resource in resources:
                resource_issues = self.analyze_resource(resource)
                issues.extend(resource_issues)
                
        except Exception as e:
            issues.append({
                'type': 'error',
                'file': str(file_path),
                'message': f"Erreur lors de la lecture du fichier: {e}"
            })
        
        return issues
    
    def extract_resources(self, content: str) -> List[Dict[str, Any]]:
        """Extrait les ressources Terraform du contenu"""
        resources = []
        
        # Pattern pour extraire les blocs de ressources
        pattern = r'resource\s+"([^"]+)"\s+"([^"]+)"\s*\{([^}]+)\}'
        matches = re.finditer(pattern, content, re.MULTILINE | re.DOTALL)
        
        for match in matches:
            resource_type = match.group(1)
            resource_name = match.group(2)
            resource_body = match.group(3)
            
            # Extraire les attributs
            attributes = self.extract_attributes(resource_body)
            
            resources.append({
                'type': resource_type,
                'name': resource_name,
                'attributes': attributes,
                'body': resource_body
            })
        
        return resources
    
    def extract_attributes(self, body: str) -> Dict[str, str]:
        """Extrait les attributs d'une ressource"""
        attributes = {}
        
        # Pattern pour extraire les attributs
        pattern = r'(\w+)\s*=\s*([^=\n]+)'
        matches = re.finditer(pattern, body)
        
        for match in matches:
            attr_name = match.group(1).strip()
            attr_value = match.group(2).strip()
            attributes[attr_name] = attr_value
        
        return attributes
    
    def analyze_resource(self, resource: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyse une ressource Terraform"""
        issues = []
        resource_type = resource['type']
        resource_name = resource['name']
        attributes = resource['attributes']
        
        self.stats['total_resources'] += 1
        
        # Vérifier les attributs requis
        if resource_type in self.required_attributes:
            required = self.required_attributes[resource_type]
            missing_required = [attr for attr in required if attr not in attributes]
            
            if missing_required:
                if self.fix_mode:
                    # Corriger automatiquement les attributs requis manquants
                    fixed_attributes = self.fix_missing_required_attributes(resource_type, missing_required, attributes)
                    if fixed_attributes:
                        resource['attributes'] = fixed_attributes
                        self.fixes_applied.append({
                            'resource': f"{resource_type}.{resource_name}",
                            'fix': f"Ajout des attributs requis: {', '.join(missing_required)}"
                        })
                        self.stats['fixes_applied'] += 1
                        self.stats['valid_resources'] += 1
                    else:
                        issues.append({
                            'type': 'error',
                            'resource': f"{resource_type}.{resource_name}",
                            'message': f"Attributs requis manquants: {', '.join(missing_required)}"
                        })
                        self.stats['errors'] += 1
                else:
                    issues.append({
                        'type': 'error',
                        'resource': f"{resource_type}.{resource_name}",
                        'message': f"Attributs requis manquants: {', '.join(missing_required)}"
                    })
                    self.stats['errors'] += 1
            else:
                self.stats['valid_resources'] += 1
        
        # Vérifier les attributs non supportés
        if resource_type in self.supported_attributes:
            supported = self.supported_attributes[resource_type]
            unsupported = [attr for attr in attributes.keys() if attr not in supported]
            
            if unsupported:
                if self.fix_mode:
                    # Supprimer les attributs non supportés
                    fixed_attributes = {k: v for k, v in attributes.items() if k in supported}
                    resource['attributes'] = fixed_attributes
                    self.fixes_applied.append({
                        'resource': f"{resource_type}.{resource_name}",
                        'fix': f"Suppression des attributs non supportés: {', '.join(unsupported)}"
                    })
                    self.stats['fixes_applied'] += 1
                    self.stats['valid_resources'] += 1
                else:
                    issues.append({
                        'type': 'warning',
                        'resource': f"{resource_type}.{resource_name}",
                        'message': f"Attributs non supportés: {', '.join(unsupported)}"
                    })
                    self.stats['warnings'] += 1
                    self.stats['invalid_resources'] += 1
        
        # Vérifications spécifiques par type de ressource
        if resource_type == 'keycloak_realm':
            issues.extend(self.analyze_realm(resource))
        elif resource_type == 'keycloak_openid_client':
            issues.extend(self.analyze_client(resource))
        elif resource_type == 'keycloak_oidc_identity_provider':
            issues.extend(self.analyze_identity_provider(resource))
        
        return issues
    
    def analyze_realm(self, resource: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyse spécifique pour keycloak_realm"""
        issues = []
        attributes = resource['attributes']
        
        # Vérifier la politique de mot de passe
        if 'password_policy' in attributes:
            policy = attributes['password_policy']
            if not self.is_valid_password_policy(policy):
                issues.append({
                    'type': 'warning',
                    'resource': f"keycloak_realm.{resource['name']}",
                    'message': f"Politique de mot de passe potentiellement invalide: {policy}"
                })
        
        return issues
    
    def analyze_client(self, resource: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyse spécifique pour keycloak_openid_client"""
        issues = []
        attributes = resource['attributes']
        
        # Vérifier la cohérence des flows
        if attributes.get('bearer_only') == 'true' and attributes.get('public_client') == 'true':
            issues.append({
                'type': 'error',
                'resource': f"keycloak_openid_client.{resource['name']}",
                'message': "Un client ne peut pas être à la fois bearer_only et public_client"
            })
        
        # Vérifier les URLs de redirection
        if 'valid_redirect_uris' in attributes:
            uris = attributes['valid_redirect_uris']
            if not self.is_valid_redirect_uris(uris):
                issues.append({
                    'type': 'warning',
                    'resource': f"keycloak_openid_client.{resource['name']}",
                    'message': "URLs de redirection potentiellement invalides"
                })
        
        return issues
    
    def analyze_identity_provider(self, resource: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyse spécifique pour keycloak_oidc_identity_provider"""
        issues = []
        attributes = resource['attributes']
        
        # Vérifier les URLs OIDC
        required_urls = ['authorization_url', 'token_url']
        missing_urls = [url for url in required_urls if url not in attributes or not attributes[url]]
        
        if missing_urls:
            issues.append({
                'type': 'error',
                'resource': f"keycloak_oidc_identity_provider.{resource['name']}",
                'message': f"URLs OIDC manquantes: {', '.join(missing_urls)}"
            })
        
        return issues
    
    def is_valid_password_policy(self, policy: str) -> bool:
        """Vérifie si une politique de mot de passe est valide"""
        # Vérifications basiques
        if not policy or len(policy) < 5:
            return False
        
        # Vérifier la présence de mots-clés valides
        valid_keywords = ['length', 'digits', 'lowerCase', 'upperCase', 'specialChars']
        has_valid_keyword = any(keyword in policy for keyword in valid_keywords)
        
        return has_valid_keyword
    
    def is_valid_redirect_uris(self, uris: str) -> bool:
        """Vérifie si les URLs de redirection sont valides"""
        try:
            # Parser la liste JSON
            uri_list = json.loads(uris)
            if not isinstance(uri_list, list):
                return False
            
            # Vérifier chaque URI
            for uri in uri_list:
                if not isinstance(uri, str) or not uri:
                    return False
                # Vérifications basiques d'URL
                if not (uri.startswith('http://') or uri.startswith('https://')):
                    return False
            
            return True
        except:
            return False
    
    def fix_missing_required_attributes(self, resource_type: str, missing_attributes: List[str], current_attributes: Dict[str, str]) -> Dict[str, str]:
        """Corrige automatiquement les attributs requis manquants"""
        fixed_attributes = current_attributes.copy()
        
        for attr in missing_attributes:
            if attr == 'username' and resource_type == 'keycloak_user':
                # Générer un nom d'utilisateur basé sur le nom de la ressource
                resource_name = current_attributes.get('first_name', 'user')
                fixed_attributes[attr] = f'"{resource_name.lower()}"'
            elif attr == 'name' and resource_type == 'keycloak_group':
                # Utiliser le nom de la ressource comme nom du groupe
                fixed_attributes[attr] = f'"{resource_type}"'
            elif attr == 'name' and resource_type == 'keycloak_role':
                # Utiliser le nom de la ressource comme nom du rôle
                fixed_attributes[attr] = f'"{resource_type}"'
            elif attr == 'client_id' and resource_type == 'keycloak_openid_client':
                # Générer un client_id basé sur le nom
                name = current_attributes.get('name', 'client')
                fixed_attributes[attr] = f'"{name.lower().replace(" ", "-")}"'
            elif attr == 'alias' and resource_type == 'keycloak_oidc_identity_provider':
                # Générer un alias basé sur le display_name
                display_name = current_attributes.get('display_name', 'idp')
                fixed_attributes[attr] = f'"{display_name.lower().replace(" ", "-")}"'
            elif attr == 'authorization_url' and resource_type == 'keycloak_oidc_identity_provider':
                # URL d'autorisation par défaut
                fixed_attributes[attr] = '"https://example.com/auth"'
            elif attr == 'token_url' and resource_type == 'keycloak_oidc_identity_provider':
                # URL de token par défaut
                fixed_attributes[attr] = '"https://example.com/token"'
            elif attr == 'default_scopes' and resource_type == 'keycloak_openid_client_default_scopes':
                # Scopes par défaut
                fixed_attributes[attr] = '["profile", "email"]'
            elif attr == 'optional_scopes' and resource_type == 'keycloak_openid_client_optional_scopes':
                # Scopes optionnels
                fixed_attributes[attr] = '["address", "phone"]'
            else:
                # Valeur par défaut générique
                fixed_attributes[attr] = f'"{attr}"'
        
        return fixed_attributes
    
    def fix_identity_provider_urls(self, resource: Dict[str, Any]) -> bool:
        """Corrige les URLs manquantes pour les identity providers"""
        attributes = resource['attributes']
        
        if 'authorization_url' not in attributes or not attributes['authorization_url']:
            attributes['authorization_url'] = '"https://example.com/auth"'
            return True
        
        if 'token_url' not in attributes or not attributes['token_url']:
            attributes['token_url'] = '"https://example.com/token"'
            return True
        
        return False
    
    def fix_client_consistency(self, resource: Dict[str, Any]) -> bool:
        """Corrige les incohérences dans les clients OIDC"""
        attributes = resource['attributes']
        fixed = False
        
        # Corriger bearer_only + public_client
        if attributes.get('bearer_only') == 'true' and attributes.get('public_client') == 'true':
            attributes['public_client'] = 'false'
            fixed = True
        
        return fixed
    
    def regenerate_terraform_file(self, file_path: Path, resources: List[Dict[str, Any]]) -> str:
        """Régénère le contenu d'un fichier Terraform avec les corrections"""
        content_lines = []
        
        for resource in resources:
            resource_type = resource['type']
            resource_name = resource['name']
            attributes = resource['attributes']
            
            # Générer le bloc de ressource
            content_lines.append(f'resource "{resource_type}" "{resource_name}" {{')
            
            for attr_name, attr_value in attributes.items():
                content_lines.append(f'  {attr_name} = {attr_value}')
            
            content_lines.append('}')
            content_lines.append('')
        
        return '\n'.join(content_lines)
    
    def analyze_directory(self) -> Dict[str, Any]:
        """Analyse tous les fichiers Terraform du répertoire"""
        all_issues = []
        fixed_files = []
        
        if not self.terraform_dir.exists():
            return {
                'error': f"Le répertoire {self.terraform_dir} n'existe pas",
                'issues': [],
                'stats': self.stats,
                'fixed_files': []
            }
        
        # Analyser tous les fichiers .tf
        tf_files = list(self.terraform_dir.glob('*.tf'))
        
        if not tf_files:
            return {
                'error': f"Aucun fichier .tf trouvé dans {self.terraform_dir}",
                'issues': [],
                'stats': self.stats,
                'fixed_files': []
            }
        
        for tf_file in tf_files:
            file_issues = self.analyze_file(tf_file)
            for issue in file_issues:
                issue['file'] = str(tf_file)
            all_issues.extend(file_issues)
            
            # Si en mode correction, régénérer le fichier
            if self.fix_mode and self.fixes_applied:
                # Extraire les ressources corrigées
                with open(tf_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                resources = self.extract_resources(content)
                
                # Appliquer les corrections spécifiques
                for resource in resources:
                    if resource['type'] == 'keycloak_oidc_identity_provider':
                        if self.fix_identity_provider_urls(resource):
                            self.fixes_applied.append({
                                'resource': f"{resource['type']}.{resource['name']}",
                                'fix': "Ajout des URLs OIDC manquantes"
                            })
                            self.stats['fixes_applied'] += 1
                    
                    if resource['type'] == 'keycloak_openid_client':
                        if self.fix_client_consistency(resource):
                            self.fixes_applied.append({
                                'resource': f"{resource['type']}.{resource['name']}",
                                'fix': "Correction de l'incohérence bearer_only/public_client"
                            })
                            self.stats['fixes_applied'] += 1
                
                # Régénérer le fichier
                new_content = self.regenerate_terraform_file(tf_file, resources)
                
                # Sauvegarder le fichier corrigé
                with open(tf_file, 'w', encoding='utf-8') as f:
                    f.write(new_content)
                
                fixed_files.append(str(tf_file))
        
        return {
            'issues': all_issues,
            'stats': self.stats,
            'files_analyzed': len(tf_files),
            'fixed_files': fixed_files,
            'fixes_applied': self.fixes_applied
        }
    
    def generate_report(self, results: Dict[str, Any]) -> str:
        """Génère un rapport d'analyse"""
        report = []
        report.append("=" * 60)
        if self.fix_mode:
            report.append("RAPPORT DE CORRECTION TERRAFORM")
        else:
            report.append("RAPPORT D'ANALYSE TERRAFORM")
        report.append("=" * 60)
        
        if 'error' in results:
            report.append(f"❌ ERREUR: {results['error']}")
            return "\n".join(report)
        
        stats = results['stats']
        issues = results['issues']
        
        # Statistiques
        report.append(f"📊 STATISTIQUES:")
        report.append(f"   • Fichiers analysés: {results.get('files_analyzed', 0)}")
        report.append(f"   • Ressources totales: {stats['total_resources']}")
        report.append(f"   • Ressources valides: {stats['valid_resources']}")
        report.append(f"   • Ressources invalides: {stats['invalid_resources']}")
        report.append(f"   • Avertissements: {stats['warnings']}")
        report.append(f"   • Erreurs: {stats['errors']}")
        
        if self.fix_mode:
            report.append(f"   • Corrections appliquées: {stats['fixes_applied']}")
            report.append(f"   • Fichiers corrigés: {len(results.get('fixed_files', []))}")
        report.append("")
        
        # Afficher les corrections appliquées
        if self.fix_mode and results.get('fixes_applied'):
            report.append("🔧 CORRECTIONS APPLIQUÉES:")
            for fix in results['fixes_applied']:
                report.append(f"   • {fix['resource']}: {fix['fix']}")
            report.append("")
        
        # Grouper les issues par type
        errors = [issue for issue in issues if issue['type'] == 'error']
        warnings = [issue for issue in issues if issue['type'] == 'warning']
        
        # Afficher les erreurs
        if errors:
            report.append("🚨 ERREURS:")
            for error in errors:
                report.append(f"   • {error['resource']}: {error['message']}")
            report.append("")
        
        # Afficher les avertissements
        if warnings:
            report.append("⚠️  AVERTISSEMENTS:")
            for warning in warnings:
                report.append(f"   • {warning['resource']}: {warning['message']}")
            report.append("")
        
        # Résumé
        if self.fix_mode:
            if stats['fixes_applied'] > 0:
                report.append(f"✅ {stats['fixes_applied']} correction(s) appliquée(s) avec succès!")
            else:
                report.append("ℹ️  Aucune correction nécessaire.")
        else:
            if not errors and not warnings:
                report.append("✅ Aucun problème détecté! Le code Terraform est conforme.")
            else:
                report.append(f"📋 RÉSUMÉ: {len(errors)} erreur(s), {len(warnings)} avertissement(s)")
        
        return "\n".join(report)

def main():
    """Fonction principale"""
    parser = argparse.ArgumentParser(description="Analyser et corriger le code Terraform généré")
    parser.add_argument("terraform_dir", help="Répertoire contenant les fichiers Terraform")
    parser.add_argument("--output", "-o", help="Fichier de sortie pour le rapport")
    parser.add_argument("--json", action="store_true", help="Sortie en format JSON")
    parser.add_argument("--verbose", "-v", action="store_true", help="Mode verbeux")
    parser.add_argument("--fix", action="store_true", help="Corriger automatiquement les problèmes détectés")
    
    args = parser.parse_args()
    
    # Créer l'analyseur
    analyzer = TerraformAnalyzer(args.terraform_dir, fix_mode=args.fix)
    
    # Analyser le répertoire
    results = analyzer.analyze_directory()
    
    # Générer le rapport
    if args.json:
        print(json.dumps(results, indent=2, ensure_ascii=False))
    else:
        report = analyzer.generate_report(results)
        print(report)
        
        # Sauvegarder le rapport si demandé
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(report)
            print(f"\n📄 Rapport sauvegardé dans: {args.output}")
        
        # Afficher les fichiers corrigés
        if args.fix and results.get('fixed_files'):
            print(f"\n📁 Fichiers corrigés:")
            for file_path in results['fixed_files']:
                print(f"   • {file_path}")

if __name__ == "__main__":
    main()
