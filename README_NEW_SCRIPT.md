# Script de Conversion Keycloak vers Terraform

Ce script Python moderne convertit un export Keycloak en code Terraform pour le provider `keycloak/keycloak`.

## Fonctionnalités

- ✅ **Conversion complète** : Realm, clients, rôles, groupes, utilisateurs, fournisseurs d'identité
- ✅ **Provider moderne** : Utilise le provider `keycloak/keycloak` officiel
- ✅ **Code Terraform propre** : Génère du code Terraform lisible et maintenable
- ✅ **Gestion des erreurs** : Validation et messages d'erreur clairs
- ✅ **Mode debug** : Affichage détaillé des opérations
- ✅ **Structure modulaire** : Fichiers séparés par type de ressource

## Installation

### Prérequis
- Python 3.7+
- Export Keycloak (fichier JSON)

### Dépendances
```bash
pip install urllib3
```

## Utilisation

### Commande de base
```bash
python keycloak_to_terraform.py export.json
```

### Options avancées
```bash
python keycloak_to_terraform.py export.json \
  --output-dir "my_terraform" \
  --debug
```

### Paramètres

| Paramètre | Description | Requis |
|-----------|-------------|---------|
| `export_file` | Fichier d'export Keycloak (JSON) | ✅ |
| `--output-dir` | Répertoire de sortie (défaut: `terraform_output`) | ❌ |
| `--debug` | Mode debug | ❌ |

## Structure de sortie

Le script génère les fichiers suivants dans le répertoire de sortie :

```
terraform_output/
├── provider.tf              # Configuration du provider
├── realm.tf                 # Configuration du realm
├── clients.tf               # Clients OAuth/OpenID Connect
├── roles.tf                 # Rôles du realm
├── groups.tf                # Groupes et hiérarchie
├── users.tf                 # Utilisateurs
└── identity_providers.tf    # Fournisseurs d'identité
```

## Exemples de sortie

### Provider (provider.tf)
```hcl
terraform {
  required_providers {
    keycloak = {
      source  = "keycloak/keycloak"
      version = "~> 4.0"
    }
  }
}

# Configuration du provider Keycloak
# Remplacez les valeurs par vos paramètres de connexion
provider "keycloak" {
  client_id     = "admin-cli"
  username      = "admin"  # Remplacez par votre nom d'utilisateur
  password      = "password"  # Remplacez par votre mot de passe
  url           = "https://keycloak.example.com"  # Remplacez par votre URL Keycloak
  initial_login = true
}
```

### Realm (realm.tf)
```hcl
resource "keycloak_realm" "myrealm" {
  realm                = "myrealm"
  display_name         = "My Realm"
  enabled              = true
  
  password_policy      = "length(8) and digits(2) and lowerCase(2) and upperCase(2) and specialChars(2)"
  brute_force_protection {
    permanent_lockout                = false
    max_login_failures              = 30
    wait_increment_seconds          = 60
    max_failure_wait_seconds        = 900
    failure_reset_time_seconds      = 43200
  }
  
  sso_session_idle_timeout         = 1800
  sso_session_max_lifespan         = 36000
  offline_session_idle_timeout     = 2592000
  offline_session_max_lifespan_enabled = true
  offline_session_max_lifespan     = 5184000
  
  access_token_lifespan            = 300
  access_token_lifespan_for_implicit_flow = 900
  refresh_token_max_reuse         = 0
  access_code_lifespan            = 60
  access_code_lifespan_user_action = 300
  access_code_lifespan_login      = 1800
  action_token_generated_by_admin_lifespan = 43200
  action_token_generated_by_user_lifespan = 300
  oauth2_device_code_lifespan    = 600
  oauth2_device_polling_interval = 5
}
```

### Client (clients.tf)
```hcl
resource "keycloak_openid_client" "my_app" {
  realm_id                     = keycloak_realm.myrealm.id
  client_id                    = "my-app"
  name                         = "My Application"
  enabled                      = true
  client_authenticator_type    = "client-secret"
  standard_flow_enabled        = true
  implicit_flow_enabled        = false
  direct_access_grants_enabled = false
  service_accounts_enabled     = false
  public_client                = false
  bearer_only                  = false
  
  valid_redirect_uris = ["http://localhost:3000/*"]
  web_origins = ["http://localhost:3000"]
  admin_url = "http://localhost:3000"
  base_url = "http://localhost:3000"
  root_url = "http://localhost:3000"
}
```

## Avantages par rapport à l'ancien script

1. **Code moderne** : Utilise les dernières pratiques Python
2. **Provider officiel** : `keycloak/keycloak` au lieu de `mrparkers/keycloak`
3. **Structure claire** : Fichiers séparés par type de ressource
4. **Gestion d'erreurs** : Validation et messages d'erreur appropriés
5. **Documentation** : Code bien documenté et lisible
6. **Flexibilité** : Options de configuration avancées
7. **Maintenance** : Plus facile à maintenir et étendre

## Déploiement

1. **Initialiser Terraform** :
   ```bash
   cd terraform_output
   terraform init
   ```

2. **Planifier les changements** :
   ```bash
   terraform plan
   ```

3. **Appliquer la configuration** :
   ```bash
   terraform apply
   ```

## Dépannage

### Mode debug
```bash
python keycloak_to_terraform.py export.json --debug
```

### Vérification des fichiers
```bash
ls -la terraform_output/
cat terraform_output/provider.tf
```

## Support

Pour toute question ou problème, consultez la documentation du provider Keycloak :
- [Provider keycloak/keycloak](https://registry.terraform.io/providers/keycloak/keycloak/latest/docs)
- [Documentation Keycloak](https://www.keycloak.org/documentation)
