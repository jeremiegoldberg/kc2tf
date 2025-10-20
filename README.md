## Prérequis

- Python 3.x
- Dépendances Python:
  ```bash
  pip install requests
  ```
  
Un compte Keycloak avec des droits suffisants sur le realm ciblé (souvent un compte administrateur de realm).

## Générer les configurations Terraform

Exécutez le script pour exporter les objets Keycloak vers des fichiers Terraform.

Commande générale:
```bash
python /home/git/external/kc2tf/bcros-keycloak-terraform/kc2tf.py main <kc_username> <kc_password> <kc_base_url> <realm_name>
```

Exemple:
```bash
python /home/git/external/kc2tf/bcros-keycloak-terraform/kc2tf.py main admin 'StrongP@ss!' https://keycloak.example.com bcregistry
```

Notes:
- Les fichiers `.tf` sont générés et copiés dans `Terraform/`.
- Les configurations générées peuvent nécessiter de légers ajustements manuels (p. ex. renommage de ressources en double, correction de contraintes).
- Consultez les fichiers `.tf` du dépôt pour identifier ce qui reste à créer manuellement (p. ex. fournisseurs d’IDP).
- Les secrets des clients sont exportés dans un fichier séparé (`client_secrets.tfvars`). Les secrets IDP restent à fournir manuellement.

## Source of inspiration

[Health Gateway](https://github.com/bcgov/healthgateway/tree/dev/Tools/KeyCloak)
