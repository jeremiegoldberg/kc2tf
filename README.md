## Service Account

Import terraform.json via admin console to generate a service account.
- Generate credentials and assign realm-admin role

## Generate Terraform configs

Run kc2tf.py script to export Keycloak objects into terraform configs.
Generated configs may need minor human intervention, i.e. renaming duplicate resource, fixing constraint violations.
Take a look at the .tf files in the repo to see which files still need to be added manually (e.g. IDP providers)
The script will export client secrets into a separate file, however IDP secrets need to be supplied manually.

## Source of inspiration

[Health Gateway](https://github.com/bcgov/healthgateway/tree/dev/Tools/KeyCloak)
