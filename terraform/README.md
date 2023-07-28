# Infrastructure

Terraform configuration for the Delta Auth Service.

Depends on <https://github.com/communitiesuk/delta-common-infrastructure> and we follow the same patterns.

## Creating a new environment

Common Infrastructure must be set up first.

1. Initialise Terraform, then create the KMS key

   ```shell
   terraform init
   terraform apply -target module.auth_service.aws_kms_key.auth_service
   ```

2. Create a service user in the environment's Active Directory instance with username "auth-service.app" and groups
   "dluhc-service-users" and "AWS Delegated Administrators",
   then create a new secret `auth-service-ldap-user-password-${var.environment}` containing the user's password and using the KMS key created above
3. Create the rest of the infrastructure with `terraform apply`
