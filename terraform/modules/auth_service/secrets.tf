# See api/README.md and terraform/test/main.tf in the Delta repository for setup instructions
data "aws_secretsmanager_secret" "saml_private_key" {
  name = "api-saml-private-key-${var.environment}"
}

data "aws_secretsmanager_secret" "saml_certificate" {
  name = "api-saml-certificate-${var.environment}"
}

resource "aws_kms_key" "auth_service" {
  description         = "auth-service-${var.environment}"
  enable_key_rotation = true
}

resource "aws_kms_alias" "auth_service" {
  target_key_id = aws_kms_key.auth_service.key_id
  name          = "alias/auth-service-${var.environment}"
}

data "aws_secretsmanager_secret" "active_directory_service_user" {
  name = "auth-service-ldap-user-password-${var.environment}"

  lifecycle {
    postcondition {
      condition     = self.kms_key_id == aws_kms_key.auth_service.arn
      error_message = "Secret must use the auth service KMS key"
    }
  }
}

resource "random_password" "ml_client_secret" {
  length  = 32
  special = false
}

resource "aws_secretsmanager_secret" "ml_client_secret" {
  name                    = "tf-${var.environment}-auth-service-marklogic-client-secret"
  description             = "Shared secret for MarkLogic -> auth service for internal API calls"
  kms_key_id              = var.ml_secret_kms_key_arn
  recovery_window_in_days = 0

  tags = {
    "delta-marklogic-deploy-read" : var.environment
  }
}

resource "aws_secretsmanager_secret_version" "ml_client_secret" {
  secret_id     = aws_secretsmanager_secret.ml_client_secret.id
  secret_string = random_password.ml_client_secret.result
}

resource "random_password" "delta_website_client_secret" {
  length  = 32
  special = false
}

# No CMK, secret is shared between multiple services
# tfsec:ignore:aws-ssm-secret-use-customer-key
resource "aws_secretsmanager_secret" "delta_website_client_secret" {
  name                    = "tf-${var.environment}-auth-delta-website-client-secret"
  description             = "Shared secret for Delta Website -> auth service for internal API calls"
  recovery_window_in_days = 0

  tags = {
    "delta-marklogic-deploy-read" : var.environment
  }
}

resource "aws_secretsmanager_secret_version" "delta_website_client_secret" {
  secret_id     = aws_secretsmanager_secret.delta_website_client_secret.id
  secret_string = random_password.delta_website_client_secret.result
}

resource "random_password" "database_password" {
  length  = 32
  special = false
}

resource "aws_secretsmanager_secret" "database_password" {
  name                    = "tf-${var.environment}-auth-service-database-password"
  description             = "Password for auth service database user (${local.database_username})"
  recovery_window_in_days = 0
  kms_key_id              = aws_kms_key.auth_service.arn
}

resource "aws_secretsmanager_secret_version" "database_password" {
  secret_id     = aws_secretsmanager_secret.database_password.id
  secret_string = random_password.database_password.result
}
