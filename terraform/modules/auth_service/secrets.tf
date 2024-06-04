# See api/README.md and terraform/test/main.tf in the Delta repository for setup instructions
data "aws_secretsmanager_secret" "saml_private_key" {
  name = "api-saml-private-key-${var.environment}"
}

data "aws_secretsmanager_secret" "saml_certificate" {
  name = "api-saml-certificate-${var.environment}"
}

# TODO 836 ticket specific release action: manually create these secrets, copying the current values from the API secrets, so they can be referenced here
# See api/README.md and terraform/test/main.tf in the Delta repository for setup instructions
data "aws_secretsmanager_secret" "delta_saml_private_key" {
  name = "delta-saml-private-key-${var.environment}"
}

data "aws_secretsmanager_secret" "delta_saml_certificate" {
  name = "delta-saml-certificate-${var.environment}"
}

resource "aws_kms_key" "auth_service" {
  description         = "auth-service-${var.environment}"
  enable_key_rotation = true

  tags = {
    "terraform-plan-read" = true
  }
}

resource "aws_kms_alias" "auth_service" {
  target_key_id = aws_kms_key.auth_service.key_id
  name          = "alias/auth-service-${var.environment}"
}

data "aws_secretsmanager_secret" "active_directory_service_user" {
  name = "auth-service-ldap-user-password-${var.environment}"

  //noinspection HCLUnknownBlockType
  lifecycle {
    //noinspection HCLUnknownBlockType
    postcondition {
      //noinspection HILUnresolvedReference
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

resource "random_id" "cookie_mac_key" {
  byte_length = 32
}

resource "aws_secretsmanager_secret" "cookie_mac_key" {
  name                    = "tf-${var.environment}-auth-service-cookie-mac-key"
  description             = "Shared hex MAC key for signing auth service session cookies"
  recovery_window_in_days = 0
  kms_key_id              = aws_kms_key.auth_service.arn
}

resource "aws_secretsmanager_secret_version" "cookie_mac_key" {
  secret_id     = aws_secretsmanager_secret.cookie_mac_key.id
  secret_string = random_id.cookie_mac_key.hex
}

# Ideally we'd create this and set it to an initial value of "[]", then ignore changes
# but that's not currently possible in Terraform https://github.com/hashicorp/terraform-provider-aws/issues/10898
data "aws_secretsmanager_secret" "sso_config" {
  name = "auth-service-sso-config-${var.environment}"

  //noinspection HCLUnknownBlockType
  lifecycle {
    //noinspection HCLUnknownBlockType
    postcondition {
      //noinspection HILUnresolvedReference
      condition     = self.kms_key_id == aws_kms_key.auth_service.arn
      error_message = "Secret must use the auth service KMS key"
    }
  }
}

data "aws_secretsmanager_secret" "delta_ses_credentials" {
  count = var.mail_settings.smtp_secret_name != null ? 1 : 0

  name = var.mail_settings.smtp_secret_name
}

resource "random_password" "client_secret_delta_api" {
  length  = 32
  special = false
}

# No CMK, secret is shared between multiple services
# tfsec:ignore:aws-ssm-secret-use-customer-key
resource "aws_secretsmanager_secret" "client_secret_delta_api" {
  name                    = "tf-${var.environment}-delta-api-client-secret"
  description             = "Shared secret for Delta API Gateway -> auth service for internal API calls"
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "client_secret_delta_api" {
  secret_id     = aws_secretsmanager_secret.client_secret_delta_api.id
  secret_string = random_password.client_secret_delta_api.result
}
