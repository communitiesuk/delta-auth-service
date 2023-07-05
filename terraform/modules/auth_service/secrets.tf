# See api/README.md and terraform/test/main.tf in the Delta repository for setup instructions
data "aws_secretsmanager_secret" "saml_private_key" {
  name = "api-saml-private-key-${var.environment}"
}

data "aws_secretsmanager_secret" "saml_certificate" {
  name = "api-saml-certificate-${var.environment}"
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
