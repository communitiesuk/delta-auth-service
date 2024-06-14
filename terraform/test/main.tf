terraform {
  backend "s3" {
    bucket         = "data-collection-service-tfstate-dev"
    encrypt        = true
    kms_key_id     = "arn:aws:kms:eu-west-1:486283582667:key/547ae46f-f57e-45f6-bcfd-9403bed9ec75"
    dynamodb_table = "tfstate-locks"
    key            = "auth-service-test"
    region         = "eu-west-1"
  }

  required_version = "~> 1.7.0"
}

provider "aws" {
  region = "eu-west-1"

  default_tags {
    tags = var.default_tags
  }
}

data "terraform_remote_state" "common_infra" {
  backend = "s3"
  config = {
    bucket = "data-collection-service-tfstate-dev"
    key    = "common-infra-test"
    region = "eu-west-1"
  }
}

locals {
  environment                    = "test"
  cloudwatch_log_expiration_days = 30
  dclg_access_group_notification_settings = {
    enabled                     = true
    additional_recipient_emails = ["Group-DLUHCDeltaDevNotifications+test@softwire.com"]
  }
}

resource "random_password" "delta_website_local_dev_client_secret" {
  length  = 32
  special = false
}

# Test only
# tfsec:ignore:aws-ssm-secret-use-customer-key
resource "aws_secretsmanager_secret" "delta_website_local_dev_client_secret" {
  name                    = "tf-${local.environment}-auth-service-website-local-dev-client-secret"
  description             = "Client secret for developing Delta locally against the auth service test environment"
  recovery_window_in_days = 0

  tags = {
    "delta-marklogic-deploy-read" : local.environment
  }
}

resource "aws_secretsmanager_secret_version" "delta_website_local_dev_client_secret" {
  secret_id     = aws_secretsmanager_secret.delta_website_local_dev_client_secret.id
  secret_string = random_password.delta_website_local_dev_client_secret.result
}

module "auth_service" {
  source                         = "../modules/auth_service"
  subnet_ids                     = data.terraform_remote_state.common_infra.outputs.auth_service_private_subnet_ids
  environment                    = local.environment
  container_image                = "468442790030.dkr.ecr.eu-west-1.amazonaws.com/delta-auth-service:${var.image_tag}"
  vpc_id                         = data.terraform_remote_state.common_infra.outputs.vpc_id
  cloudwatch_log_expiration_days = local.cloudwatch_log_expiration_days
  alarms_sns_topic_arn           = data.terraform_remote_state.common_infra.outputs.alarms_sns_topic_arn
  internal_alb                   = data.terraform_remote_state.common_infra.outputs.auth_internal_alb
  //noinspection HILUnresolvedReference
  external_alb          = data.terraform_remote_state.common_infra.outputs.public_albs.auth
  ml_secret_kms_key_arn = data.terraform_remote_state.common_infra.outputs.deploy_user_kms_key_arn
  //noinspection HILUnresolvedReference
  delta_hostname            = data.terraform_remote_state.common_infra.outputs.public_albs.delta.primary_hostname
  bastion_security_group_id = data.terraform_remote_state.common_infra.outputs.bastion_sg_id
  private_dns               = data.terraform_remote_state.common_infra.outputs.private_dns
  api_origin                = "api.delta.test.communities.gov.uk"
  enable_telemetry          = true

  ldap_config = {
    CA_S3_URL                   = "https://data-collection-service-ldaps-crl-test.s3.amazonaws.com/CASRVTEST2/CASRVtest2.dluhctest.local_CASRVtest2.crt"
    DELTA_LDAP_URL              = "ldaps://dluhctest.local:636"
    LDAP_SERVICE_USER_DN_FORMAT = "CN=%s,OU=Users,OU=dluhctest,DC=dluhctest,DC=local"
    LDAP_DELTA_USER_DN_FORMAT   = "CN=%s,CN=Datamart,OU=Users,OU=dluhctest,DC=dluhctest,DC=local"
    LDAP_GROUP_DN_FORMAT        = "CN=%s,OU=Groups,OU=dluhctest,DC=dluhctest,DC=local"
    LDAP_DOMAIN_REALM           = "dluhctest.local"
    ACCESS_GROUP_CONTAINER_DN   = "CN=datamart-delta,OU=Groups,OU=dluhctest,DC=dluhctest,DC=local"
  }
  dclg_access_group_notification_settings = local.dclg_access_group_notification_settings

  # Test environment only settings
  delta_website_local_dev_client_secret_arn = aws_secretsmanager_secret.delta_website_local_dev_client_secret.arn
  enable_http_internal_alb_listener         = true
  mail_settings = {
    smtp_host        = "mailhog.vpc.local"
    smtp_port        = "1025"
    from_name        = "Delta System (Test)"
    from_address     = "delta-test@datacollection.dluhc-dev.uk"
    reply_to_name    = "DLUHC Digital Services"
    reply_to_address = "no-reply@datacollection.dluhc-dev.uk"
  }
}
