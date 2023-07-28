terraform {
  backend "s3" {
    bucket         = "data-collection-service-tfstate-dev"
    encrypt        = true
    kms_key_id     = "arn:aws:kms:eu-west-1:486283582667:key/547ae46f-f57e-45f6-bcfd-9403bed9ec75"
    dynamodb_table = "tfstate-locks"
    key            = "auth-service-test"
    region         = "eu-west-1"
  }

  required_version = "~> 1.5.3"
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
  external_alb                   = data.terraform_remote_state.common_infra.outputs.public_albs.auth
  ml_secret_kms_key_arn          = data.terraform_remote_state.common_infra.outputs.deploy_user_kms_key_arn
  delta_hostname                 = data.terraform_remote_state.common_infra.outputs.public_albs.delta.primary_hostname
  bastion_security_group_id      = data.terraform_remote_state.common_infra.outputs.bastion_sg_id
  private_dns                    = data.terraform_remote_state.common_infra.outputs.private_dns

  ldap_config = {
    CA_S3_URL                   = "https://data-collection-service-ldaps-crl-test.s3.amazonaws.com/CASRVTEST/CASRVtest.dluhctest.local_CASRVtest.crt"
    DELTA_LDAP_URL              = "ldaps://dluhctest.local:636"
    LDAP_SERVICE_USER_DN_FORMAT = "CN=%s,OU=Users,OU=dluhctest,DC=dluhctest,DC=local"
    LDAP_DELTA_USER_DN_FORMAT   = "CN=%s,CN=Datamart,OU=Users,OU=dluhctest,DC=dluhctest,DC=local"
    LDAP_GROUP_DN_FORMAT        = "CN=%s,OU=Groups,OU=dluhctest,DC=dluhctest,DC=local"
  }
}
