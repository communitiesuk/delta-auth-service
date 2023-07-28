terraform {
  backend "s3" {
    bucket         = "data-collection-service-tfstate-production"
    encrypt        = true
    kms_key_id     = "arn:aws:kms:eu-west-1:468442790030:key/5227677e-1230-49f6-b0d8-1e8aa2fc71fe"
    dynamodb_table = "tfstate-locks"
    key            = "auth-service-production"
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
    bucket = "data-collection-service-tfstate-production"
    key    = "common-infra-prod"
    region = "eu-west-1"
  }
}

locals {
  environment                    = "production"
  cloudwatch_log_expiration_days = 731
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
  ldap_config = {
    CA_S3_URL                   = "https://data-collection-service-ldaps-crl-production.s3.amazonaws.com/CASRVPRODUCTION/CASRVproduction.dluhcdata.local_CASRVproduction.crt"
    DELTA_LDAP_URL              = "ldaps://dluhcdata.local:636"
    LDAP_SERVICE_USER_DN_FORMAT = "CN=%s,OU=Users,OU=dluhcdata,DC=dluhcdata,DC=local"
    LDAP_GROUP_DN_FORMAT        = "CN=%s,OU=Groups,OU=dluhcdata,DC=dluhcdata,DC=local"
  }
  ecs = {
    cpu           = 1024
    memory        = 2048
    desired_count = 2
  }
}
