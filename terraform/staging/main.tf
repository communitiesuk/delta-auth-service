terraform {
  backend "s3" {
    bucket         = "data-collection-service-tfstate-dev"
    encrypt        = true
    kms_key_id     = "arn:aws:kms:eu-west-1:486283582667:key/547ae46f-f57e-45f6-bcfd-9403bed9ec75"
    dynamodb_table = "tfstate-locks"
    key            = "auth-service-staging"
    region         = "eu-west-1"
  }

  required_version = "~> 1.5.1"
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
    key    = "common-infra-staging"
    region = "eu-west-1"
  }
}

locals {
  environment                    = "staging"
  cloudwatch_log_expiration_days = 30
}

module "fargate_auth" {
  source                             = "../modules/fargate"
  subnets                            = data.terraform_remote_state.common_infra.outputs.auth_service_private_subnet_ids
  environment                        = local.environment
  app_name                           = "delta-auth-service"
  container_port                     = 80
  container_image                    = "468442790030.dkr.ecr.eu-west-1.amazonaws.com/delta-auth-service:${var.image_tag}"
  vpc_id                             = data.terraform_remote_state.common_infra.outputs.vpc_id
  healthcheck_path                   = "/"
  ecs_cloudwatch_log_expiration_days = local.cloudwatch_log_expiration_days
  alarms_sns_topic_arn               = data.terraform_remote_state.common_infra.outputs.alarms_sns_topic_arn
  environment_variables              = []
  secrets                            = []
}