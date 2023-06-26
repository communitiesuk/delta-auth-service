terraform {
  backend "s3" {
    bucket         = "data-collection-service-tfstate-production"
    encrypt        = true
    kms_key_id     = "arn:aws:kms:eu-west-1:468442790030:key/5227677e-1230-49f6-b0d8-1e8aa2fc71fe"
    dynamodb_table = "tfstate-locks"
    key            = "auth-service-production"
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
    bucket = "data-collection-service-tfstate-production"
    key    = "common-infra-production"
    region = "eu-west-1"
  }
}

locals {
  environment                    = "production"
  cloudwatch_log_expiration_days = 700
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