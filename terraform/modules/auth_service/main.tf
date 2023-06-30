data "aws_vpc" "main" {
  id = var.vpc_id
}

# See api/README.md and terraform/test/main.tf in the Delta repository for setup instructions
data "aws_secretsmanager_secret" "saml_private_key" {
  name = "api-saml-private-key-${var.environment}"
}

data "aws_secretsmanager_secret" "saml_certificate" {
  name = "api-saml-certificate-${var.environment}"
}

module "fargate" {
  source                             = "../fargate"
  subnets                            = var.subnet_ids
  environment                        = var.environment
  app_name                           = "delta-auth-service"
  container_port                     = 8443
  container_image                    = var.container_image
  vpc_id                             = var.vpc_id
  healthcheck_path                   = "/health"
  desired_count                      = var.ecs.desired_count
  cpu                                = var.ecs.cpu
  memory                             = var.ecs.memory
  ecs_cloudwatch_log_expiration_days = var.cloudwatch_log_expiration_days
  alarms_sns_topic_arn               = var.alarms_sns_topic_arn
  target_group = {
    tg_arn        = aws_lb_target_group.main.arn
    tg_arn_suffix = aws_lb_target_group.main.arn_suffix
    lb_arn_suffix = var.alb_arn_suffix
  }
  environment_variables = [
    {
      name  = "DELTA_LDAP_URL"
      value = var.ldap_config.DELTA_LDAP_URL
    },
    {
      name  = "LDAP_GROUP_DN_FORMAT"
      value = var.ldap_config.LDAP_GROUP_DN_FORMAT
    },
    {
      name  = "LDAP_SERVICE_USER_DN_FORMAT"
      value = var.ldap_config.LDAP_SERVICE_USER_DN_FORMAT
    },
    {
      name  = "CA_S3_URL"
      value = var.ldap_config.CA_S3_URL
    }
  ]
  secrets = [
    {
      name      = "DELTA_SAML_PRIVATE_KEY"
      valueFrom = data.aws_secretsmanager_secret.saml_private_key.arn
    },
    {
      name      = "DELTA_SAML_CERTIFICATE"
      valueFrom = data.aws_secretsmanager_secret.saml_certificate.arn
    },
  ]
}
