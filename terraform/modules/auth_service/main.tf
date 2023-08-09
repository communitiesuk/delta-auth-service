data "aws_vpc" "main" {
  id = var.vpc_id
}

resource "aws_ssm_parameter" "auth_service_rate_limit" {
  name  = "${var.environment}-auth-service-rate-limit"
  type  = "String"
  value = 1 # To be manually changed on AWS
  lifecycle { ignore_changes = [value] }
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
  target_groups = [
    {
      tg_arn        = aws_lb_target_group.internal.arn
      tg_arn_suffix = aws_lb_target_group.internal.arn_suffix
      lb_arn_suffix = var.internal_alb.arn_suffix
    },
    {
      tg_arn        = aws_lb_target_group.external.arn
      tg_arn_suffix = aws_lb_target_group.external.arn_suffix
      lb_arn_suffix = var.external_alb.arn_suffix
    }
  ]
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
      name  = "LDAP_DELTA_USER_DN_FORMAT"
      value = var.ldap_config.LDAP_DELTA_USER_DN_FORMAT
    },
    {
      name  = "CA_S3_URL"
      value = var.ldap_config.CA_S3_URL
    },
    {
      name  = "DELTA_WEBSITE_URL"
      value = "https://${var.delta_hostname}"
    },
    {
      name  = "LDAP_AUTH_SERVICE_USER"
      value = "auth-service.app"
    },
    {
      name  = "DATABASE_URL"
      value = "jdbc:postgresql://${aws_db_instance.auth_service.endpoint}/auth_service?ssl=true&sslmode=verify-full"
    },
    {
      name  = "DATABASE_USER"
      value = local.database_username
    },
    {
      name  = "DISABLE_DEVELOPMENT_FALLBACK"
      value = "true"
    },
    {
      name  = "SERVICE_URL"
      value = "https://${var.external_alb.primary_hostname}"
    },
  ]
  secrets = [for s in [
    {
      name      = "DELTA_SAML_PRIVATE_KEY"
      valueFrom = data.aws_secretsmanager_secret.saml_private_key.arn
    },
    {
      name      = "DELTA_SAML_CERTIFICATE"
      valueFrom = data.aws_secretsmanager_secret.saml_certificate.arn
    },
    {
      name      = "CLIENT_SECRET_MARKLOGIC"
      valueFrom = aws_secretsmanager_secret.ml_client_secret.arn
    },
    {
      name      = "CLIENT_SECRET_DELTA_WEBSITE"
      valueFrom = aws_secretsmanager_secret.delta_website_client_secret.arn
    },
    {
      name      = "LDAP_AUTH_SERVICE_USER_PASSWORD"
      valueFrom = data.aws_secretsmanager_secret.active_directory_service_user.arn
    },
    {
      name      = "DATABASE_PASSWORD"
      valueFrom = aws_secretsmanager_secret.database_password.arn
    },
    {
      name      = "AUTH_RATE_LIMIT"
      valueFrom = aws_ssm_parameter.auth_service_rate_limit.arn
    },
    {
      name      = "COOKIE_SIGNING_KEY_HEX"
      valueFrom = aws_secretsmanager_secret.cookie_mac_key.arn
    },
    {
      name      = "AZ_SSO_CLIENTS_JSON"
      valueFrom = data.aws_secretsmanager_secret.sso_config.arn
    },
    var.delta_website_local_dev_client_secret_arn == null ? null : {
      name      = "CLIENT_SECRET_DELTA_WEBSITE_DEV"
      valueFrom = var.delta_website_local_dev_client_secret_arn
    },
  ] : s if s != null]
  secret_kms_key_arns = compact([aws_kms_key.auth_service.arn, var.ml_secret_kms_key_arn, data.aws_secretsmanager_secret.saml_certificate.kms_key_id])
}
