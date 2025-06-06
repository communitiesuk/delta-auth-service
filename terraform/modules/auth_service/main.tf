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
  task_role_arn                      = aws_iam_role.auth_service_task_role.arn
  enable_adot_sidecar                = var.enable_telemetry
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
  environment_variables = [for env in [
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
      name  = "ACCESS_GROUP_CONTAINER_DN"
      value = var.ldap_config.ACCESS_GROUP_CONTAINER_DN
    },
    {
      name  = "GROUP_CONTAINER_DN"
      value = var.ldap_config.GROUP_CONTAINER_DN
    },
    {
      name  = "USER_CONTAINER_DN"
      value = var.ldap_config.USER_CONTAINER_DN
    },
    {
      name  = "DATABASE_URL"
      value = "jdbc:postgresql://${aws_db_instance.auth_service.endpoint}/auth_service?ssl=true&sslmode=verify-full&sslrootcert=/root/.postgresql/ca-bundle.pem"
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
      name  = "AUTH_METRICS_NAMESPACE"
      value = local.auth_metrics_namespace
    },
    {
      name  = "SERVICE_URL"
      value = "https://${var.external_alb.primary_hostname}"
    },
    {
      name  = "DELTA_MARKLOGIC_LDAP_AUTH_APP_SERVICE"
      value = "http://marklogic.vpc.local:8050/"
    },
    {
      name  = "MAIL_SMTP_HOST"
      value = var.mail_settings.smtp_host
    },
    {
      name  = "MAIL_SMTP_PORT"
      value = var.mail_settings.smtp_port
    },
    {
      name  = "FROM_EMAIL_ADDRESS"
      value = var.mail_settings.from_address
    },
    {
      name  = "FROM_EMAIL_NAME"
      value = var.mail_settings.from_name
    },
    {
      name  = "REPLY_TO_EMAIL_ADDRESS"
      value = var.mail_settings.reply_to_address
    },
    {
      name  = "REPLY_TO_EMAIL_NAME"
      value = var.mail_settings.reply_to_name
    },
    {
      name  = "LDAP_DOMAIN_REALM"
      value = var.ldap_config.LDAP_DOMAIN_REALM
    },
    {
      name  = "DCLG_ACCESS_GROUP_NOTIFICATIONS_ENABLED"
      value = var.dclg_access_group_notification_settings.enabled ? "true" : "false"
    },
    {
      name  = "DCLG_ACCESS_GROUP_UPDATE_ADDITIONAL_RECIPIENTS"
      value = join(";", var.dclg_access_group_notification_settings.additional_recipient_emails)
    },
    {
      name  = "API_ORIGIN"
      value = var.api_origin
    },
    {
      name  = "ENVIRONMENT",
      value = var.environment
    },
    var.enable_telemetry ? {
      name  = "AUTH_TELEMETRY_PREFIX"
      value = var.environment
    } : null,
  ] : env if env != null]
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
    {
      name      = "CLIENT_SECRET_DELTA_API"
      valueFrom = aws_secretsmanager_secret.client_secret_delta_api.arn
    },
    var.delta_website_local_dev_client_secret_arn == null ? null : {
      name      = "CLIENT_SECRET_DELTA_WEBSITE_DEV"
      valueFrom = var.delta_website_local_dev_client_secret_arn
    },
    var.mail_settings.smtp_secret_name == null ? null : {
      name      = "MAIL_SMTP_USER"
      valueFrom = data.aws_secretsmanager_secret.delta_ses_credentials[0].arn
    },
  ] : s if s != null]
  secret_kms_key_arns = compact([
    aws_kms_key.auth_service.arn, var.ml_secret_kms_key_arn, data.aws_secretsmanager_secret.saml_certificate.kms_key_id
  ])
}
