data "aws_region" "current" {}

data "aws_caller_identity" "current" {}

variable "environment" {
  type = string
}

variable "subnet_ids" {
  type = list(string)
}

variable "vpc_id" {
  type = string
}

variable "external_alb" {
  type = object({
    arn               = string
    arn_suffix        = string
    security_group_id = string
    cloudfront_key    = string
    listener_arn      = string
    primary_hostname  = string
  })
}

variable "internal_alb" {
  type = object({
    arn               = string
    arn_suffix        = string
    listener_arn      = string
    security_group_id = string
  })
}

variable "enable_http_internal_alb_listener" {
  type        = bool
  default     = false
  description = "Create a HTTP listener for the auth service. Used in the test environment to make local development against it easier."
}

variable "alarms_sns_topic_arn" {
  type = string
}

variable "container_image" {
  type = string
}

variable "cloudwatch_log_expiration_days" {
  type = number
}

variable "ldap_config" {
  type = object({
    DELTA_LDAP_URL              = string
    LDAP_SERVICE_USER_DN_FORMAT = string
    LDAP_DELTA_USER_DN_FORMAT   = string
    LDAP_GROUP_DN_FORMAT        = string
    CA_S3_URL                   = string
    LDAP_DOMAIN_REALM           = string
    ACCESS_GROUP_CONTAINER_DN   = string
  })
}

variable "ecs" {
  type = object({
    cpu           = number
    memory        = number
    desired_count = number
  })
  default = {
    cpu           = 256
    memory        = 512
    desired_count = 1
  }
}

variable "ml_secret_kms_key_arn" {
  type = string
}

variable "delta_hostname" {
  type = string
}

variable "bastion_security_group_id" {
  type = string
}

variable "db_instance_type" {
  type    = string
  default = "db.t4g.micro"
}

variable "db_backup_retention_days" {
  type    = number
  default = 3
}

variable "private_dns" {
  type = object({
    zone_id     = string
    base_domain = string
  })
}

variable "delta_website_local_dev_client_secret_arn" {
  type        = string
  default     = null
  description = "Client secret for a client that redirects to localhost, for use only on the test environment"
}

variable "mail_settings" {
  type = object({
    smtp_host        = string
    smtp_port        = string
    from_name        = string
    from_address     = string
    reply_to_name    = string
    reply_to_address = string
    smtp_secret_name = optional(string)
  })
}

variable "dclg_access_group_notification_settings" {
  type = object({
    enabled                     = bool
    additional_recipient_emails = list(string)
  })
}

variable "enable_telemetry" {
  type    = bool
  default = false
}

variable "api_origin" {
  type        = string
  description = "Domain name for the Delta API Swagger page, used by the auth service to set CORS headers on the API authentication endpoint"
}

locals {
  auth_metrics_namespace = "${var.environment}/AuthService"
}
