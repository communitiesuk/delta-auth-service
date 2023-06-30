variable "environment" {
  type = string
}

variable "subnet_ids" {
  type = list(string)
}

variable "vpc_id" {
  type = string
}

variable "alb_listener_arn" {
  type = string
}

variable "alb_arn_suffix" {
  type = string
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
    LDAP_GROUP_DN_FORMAT        = string
    CA_S3_URL                   = string
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
