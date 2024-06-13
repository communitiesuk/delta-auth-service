variable "subnets" {
  description = "subnets ids ecs will run in"
  type        = list(string)
}

variable "environment" {
  description = "environment to run in: 'test', 'staging' or 'prod'"
  type        = string
}

variable "app_name" {
  description = "name of the application"
  type        = string
}

variable "container_port" {
  description = "the port the container will expose e.g. 8080"
  type        = number
}

variable "healthcheck_path" {
  description = "path to the application's healthcheck endpoint, if one exists"
  type        = string
  default     = null
}

variable "container_image" {
  description = "the docker image the container should run"
  type        = string
}

variable "environment_variables" {
  description = "environment variables to pass to the container"
  type = list(object({
    name  = string
    value = string
  }))
  default = []
}

variable "secrets" {
  description = "secrets to pass to the container"
  type = list(object({
    name      = string
    valueFrom = string
  }))
  default = []
}

variable "secret_kms_key_arns" {
  description = "KMS key ARNs used by secrets"
  type        = list(string)
  default     = []
}

variable "vpc_id" {
  description = "virtual private cloud id"
}

variable "cpu" {
  type        = number
  description = "number of AWS CPU units to dedicate to the container"
  default     = 256
}

variable "memory" {
  type        = number
  description = "number of MB of memory units to dedicate to the container"
  default     = 512
}

variable "desired_count" {
  type        = number
  description = "desired count for the ecs service"
  default     = 1
}

variable "task_role_arn" {
  type    = string
  default = null
}

variable "target_groups" {
  type = list(object({
    tg_arn        = string
    tg_arn_suffix = string
    lb_arn_suffix = string
  }))
  default = []
}

variable "additional_task_sg_id" {
  type        = string
  default     = null
  description = "Optional, additional security group for the ECS tasks to use."
}

variable "ecs_cloudwatch_log_expiration_days" {
  type = number
}

variable "alarms_sns_topic_arn" {
  description = "SNS topic ARN to send alarm notifications to"
  type        = string
}

variable "enable_adot_sidecar" {
  type = bool
}
