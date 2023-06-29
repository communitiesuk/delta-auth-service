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
