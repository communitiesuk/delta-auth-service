variable "listener_arn" {
  type = string
}

variable "environment" {
  type = string
}

variable "vpc_id" {
  type = string
}

variable "target_group_port" {
  type = number
}

variable "healthcheck_path" {
  type = string
}

data "aws_vpc" "main" {
  id = var.vpc_id
}

resource "aws_lb_listener_rule" "vpc_traffic" {
  listener_arn = var.listener_arn
  priority     = 150

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.auth.arn
  }

  condition {
    source_ip {
      values = [data.aws_vpc.main.cidr_block]
    }
  }

  condition {
    path_pattern {
      values = ["/auth-internal/*", "/auth-internal"]
    }
  }
}

resource "aws_lb_target_group" "auth" {
  name_prefix = "auth-${substr(var.environment, 0, 1)}"
  port        = var.target_group_port
  protocol    = "HTTPS"
  vpc_id      = var.vpc_id
  target_type = "ip"

  health_check {
    path              = var.healthcheck_path
    protocol          = "HTTPS"
    healthy_threshold = 2
  }

  lifecycle {
    create_before_destroy = true
  }
}

output "target_group_arn" {
  value = aws_lb_target_group.auth.arn
}

output "target_group_arn_suffix" {
  value = aws_lb_target_group.auth.arn_suffix
}
