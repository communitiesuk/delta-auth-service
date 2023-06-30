resource "aws_lb_listener_rule" "vpc_traffic" {
  listener_arn = var.alb_listener_arn
  priority     = 150

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.main.arn
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

resource "aws_lb_target_group" "main" {
  name_prefix = "auth-${substr(var.environment, 0, 1)}"
  port        = 8443
  protocol    = "HTTPS"
  vpc_id      = var.vpc_id
  target_type = "ip"

  health_check {
    path              = "/health"
    protocol          = "HTTPS"
    healthy_threshold = 2
  }

  lifecycle {
    create_before_destroy = true
  }
}