resource "aws_lb_listener_rule" "vpc_traffic" {
  listener_arn = var.internal_alb.listener_arn
  priority     = 1000

  condition {
    source_ip {
      values = [data.aws_vpc.main.cidr_block]
    }
  }

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.internal.arn
  }
}

resource "aws_lb_target_group" "internal" {
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

resource "aws_lb_listener_rule" "block_internal_routes" {
  listener_arn = var.external_alb.listener_arn
  priority     = 1000

  condition {
    path_pattern {
      values = ["/auth-internal/*"]
    }
  }

  action {
    type = "fixed-response"
    fixed_response {
      content_type = "text/plain"
      message_body = "This resource is not available externally"
      status_code  = "403"
    }
  }
}

resource "aws_lb_listener_rule" "external_traffic" {
  listener_arn = var.external_alb.listener_arn
  priority     = 1100

  condition {
    http_header {
      http_header_name = "X-Cloudfront-Key"
      values           = [sensitive(var.external_alb.cloudfront_key)]
    }
  }

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.external.arn
  }
}

resource "aws_lb_target_group" "external" {
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
