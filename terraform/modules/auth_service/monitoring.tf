locals {
  metric_failed_logins                = "login.failedLogins.count"
  metric_successful_logins            = "login.successfulLogins.count"
  metric_successful_sso_login         = "login.ssoLogins.count"
  metric_login_rate_limited           = "login.rateLimitedRequests.count"
  metric_registration_rate_limited    = "registration.rateLimitedRequests.count"
  metric_set_password_rate_limited    = "setPassword.rateLimitedRequests.count"
  metric_reset_password_rate_limited  = "resetPassword.rateLimitedRequests.count"
  metric_forgot_password_rate_limited = "forgotPassword.rateLimitedRequests.count"
}


resource "aws_cloudwatch_metric_alarm" "fail_rate_high_login" {
  alarm_name          = "auth-${var.environment}-login-fail-rate-high"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = local.metric_failed_logins
  namespace           = local.auth_metrics_namespace
  period              = 300
  statistic           = "Sum"
  threshold           = 20 //Highest in last month (10/08) is 10
  treat_missing_data  = "notBreaching"

  alarm_description = <<EOF
There are more failed logins than expected.
This is probably some frustrated users repeatedly retrying, but could indicate an issue preventing logins, or possibly a brute force/credential stuffing attack.
Check whether you can log into ${var.environment} Delta. Review the ${aws_cloudwatch_dashboard.main.dashboard_name} dashboard and ${module.fargate.log_group_name} log group.
Escalate if there's any evidence of an attack e.g. a small number of IP addresses trying to log in as lots of different users.
  EOF
  alarm_actions     = [var.alarms_sns_topic_arn]
  ok_actions        = [var.alarms_sns_topic_arn]
}

resource "aws_cloudwatch_metric_alarm" "success_rate_high_login" {
  alarm_name          = "auth-${var.environment}-login-success-rate-high"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = local.metric_successful_logins
  namespace           = local.auth_metrics_namespace
  period              = 300
  statistic           = "Sum"
  threshold           = 30 // Highest in last month (10/08) is 23
  treat_missing_data  = "notBreaching"

  alarm_description = <<EOF
There are more successful logins than expected.
This is probably just more people than usual logging into Delta.
Review the ${aws_cloudwatch_dashboard.main.dashboard_name} dashboard.
Escalate if there's any evidence of an attack e.g. a small number of IP addresses trying to log in as lots of different users.
  EOF
  alarm_actions     = [var.alarms_sns_topic_arn]
  ok_actions        = [var.alarms_sns_topic_arn]
}

resource "aws_cloudwatch_metric_alarm" "auth_login_rate_limit_reached" {
  alarm_name          = "auth-${var.environment}-login-rate-limit-reached"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = local.metric_login_rate_limited
  namespace           = local.auth_metrics_namespace
  period              = 120
  statistic           = "Sum"
  threshold           = 1
  treat_missing_data  = "notBreaching"

  alarm_description = <<EOF
An IP address has reached the rate limit on the login page.
This is probably someone repeatedly reloading the login page.
Review the ${aws_cloudwatch_dashboard.main.dashboard_name} dashboard.
Escalate if there's any evidence of an attack e.g. a small number of IP addresses trying to log in as lots of different users.
  EOF
  alarm_actions     = [var.alarms_sns_topic_arn]
  ok_actions        = [var.alarms_sns_topic_arn]
}

resource "aws_cloudwatch_metric_alarm" "auth_registration_rate_limit_reached" {
  alarm_name          = "auth-${var.environment}-registration-rate-limit-reached"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = local.metric_registration_rate_limited
  namespace           = local.auth_metrics_namespace
  period              = 120
  statistic           = "Sum"
  threshold           = 1
  treat_missing_data  = "notBreaching"

  alarm_description = <<EOF
An IP address has reached the rate limit on the registration page
This is probably a user repeatedly trying to register, but could be someone spamming the service.
Review the ${module.fargate.log_group_name} log group.
  EOF
  alarm_actions     = [var.alarms_sns_topic_arn]
  ok_actions        = [var.alarms_sns_topic_arn]
}

resource "aws_cloudwatch_metric_alarm" "auth_set_password_rate_limit_reached" {
  alarm_name          = "auth-${var.environment}-set-password-rate-limit-reached"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = local.metric_set_password_rate_limited
  namespace           = local.auth_metrics_namespace
  period              = 120
  statistic           = "Sum"
  threshold           = 1
  treat_missing_data  = "notBreaching"
  alarm_description   = <<EOF
An IP address has reached the rate limit on the set password page
This is almost certainly a frustrated user repeatedly retrying or with a browser stuck in a loop, but could be someone trying to brute force the page.
Review the ${module.fargate.log_group_name} log group.
  EOF
  alarm_actions       = [var.alarms_sns_topic_arn]
  ok_actions          = [var.alarms_sns_topic_arn]
}

resource "aws_cloudwatch_metric_alarm" "auth_reset_password_rate_limit_reached" {
  alarm_name          = "auth-${var.environment}-reset-password-rate-limit-reached"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = local.metric_reset_password_rate_limited
  namespace           = local.auth_metrics_namespace
  period              = 120
  statistic           = "Sum"
  threshold           = 1
  treat_missing_data  = "notBreaching"

  alarm_description = <<EOF
An IP address has reached the rate limit on the reset password page
This is almost certainly a frustrated user repeatedly retrying or with a browser stuck in a loop, but could be someone trying to brute force the page.
Review the ${module.fargate.log_group_name} log group.
  EOF
  alarm_actions     = [var.alarms_sns_topic_arn]
  ok_actions        = [var.alarms_sns_topic_arn]
}

resource "aws_cloudwatch_metric_alarm" "auth_forgot_password_rate_limit_reached" {
  alarm_name          = "auth-${var.environment}-forgot-password-rate-limit-reached"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = local.metric_forgot_password_rate_limited
  namespace           = local.auth_metrics_namespace
  period              = 120
  statistic           = "Sum"
  threshold           = 1
  treat_missing_data  = "notBreaching"

  alarm_description = <<EOF
An IP address has reached the rate limit on the forgot password page
This is almost certainly a frustrated user repeatedly retrying or with a browser stuck in a loop, but could be someone trying to brute force the page.
Review the ${module.fargate.log_group_name} log group.
  EOF
  alarm_actions     = [var.alarms_sns_topic_arn]
  ok_actions        = [var.alarms_sns_topic_arn]
}
