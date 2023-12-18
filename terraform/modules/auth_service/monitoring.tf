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

  alarm_description = "There are more failed logins than expected"
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

  alarm_description = "There are more successful logins than expected"
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

  alarm_description = "An IP address has reached the rate limit on the login page"
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

  alarm_description = "An IP address has reached the rate limit on the registration page"
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

  alarm_description = "An IP address has reached the rate limit on the set password page"
  alarm_actions     = [var.alarms_sns_topic_arn]
  ok_actions        = [var.alarms_sns_topic_arn]
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

  alarm_description = "An IP address has reached the rate limit on the reset password page"
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

  alarm_description = "An IP address has reached the rate limit on the forgot password page"
  alarm_actions     = [var.alarms_sns_topic_arn]
  ok_actions        = [var.alarms_sns_topic_arn]
}
