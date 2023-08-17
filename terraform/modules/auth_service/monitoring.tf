resource "aws_cloudwatch_metric_alarm" "fail_rate_high_login" {
  alarm_name          = "auth-${var.environment}-login-fail-rate-high"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "login.failedLogins.count"
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
  metric_name         = "login.successfulLogins.count"
  namespace           = local.auth_metrics_namespace
  period              = 300
  statistic           = "Sum"
  threshold           = 30 // Highest in last month (10/08) is 23
  treat_missing_data  = "notBreaching"

  alarm_description = "There are more successful logins than expected"
  alarm_actions     = [var.alarms_sns_topic_arn]
  ok_actions        = [var.alarms_sns_topic_arn]
}

resource "aws_cloudwatch_metric_alarm" "auth_rate_limit_reached" {
  alarm_name          = "auth-${var.environment}-rate-limit-reached"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "login.rateLimitedRequests.count"
  namespace           = local.auth_metrics_namespace
  period              = 120
  statistic           = "Sum"
  threshold           = 1
  treat_missing_data  = "notBreaching"

  alarm_description = "An IP address has reached the rate limit on the login page"
  alarm_actions     = [var.alarms_sns_topic_arn]
  ok_actions        = [var.alarms_sns_topic_arn]
}
