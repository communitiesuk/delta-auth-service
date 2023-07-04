locals {
  alarm_description_template = "Average service %v utilization %v last %d minutes"
}

resource "aws_cloudwatch_metric_alarm" "cpu_utilisation_high" {
  alarm_name          = "${aws_ecs_cluster.main.name}-cpu-high"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/ECS"
  period              = 300
  statistic           = "Average"
  threshold           = 80

  alarm_description         = format(local.alarm_description_template, "CPU", "High", 10)
  alarm_actions             = [var.alarms_sns_topic_arn]
  ok_actions                = [var.alarms_sns_topic_arn]
  insufficient_data_actions = [var.alarms_sns_topic_arn]

  dimensions = {
    "ClusterName" = aws_ecs_cluster.main.name
    "ServiceName" = aws_ecs_service.main.name
  }
}

resource "aws_cloudwatch_metric_alarm" "memory_utilisation_high" {
  alarm_name          = "${aws_ecs_cluster.main.name}-memory-use-high"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "MemoryUtilization"
  namespace           = "AWS/ECS"
  period              = 300
  statistic           = "Average"
  threshold           = 80

  alarm_description         = format(local.alarm_description_template, "Memory Usage", "High", 10)
  alarm_actions             = [var.alarms_sns_topic_arn]
  ok_actions                = [var.alarms_sns_topic_arn]
  insufficient_data_actions = [var.alarms_sns_topic_arn]

  dimensions = {
    "ClusterName" = aws_ecs_cluster.main.name
    "ServiceName" = aws_ecs_service.main.name
  }
}

# If we're passed an ALB target group make alarms on that
resource "aws_cloudwatch_metric_alarm" "unhealthy_host_high_alb" {
  count = length(var.target_groups) > 0 ? 1 : 0

  alarm_name          = "${aws_ecs_cluster.main.name}-unhealthy-host-count-high"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "UnHealthyHostCount"
  namespace           = "AWS/ApplicationELB"
  period              = 300
  statistic           = "Maximum"
  threshold           = 0

  alarm_description         = "There is at least one unhealthy host"
  alarm_actions             = [var.alarms_sns_topic_arn]
  ok_actions                = [var.alarms_sns_topic_arn]
  insufficient_data_actions = [var.alarms_sns_topic_arn]

  dimensions = {
    "TargetGroup" : var.target_groups[0].tg_arn_suffix
    "LoadBalancer" : var.target_groups[0].lb_arn_suffix
  }
}

resource "aws_cloudwatch_metric_alarm" "healthy_host_low_alb" {
  count = length(var.target_groups) > 0 ? 1 : 0

  alarm_name          = "${aws_ecs_cluster.main.name}-healthy-host-count-low"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 1
  metric_name         = "HealthyHostCount"
  namespace           = "AWS/ApplicationELB"
  period              = 300
  statistic           = "Minimum"
  threshold           = var.desired_count

  alarm_description  = "There are fewer healthy hosts than expected"
  alarm_actions      = [var.alarms_sns_topic_arn]
  ok_actions         = [var.alarms_sns_topic_arn]
  treat_missing_data = "breaching"

  dimensions = {
    "TargetGroup" : var.target_groups[0].tg_arn_suffix
    "LoadBalancer" : var.target_groups[0].lb_arn_suffix
  }
}

