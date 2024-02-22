locals {
  tasks = {
    DeleteOldAuthCodes = {
      cron     = "0 0 * * ? *" // Midnight
      timezone = "Europe/London"
    }
    DeleteOldDeltaSessions = {
      cron     = "10 0 * * ? *" // Ten past midnight
      timezone = "Europe/London"
    }
    UpdateUserGUIDMap = {
      cron     = "10 0 * * ? *" // Ten past midnight
      timezone = "Europe/London"
    }
  }
}


resource "aws_scheduler_schedule_group" "tasks" {
  name = "auth-service-tasks-${var.environment}"
}

resource "aws_scheduler_schedule" "task" {
  for_each = local.tasks

  name       = "auth-service-${each.key}"
  group_name = aws_scheduler_schedule_group.tasks.name

  flexible_time_window {
    mode = "OFF"
  }

  schedule_expression          = "cron(${each.value.cron})"
  schedule_expression_timezone = each.value.timezone

  target {
    arn      = module.fargate.cluster_arn
    role_arn = aws_iam_role.scheduler.arn

    ecs_parameters {
      task_definition_arn = module.fargate.latest_task_definition_arn
      launch_type         = "FARGATE"

      network_configuration {
        assign_public_ip = false
        security_groups  = [module.fargate.tasks_security_group_id]
        subnets          = var.subnet_ids
      }
    }

    input = jsonencode({
      containerOverrides : [
        {
          name : "delta-auth-service-container-${var.environment}",
          environment : [
            {
              name : "RUN_TASK",
              value : each.key
            }
          ]
        }
      ]
    })

    retry_policy {
      maximum_retry_attempts = 0
    }

    dead_letter_config {
      arn = aws_sqs_queue.tasks_dead_letter_queue.arn
    }
  }
}

# Non sensitive
# tfsec:ignore:aws-sqs-enable-queue-encryption
resource "aws_sqs_queue" "tasks_dead_letter_queue" {
  name = "auth-service-tasks-dlq-${var.environment}"

  message_retention_seconds = 1209600 // 14 days, the maximum
}

resource "aws_iam_role" "scheduler" {
  name = "auth-service-scheduler-role-${var.environment}"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = ["scheduler.amazonaws.com"]
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "scheduler" {
  policy_arn = aws_iam_policy.scheduler.arn
  role       = aws_iam_role.scheduler.name
}

resource "aws_iam_policy" "scheduler" {
  name   = "auth-service-scheduler-policy-${var.environment}"
  policy = data.aws_iam_policy_document.scheduler.json
}

data "aws_iam_policy_document" "scheduler" {
  statement {
    actions   = ["ecs:RunTask"]
    resources = [module.fargate.latest_task_definition_arn]
  }
  statement {
    actions   = ["iam:PassRole"]
    resources = [aws_iam_role.auth_service_task_role.arn, module.fargate.execution_role_arn]
    condition {
      test     = "StringLike"
      values   = ["ecs-tasks.amazonaws.com"]
      variable = "iam:PassedToService"
    }
  }
  statement {
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.tasks_dead_letter_queue.arn]
  }
}

resource "aws_cloudwatch_metric_alarm" "task_invocation_failure" {
  alarm_name          = "auth-${var.environment}-task-invocation-failure"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "InvocationDroppedCount"
  namespace           = "AWS/Scheduler"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  treat_missing_data  = "notBreaching"
  dimensions = {
    "ScheduleGroup" = aws_scheduler_schedule_group.tasks.name
  }

  alarm_description = <<-EOT
    Auth service EventBridge scheduler failed to start a scheduled ECS task.
    Check the dead letter queue ${aws_sqs_queue.tasks_dead_letter_queue.name}
  EOT
  alarm_actions     = [var.alarms_sns_topic_arn]
  ok_actions        = [var.alarms_sns_topic_arn]
}

resource "aws_cloudwatch_metric_alarm" "task_execution_failure" {
  alarm_name          = "auth-${var.environment}-task-execution-failure"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "tasks.failure"
  namespace           = local.auth_metrics_namespace
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  treat_missing_data  = "notBreaching"

  alarm_description = <<-EOT
    A task failed to execute on the auth service.
    Check the auth service log group for relevant messages (with e.g. | filter ispresent(taskName))
  EOT
  alarm_actions     = [var.alarms_sns_topic_arn]
  ok_actions        = [var.alarms_sns_topic_arn]
}
