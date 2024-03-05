
output "tasks_security_group_id" {
  value = aws_security_group.tasks.id
}

output "image_tag" {
  value = null_resource.image_tag.triggers.tag
}

output "cluster_arn" {
  value = aws_ecs_cluster.main.arn
}

output "latest_task_definition_arn" {
  # Construct the task definition ARN rather than reading it from the latest task definition,
  # otherwise Terraform can't tell it hasn't changed when planning
  value = "arn:aws:ecs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:task-definition/${local.task_definition_family}"
}

output "execution_role_arn" {
  value = aws_iam_role.ecs_image_runner_role.arn
}

output "log_group_name" {
  value = aws_cloudwatch_log_group.ecs_logs.name
}
