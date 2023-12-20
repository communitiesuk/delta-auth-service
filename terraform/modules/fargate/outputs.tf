
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
  value = trimsuffix(aws_ecs_task_definition.main.arn, ":${aws_ecs_task_definition.main.revision}")
}

output "execution_role_arn" {
  value = aws_iam_role.ecs_image_runner_role.arn
}

output "log_group_name" {
  value = aws_cloudwatch_log_group.ecs_logs.name
}
