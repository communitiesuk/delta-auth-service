
output "tasks_security_group_id" {
  value = aws_security_group.tasks.id
}

output "image_tag" {
  value = null_resource.image_tag.triggers.tag
}
