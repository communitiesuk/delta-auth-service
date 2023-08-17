data "aws_region" "current" {}

data "aws_caller_identity" "current" {}

data "aws_prefix_list" "s3" {
  name = "com.amazonaws.${data.aws_region.current.name}.s3"
}

locals {
  log_group_name = "${var.environment}/${var.app_name}-ecs-logs"
}

resource "aws_kms_key" "log_encryption_key" {
  description         = "${var.app_name} ECS logs - ${var.environment}"
  enable_key_rotation = true
  policy = templatefile("${path.module}/policies/logging_kms_policy.json", {
    account_id        = data.aws_caller_identity.current.account_id
    region            = data.aws_region.current.name
    log_group_pattern = local.log_group_name
  })
}

resource "aws_kms_alias" "log_encryption_key" {
  name          = "alias/${var.app_name}-ecs-logs-${var.environment}"
  target_key_id = aws_kms_key.log_encryption_key.id
}

resource "aws_cloudwatch_log_group" "ecs_logs" {
  name              = local.log_group_name
  retention_in_days = var.ecs_cloudwatch_log_expiration_days
  kms_key_id        = aws_kms_key.log_encryption_key.arn

  lifecycle {
    prevent_destroy = true
  }
}

// We use this to keep the image tag in the Terraform state
// to feed the image tag outputs so a partial apply doesn't make them out of sync
resource "null_resource" "image_tag" {
  triggers = {
    tag = split(":", var.container_image)[1]
  }
}

resource "aws_ecs_task_definition" "main" {
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.cpu
  memory                   = var.memory
  execution_role_arn       = aws_iam_role.ecs_image_runner_role.arn
  task_role_arn            = var.task_role_arn
  container_definitions = jsonencode([{
    name        = "${var.app_name}-container-${var.environment}"
    image       = var.container_image
    essential   = true
    environment = var.environment_variables
    secrets     = var.secrets
    portMappings = [{
      protocol      = "tcp"
      containerPort = var.container_port
      hostPort      = var.container_port
    }]
    logConfiguration = {
      logDriver = "awslogs",
      options = {
        awslogs-group         = aws_cloudwatch_log_group.ecs_logs.name
        awslogs-region        = data.aws_region.current.name
        awslogs-stream-prefix = "${var.app_name}-${var.environment}"
      }
    }
  }])
  family = "${var.app_name}-${var.environment}"
}

#tfsec:ignore:aws-ecs-enable-container-insight
resource "aws_ecs_cluster" "main" {
  name = "${var.app_name}-cluster-${var.environment}"
}

data "aws_vpc" "main" {
  id = var.vpc_id
}

resource "aws_security_group" "tasks" {
  name        = "${var.app_name}-task-${var.environment}"
  vpc_id      = var.vpc_id
  description = "Allow ingress from the whole VPC and allow egress to pull image"
}

resource "aws_security_group_rule" "ingress" {
  type              = "ingress"
  security_group_id = aws_security_group.tasks.id
  description       = "Allow ingress from the whole VPC"

  protocol    = "tcp"
  from_port   = var.container_port
  to_port     = var.container_port
  cidr_blocks = [data.aws_vpc.main.cidr_block]
}

resource "aws_security_group_rule" "vpc_egress" {
  type              = "egress"
  security_group_id = aws_security_group.tasks.id
  description       = "Allow egress within VPC to use VPC endpoints"

  protocol    = "-1"
  from_port   = 0
  to_port     = 0
  cidr_blocks = [data.aws_vpc.main.cidr_block]
}

resource "aws_security_group_rule" "s3_egress" {
  type              = "egress"
  security_group_id = aws_security_group.tasks.id
  description       = "Egress to S3 Gateway"

  protocol        = "tcp"
  from_port       = 443
  to_port         = 443
  prefix_list_ids = [data.aws_prefix_list.s3.id]
}

# Outbound internet access required for OAuth to Azure AD
# tfsec:ignore:aws-vpc-no-public-egress-sgr
resource "aws_security_group_rule" "outbound_internet_from_tasks" {
  type              = "egress"
  security_group_id = aws_security_group.tasks.id
  description       = "Egress HTTPS outbound to internet"

  protocol    = "tcp"
  from_port   = 443
  to_port     = 443
  cidr_blocks = ["0.0.0.0/0"]
}

resource "aws_ecs_service" "main" {
  name                = "ecs-service-${var.environment}"
  cluster             = aws_ecs_cluster.main.id
  task_definition     = aws_ecs_task_definition.main.arn
  desired_count       = var.desired_count
  launch_type         = "FARGATE"
  scheduling_strategy = "REPLICA"

  network_configuration {
    security_groups  = concat([aws_security_group.tasks.id], var.additional_task_sg_id == null ? [] : [var.additional_task_sg_id])
    subnets          = var.subnets
    assign_public_ip = false
  }

  dynamic "load_balancer" {
    for_each = var.target_groups
    content {
      target_group_arn = load_balancer.value.tg_arn
      container_name   = "${var.app_name}-container-${var.environment}"
      container_port   = var.container_port
    }
  }
}
