data "aws_vpc" "main" {
  id = var.vpc_id
}

module "fargate" {
  source                             = "../fargate"
  subnets                            = var.subnet_ids
  environment                        = var.environment
  app_name                           = "delta-auth-service"
  container_port                     = 8443
  container_image                    = var.container_image
  vpc_id                             = var.vpc_id
  healthcheck_path                   = "/health"
  ecs_cloudwatch_log_expiration_days = var.cloudwatch_log_expiration_days
  alarms_sns_topic_arn               = var.alarms_sns_topic_arn
  target_group = {
    tg_arn        = aws_lb_target_group.main.arn
    tg_arn_suffix = aws_lb_target_group.main.arn_suffix
    lb_arn_suffix = var.alb_arn_suffix
  }
  environment_variables = []
  secrets               = []
}
