resource "aws_security_group" "db" {
  name        = "auth-service-db-${var.environment}"
  vpc_id      = var.vpc_id
  description = "Allow ingress from auth service tasks and bastion"
}

resource "aws_security_group_rule" "database_from_task" {
  security_group_id        = aws_security_group.db.id
  type                     = "ingress"
  protocol                 = "tcp"
  from_port                = 5432
  to_port                  = 5432
  source_security_group_id = module.fargate.tasks_security_group_id
  description              = "auth-service tasks to database"
}

resource "aws_security_group_rule" "database_from_task" {
  security_group_id        = aws_security_group.db.id
  type                     = "ingress"
  protocol                 = "tcp"
  from_port                = 5432
  to_port                  = 5432
  source_security_group_id = var.bastion_security_group_id
  description              = "auth-service tasks to database"
}

resource "aws_db_subnet_group" "auth-service" {
  name       = "${var.environment}-auth-service"
  subnet_ids = var.subnet_ids
}

locals {
  database_username = "auth-service"
}

# We can enable RDS Performance Insights if we need to.
# The AVD-AWS code is an ignore for 'Instance does not have IAM Authentication enabled' rule
# tfsec:ignore:aws-rds-enable-performance-insights
# tfsec:ignore:AVD-AWS-0176
resource "aws_db_instance" "auth_service" {
  identifier                = "${var.environment}-auth-service"
  db_name                   = "auth_service"
  instance_class            = var.db_instance_type
  engine                    = "postgres"
  engine_version            = "14.8"
  allocated_storage         = 10 # GB
  storage_encrypted         = true
  kms_key_id                = aws_kms_key.auth_service.arn
  username                  = local.database_username
  password                  = random_password.database_password.result
  db_subnet_group_name      = aws_db_subnet_group.auth-service.name
  multi_az                  = true
  network_type              = "IPV4"
  port                      = 5432
  vpc_security_group_ids    = [aws_security_group.db.id]
  publicly_accessible       = false
  skip_final_snapshot       = false
  final_snapshot_identifier = "auth-service-db-final-${var.environment}"
  maintenance_window        = "Tue:03:00-Tue:05:00"
  backup_window             = "01:00-02:00"
  backup_retention_period   = 14
  deletion_protection       = true

  lifecycle {
    # The DB automatically upgrades to new minor versions
    ignore_changes = [engine_version]
  }
}

resource "aws_route53_record" "auth_service_db" {
  zone_id = var.private_dns.zone_id
  name    = "auth-service-db.${var.private_dns.base_domain}"
  type    = "CNAME"
  ttl     = 60
  records = [aws_db_instance.auth_service.address]
}
