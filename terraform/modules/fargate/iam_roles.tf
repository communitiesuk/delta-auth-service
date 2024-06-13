resource "aws_iam_role" "ecs_image_runner_role" {
  name = "${var.app_name}-runner-${var.environment}"

  assume_role_policy = jsonencode(
    {
      Version = "2012-10-17"
      Statement = [
        {
          Effect = "Allow"
          Action = "sts:AssumeRole"
          Sid    = ""
          Principal = {
            Service = "ecs-tasks.amazonaws.com"
          }
        }
      ]
    }
  )
}

resource "aws_iam_role_policy_attachment" "ecs_image_runner_role_execution_policy_attachment" {
  role       = aws_iam_role.ecs_image_runner_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role_policy_attachment" "ecs_image_runner_role_secrets_policy_attachment" {
  role       = aws_iam_role.ecs_image_runner_role.name
  policy_arn = aws_iam_policy.ecs_delta_secret_reader.arn
}

resource "aws_iam_policy" "ecs_delta_secret_reader" {
  name = "${var.app_name}-delta-secret-reader-${var.environment}"
  policy = jsonencode(
    {
      Version = "2012-10-17"
      Statement = [
        {
          Effect = "Allow"
          Action = [
            "secretsmanager:GetSecretValue",
            "ssm:GetParameter", "ssm:GetParameters",
          ]
          Resource = var.secrets[*]["valueFrom"]
        }
      ]
    }
  )
}

resource "aws_iam_role_policy_attachment" "ecs_image_runner_role_kms_policy_attachment" {
  role       = aws_iam_role.ecs_image_runner_role.name
  policy_arn = aws_iam_policy.ecs_kms_decrypt.arn
}

resource "aws_iam_policy" "ecs_kms_decrypt" {
  name   = "${var.app_name}-secret-kms-decrypt-${var.environment}"
  policy = data.aws_iam_policy_document.ecs_kms_decrypt.json
}

data "aws_iam_policy_document" "ecs_kms_decrypt" {
  statement {
    actions   = ["kms:Decrypt"]
    effect    = "Allow"
    resources = var.secret_kms_key_arns
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["secretsmanager.${data.aws_region.current.name}.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy_attachment" "ecs_image_runner_role_create_pull_through_cache" {
  count = var.enable_adot_sidecar ? 1 : 0

  role       = aws_iam_role.ecs_image_runner_role.name
  policy_arn = aws_iam_policy.ecr_create_pull_through_repository.arn
}

resource "aws_iam_policy" "ecr_create_pull_through_repository" {
  name   = "${var.app_name}-ecr-create-pull-through-cache-${var.environment}"
  policy = data.aws_iam_policy_document.ecr_create_pull_through_repository.json
}

# Required for the ECR pull-through cache. The private repository is created on first use
# and then updated ("BatchImportUpstreamImage") on pull
# tfsec:ignore:aws-iam-no-policy-wildcards
data "aws_iam_policy_document" "ecr_create_pull_through_repository" {
  statement {
    actions   = ["ecr:BatchImportUpstreamImage", "ecr:CreateRepository"]
    effect    = "Allow"
    resources = ["*"]
  }
}
