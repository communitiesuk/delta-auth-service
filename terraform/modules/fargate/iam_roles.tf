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
            "secretsmanager:GetSecretValue"
          ]
          Resource = var.secrets[*]["valueFrom"]
        }
      ]
    }
  )
}

resource "aws_iam_role_policy_attachment" "ecs_image_runner_role_kms_policy_attachment" {
  count      = length(var.secret_kms_key_arns) > 0 ? 1 : 0
  role       = aws_iam_role.ecs_image_runner_role.name
  policy_arn = aws_iam_policy.ecs_kms_decrypt[0].arn
}

resource "aws_iam_policy" "ecs_kms_decrypt" {
  count  = length(var.secret_kms_key_arns) > 0 ? 1 : 0
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
