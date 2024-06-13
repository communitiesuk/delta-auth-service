resource "aws_iam_role" "auth_service_task_role" {
  name = "${var.environment}-auth-service-metrics-role"

  assume_role_policy = jsonencode(
    {
      Version = "2012-10-17"
      Statement = [
        {
          Effect = "Allow"
          Action = "sts:AssumeRole"
          "Condition" : {
            "ArnLike" : {
              "aws:SourceArn" : "arn:aws:ecs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:*"
            }
          }
          Sid = ""
          Principal = {
            Service = "ecs-tasks.amazonaws.com"
          }
        }
      ]
    }
  )
}

resource "aws_iam_role_policy_attachment" "auth_service_metrics_role_policy_attachment" {
  role       = aws_iam_role.auth_service_task_role.name
  policy_arn = aws_iam_policy.auth_service_metrics_access.arn
}

resource "aws_iam_policy" "auth_service_metrics_access" {
  name   = "${var.environment}-auth-service-metrics-access"
  policy = data.aws_iam_policy_document.auth_service_metrics_access.json
}

# tfsec:ignore:aws-iam-no-policy-wildcards
data "aws_iam_policy_document" "auth_service_metrics_access" {
  statement {
    actions   = ["cloudwatch:PutMetricData"]
    effect    = "Allow"
    resources = ["*"]
    condition {
      test     = "StringEquals"
      values   = [local.auth_metrics_namespace]
      variable = "cloudwatch:namespace"
    }
  }
}

resource "aws_iam_role_policy_attachment" "x_ray_role_policy_attachment" {
  role       = aws_iam_role.auth_service_task_role.name
  policy_arn = data.aws_iam_policy.AWSXRayDaemonWriteAccess.arn
}

data "aws_iam_policy" "AWSXRayDaemonWriteAccess" {
  arn = "arn:aws:iam::aws:policy/AWSXRayDaemonWriteAccess"
}
