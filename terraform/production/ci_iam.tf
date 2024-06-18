data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  ecr_repo = "${data.aws_caller_identity.current.account_id}.dkr.ecr.eu-west-1.amazonaws.com/delta-auth-service"
}

resource "aws_iam_role" "github_actions_delta_auth_ci" {
  name               = "github-actions-delta-auth-ci"
  assume_role_policy = data.aws_iam_policy_document.github_actions_delta_auth_assume_role.json
}

data "aws_iam_openid_connect_provider" "github" {
  arn = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:oidc-provider/token.actions.githubusercontent.com"
}

data "aws_iam_policy_document" "github_actions_delta_auth_assume_role" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [data.aws_iam_openid_connect_provider.github.arn]
    }

    condition {
      test     = "StringEquals"
      values   = ["sts.amazonaws.com"]
      variable = "token.actions.githubusercontent.com:aud"
    }

    condition {
      test = "StringEquals"
      values = [
        "repo:communitiesuk/delta-auth-service:environment:publish"
      ]
      variable = "token.actions.githubusercontent.com:sub"
    }
  }
}

data "aws_iam_policy_document" "ecr_push_access" {
  statement {
    sid    = "1"
    effect = "Allow"

    actions = [
      "ecr:CompleteLayerUpload",
      "ecr:UploadLayerPart",
      "ecr:DescribeImages",
      "ecr:InitiateLayerUpload",
      "ecr:BatchCheckLayerAvailability",
      "ecr:PutImage"
    ]

    resources = [
      local.ecr_repo
    ]
  }

  statement {
    sid    = "2"
    effect = "Allow"

    actions = [
      "ecr:GetAuthorizationToken"
    ]

    resources = ["*"]
  }
}

resource "aws_iam_policy" "github_actions_auth_service_ci_ecr_access" {
  name        = "github-actions-auth-service-ci-ecr-access"
  description = "Grant github-actions-auth-service-ci the ability to push to ECR"
  policy      = data.aws_iam_policy_document.ecr_push_access.json
}

resource "aws_iam_role_policy_attachment" "github_actions_ecr_push_access" {
  role       = aws_iam_role.github_actions_delta_auth_ci.name
  policy_arn = aws_iam_policy.github_actions_auth_service_ci_ecr_access.arn
}