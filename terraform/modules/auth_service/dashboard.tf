locals {
  metric_warning_log_filter = "auth-log-count-warning-transform-${var.environment}"
  metric_error_log_filter   = "auth-log-count-error-transform-${var.environment}"
}


resource "aws_cloudwatch_log_metric_filter" "warning_logs" {
  log_group_name = module.fargate.log_group_name
  name           = "auth-${var.environment}-warning-logs-filter"
  pattern        = "{ $.level = \"WARN\" }"
  metric_transformation {
    name          = local.metric_warning_log_filter
    namespace     = local.auth_metrics_namespace
    value         = "1"
    default_value = "0"
    unit          = "Count"
  }
}

resource "aws_cloudwatch_log_metric_filter" "error_logs" {
  log_group_name = module.fargate.log_group_name
  name           = "auth-${var.environment}-error-logs-filter"
  pattern        = "{ $.level = \"ERROR\" }"
  metric_transformation {
    name          = local.metric_error_log_filter
    namespace     = local.auth_metrics_namespace
    value         = "1"
    default_value = "0"
    unit          = "Count"
  }
}

locals {
  colour_green  = "#2ca02c"
  colour_orange = "#ff7f0e"
  colour_red    = "#d62728"
  colour_blue   = "#1f77b4"
}

resource "aws_cloudwatch_dashboard" "main" {
  dashboard_name = "${var.environment}-auth"
  dashboard_body = jsonencode(
    {
      "widgets" : [
        {
          "height" : 6,
          "width" : 8,
          "y" : 0,
          "x" : 0,
          "type" : "metric",
          "properties" : {
            "metrics" : [
              [local.auth_metrics_namespace, local.metric_successful_logins, { "color" : local.colour_green }],
              [".", local.metric_successful_sso_login, { "color" : local.colour_blue }],
              [".", local.metric_failed_logins, { "color" : local.colour_orange }],
              [".", local.metric_login_rate_limited, { "color" : local.colour_red }],
            ],
            "view" : "timeSeries",
            "stacked" : false,
            "region" : data.aws_region.current.name,
            "stat" : "Sum",
            "period" : 300,
            "title" : "Logins"
          }
        },
        {
          "height" : 6,
          "width" : 6,
          "y" : 0,
          "x" : 8,
          "type" : "metric",
          "properties" : {
            "metrics" : [
              [local.auth_metrics_namespace, "tasks.success.count", { "color" : local.colour_blue, "region" : data.aws_region.current.name }],
              [".", "tasks.failure.count", { "color" : local.colour_red, "region" : data.aws_region.current.name }]
            ],
            "view" : "timeSeries",
            "stacked" : false,
            "title" : "Regular tasks",
            "region" : data.aws_region.current.name,
            "stat" : "Sum",
            "period" : 3600
          }
        },
        {
          "height" : 6,
          "width" : 8,
          "y" : 6,
          "x" : 0,
          "type" : "metric",
          "properties" : {
            "metrics" : [
              ["AWS/ApplicationELB", "HTTPCode_Target_2XX_Count", "TargetGroup", aws_lb_target_group.external.arn_suffix, "LoadBalancer", var.external_alb.arn_suffix, { "color" : local.colour_green, "label" : "2XX responses" }],
              [".", "HTTPCode_Target_3XX_Count", ".", ".", ".", ".", { "color" : local.colour_blue, "label" : "3XX responses" }],
              [".", "HTTPCode_Target_4XX_Count", ".", ".", ".", ".", { "color" : local.colour_orange, "label" : "4XX responses" }],
              [".", "HTTPCode_Target_5XX_Count", ".", ".", ".", ".", { "color" : local.colour_red, "label" : "5XX responses" }]
            ],
            "view" : "timeSeries",
            "stacked" : false,
            "title" : "Response codes (ALB target metrics)",
            "region" : data.aws_region.current.name,
            "stat" : "Sum",
            "period" : 300,
            "yAxis" : {
              "left" : {
                "min" : 0
              }
            }
          }
        },
        {
          "height" : 6,
          "width" : 6,
          "y" : 6,
          "x" : 8,
          "type" : "metric",
          "properties" : {
            "metrics" : [
              [local.auth_metrics_namespace, local.metric_warning_log_filter, { "color" : local.colour_orange }],
              [".", local.metric_error_log_filter, { "color" : local.colour_red }]
            ],
            "view" : "timeSeries",
            "stacked" : false,
            "title" : "Count of errors and warnings in logs",
            "region" : data.aws_region.current.name,
            "stat" : "Sum",
            "period" : 300,
            "yAxis" : {
              "left" : {
                "min" : 0
              }
            }
          }
        },
        {
          "height" : 6,
          "width" : 6,
          "y" : 0,
          "x" : 14,
          "type" : "log",
          "properties" : {
            "query" : "SOURCE '${module.fargate.log_group_name}' | filter message = 'Successful login' | stats count() as login_count by IPAddress | sort login_count desc | limit 9",
            "region" : data.aws_region.current.name,
            "stacked" : false,
            "title" : "Successful logins by IP address",
            "view" : "table"
          }
        },
        {
          "height" : 6,
          "width" : 6,
          "y" : 6,
          "x" : 14,
          "type" : "log",
          "properties" : {
            "query" : "SOURCE '${module.fargate.log_group_name}' | filter message = 'Login failed' | stats count() as login_count by IPAddress | sort login_count desc | limit 9",
            "region" : data.aws_region.current.name,
            "stacked" : false,
            "title" : "Failed logins by IP address",
            "view" : "table"
          }
        },
        {
          "height" : 6,
          "width" : 14,
          "y" : 12,
          "x" : 0,
          "type" : "log",
          "properties" : {
            "query" : "SOURCE '${module.fargate.log_group_name}' | fields @timestamp, message | filter level = 'ERROR'",
            "region" : data.aws_region.current.name,
            "stacked" : false,
            "title" : "Error logs",
            "view" : "table"
          }
        }
      ]
    }
  )
}
