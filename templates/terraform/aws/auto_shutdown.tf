# CLAUDE.md invariant #4: every deployment carries auto_shutdown so cost never
# depends on anyone remembering to run `/destroy` promptly. Azure has a native
# per-VM DevTest shutdown schedule; AWS has no equivalent, so this is built from
# EventBridge Scheduler (the cron trigger, with a native IANA timezone) + a tiny
# Lambda that stops every EC2 instance tagged lab=<lab_name> (bastion included —
# it's billed too). The IAM role is scoped by that tag, and teardown destroys
# all of it, so cost still returns to zero.
#
# RELAXATION NOTE (documented, like Proxmox's local state backend): this adds a
# Lambda + two IAM roles the Azure/Proxmox paths don't have. `terraform destroy`
# removes them; verify_aws_teardown double-checks nothing tagged lab=<name>
# survives.

data "archive_file" "stop_lambda" {
  type        = "zip"
  source_file = "${path.module}/lambda/stop_instances.py"
  output_path = "${path.module}/lambda/stop_instances.zip"
}

resource "aws_iam_role" "stop_lambda" {
  name = "${var.lab_name}-autoshutdown-lambda"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "stop_lambda" {
  name = "${var.lab_name}-autoshutdown-lambda"
  role = aws_iam_role.stop_lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["ec2:DescribeInstances"]
        # DescribeInstances cannot be resource-scoped by tag in IAM; the Lambda
        # itself filters to lab=<lab_name> before stopping anything.
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = ["ec2:StopInstances"]
        Resource = "*"
        Condition = {
          StringEquals = { "aws:ResourceTag/lab" = var.lab_name }
        }
      },
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "arn:aws:logs:*:*:*"
      },
    ]
  })
}

resource "aws_lambda_function" "stop" {
  function_name    = "${var.lab_name}-autoshutdown"
  role             = aws_iam_role.stop_lambda.arn
  runtime          = "python3.12"
  handler          = "stop_instances.handler"
  filename         = data.archive_file.stop_lambda.output_path
  source_code_hash = data.archive_file.stop_lambda.output_base64sha256
  timeout          = 60

  environment {
    variables = { LAB_NAME = var.lab_name }
  }
}

# Scheduler's own role to invoke the Lambda.
resource "aws_iam_role" "scheduler" {
  name = "${var.lab_name}-autoshutdown-scheduler"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "scheduler.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "scheduler" {
  name = "${var.lab_name}-autoshutdown-scheduler"
  role = aws_iam_role.scheduler.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["lambda:InvokeFunction"]
      Resource = aws_lambda_function.stop.arn
    }]
  })
}

resource "aws_scheduler_schedule" "auto_shutdown" {
  name = "${var.lab_name}-autoshutdown"

  flexible_time_window {
    mode = "OFF"
  }

  schedule_expression          = var.auto_shutdown_cron
  schedule_expression_timezone = var.auto_shutdown_timezone

  target {
    arn      = aws_lambda_function.stop.arn
    role_arn = aws_iam_role.scheduler.arn
  }
}
