provider "aws" {
  region = "us-west-1"
}

resource "aws_iam_policy" "policy" {
  name        = "demo-rolecleanup-policy"
  path        = "/"
  description = "Policies required to do role cleanup"

  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": [
                "iam:ListPolicies",
                "iam:ListInstanceProfilesForRole",
                "iam:ListAttachedRolePolicies",
                "iam:ListRoles",
                "iam:ListRolePolicies",
                "iam:GetRole",
                "iam:GetRolePolicy",
                "iam:DetachRolePolicy",
                "iam:DeleteRolePolicy",
                "iam:DeleteRole",
                "iam:RemoveRoleFromInstanceProfile"
            ],
            "Resource": "*"
        }
    ]
}
EOF
}

resource "aws_iam_role" "role" {
  name = "demo_rolecleanup_lambda_role"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "test-attach" {
  role       = aws_iam_role.role.name
  policy_arn = aws_iam_policy.policy.arn
}

data "archive_file" "init" {
  type        = "zip"
  source_file = "roleclean.py"
  output_path = "roleclean.zip"
}


resource "aws_lambda_function" "lambda" {
  filename      = data.archive_file.init.output_path
  function_name = "lambda_iamrole_cleanup"
  role          = aws_iam_role.role.arn
  handler       = "roleclean.demo"

  # The filebase64sha256() function is available in Terraform 0.11.12 and later
  # For Terraform 0.11.11 and earlier, use the base64sha256() function and the file() function:
  # source_code_hash = "${base64sha256(file("lambda_function_payload.zip"))}"
  source_code_hash = filebase64sha256(data.archive_file.init.output_path)

  runtime = "python3.8"

  environment {
    variables = {
      DAYS_UNUSED = 90
    }
  }
}

resource "aws_cloudwatch_event_rule" "every_day_once" {
  name                = "every-day-once-role-clean"
  description         = "Fires every day"
  schedule_expression = "cron(0 20 * * ? *)"
}

resource "aws_cloudwatch_event_target" "check_every_day_once" {
  rule      = aws_cloudwatch_event_rule.every_day_once.name
  target_id = "lambda"
  arn       = aws_lambda_function.lambda.arn
}

resource "aws_lambda_permission" "allow_cloudwatch_to_call_roleclean_lambda" {
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.lambda.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.every_day_once.arn
}