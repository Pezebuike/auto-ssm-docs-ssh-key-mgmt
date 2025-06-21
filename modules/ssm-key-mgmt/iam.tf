# Data source for current AWS account
data "aws_caller_identity" "current" {}

# Data source for current AWS region  
data "aws_region" "current" {}

# IAM Role for SSM Automation Document execution
resource "aws_iam_role" "ssm_automation_execution_role" {
  name = var.iam_role_name
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ssm.amazonaws.com"
        }
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      }
    ]
  })
  tags = merge(
    var.common_tags,
    var.iam_role_tags,
    {
      Name = "SSM Automation Execution Role"
      Type = "IAM Role"
    }
  )
}

# Enhanced IAM Policy with comprehensive permissions
resource "aws_iam_role_policy" "ssm_automation_policy" {
  name = var.iam_policy_name
  role = aws_iam_role.ssm_automation_execution_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([
      {
        Effect = "Allow"
        Action = [
          # Core SSM permissions
          "ssm:SendCommand",
          "ssm:ListCommands",
          "ssm:ListCommandInvocations",
          "ssm:DescribeInstanceInformation",
          "ssm:GetCommandInvocation",
          "ssm:DescribeInstanceAssociationsStatus",
          "ssm:GetAutomationExecution",
          "ssm:StopAutomationExecution",
          "ssm:StartAutomationExecution",
          "ssm:DescribeAutomationExecutions",
          "ssm:DescribeAutomationStepExecutions",
          "ssm:GetDocument",
          "ssm:DescribeDocument",
          "ssm:ListDocuments",
          # Additional SSM permissions for debugging
          "ssm:DescribeInstanceProperties",
          "ssm:GetConnectionStatus",
          "ssm:DescribeInstancePatchStates"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          # EC2 permissions for instance discovery and validation
          "ec2:DescribeInstances",
          "ec2:DescribeInstanceStatus",
          "ec2:DescribeInstanceAttribute",
          "ec2:DescribeImages",
          "ec2:DescribeSnapshots",
          "ec2:DescribeVolumes",
          "ec2:DescribeTags",
          "ec2:DescribeRegions",
          "ec2:DescribeAvailabilityZones"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "iam:PassRole"
        ]
        Resource = [
          "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${var.iam_role_name}",
          "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/SSMAutomationExecutionRole-*",
          aws_iam_role.ssm_automation_execution_role.arn
        ]
      },
      {
        Effect = "Allow"
        Action = [
          # CloudWatch Logs for debugging
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams",
          "logs:GetLogEvents"
        ]
        Resource = [
          "arn:aws:logs:${data.aws_region.current.id}:${data.aws_caller_identity.current.account_id}:log-group:/aws/ssm/*",
          "arn:aws:logs:${data.aws_region.current.id}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          # Lambda permissions for Python scripts
          "lambda:InvokeFunction"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          # Additional IAM permissions for debugging
          "iam:GetRole",
          "iam:GetRolePolicy",
          "iam:ListAttachedRolePolicies",
          "iam:ListRolePolicies"
        ]
        Resource = "*"
      }
    ], var.custom_iam_policy_statements)
  })
}

# Attach additional managed policies for comprehensive access
resource "aws_iam_role_policy_attachment" "ssm_automation_managed_policy" {
  role       = aws_iam_role.ssm_automation_execution_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy_attachment" "ssm_full_access" {
  role       = aws_iam_role.ssm_automation_execution_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMFullAccess"
}

resource "aws_iam_role_policy_attachment" "ec2_read_only" {
  role       = aws_iam_role.ssm_automation_execution_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ReadOnlyAccess"
}