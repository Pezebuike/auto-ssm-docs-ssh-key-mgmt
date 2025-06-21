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

# Base IAM Policy for the automation role
resource "aws_iam_role_policy" "ssm_automation_policy" {
  name = var.iam_policy_name
  role = aws_iam_role.ssm_automation_execution_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([
      {
        Effect = "Allow"
        Action = [
          "ssm:SendCommand",
          "ssm:ListCommands", 
          "ssm:ListCommandInvocations",
          "ssm:DescribeInstanceInformation",
          "ssm:GetCommandInvocation",
          "ssm:DescribeInstanceAssociationsStatus",
          "ssm:GetAutomationExecution",
          "ssm:StopAutomationExecution"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeInstanceStatus", 
          "ec2:DescribeInstanceAttribute"
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
          "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/SSMAutomationExecutionRole-*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream", 
          "logs:PutLogEvents",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams"
        ]
        Resource = [
          "arn:aws:logs:${data.aws_region.current.id}:${data.aws_caller_identity.current.account_id}:log-group:/aws/ssm/*"
        ]
      }
    ], var.custom_iam_policy_statements)
  })
}

# Optional: Attach AWS managed policy for SSM
resource "aws_iam_role_policy_attachment" "ssm_automation_managed_policy" {
  role       = aws_iam_role.ssm_automation_execution_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}