# Main configuration file for SSH Key Management Terraform Module
# This module creates SSM automation documents for managing SSH keys on EC2 instances

# Local values for module-wide configuration
locals {
  module_name    = "ssh-key-management"
  module_version = "1.0.0"
  
  # Common resource naming prefix
  resource_prefix = var.common_tags.Environment != null ? "${var.common_tags.Environment}-" : ""
  
  # Merged tags for all resources
  default_tags = merge(
    var.common_tags,
    {
      Module        = local.module_name
      ModuleVersion = local.module_version
      ManagedBy     = "terraform"
    }
  )
}

# Optional: CloudWatch Log Group for SSM execution logs
resource "aws_cloudwatch_log_group" "ssm_automation_logs" {
  count = var.enable_logging ? 1 : 0
  
  name              = "/aws/ssm/automation/${var.add_ssh_key_document_name}"
  retention_in_days = var.backup_retention_days > 0 ? var.backup_retention_days : 7
  
  tags = merge(
    local.default_tags,
    {
      Name = "SSM Automation Logs"
      Type = "CloudWatch Log Group"
    }
  )
}

# Optional: CloudWatch Log Group for command execution
resource "aws_cloudwatch_log_group" "ssm_command_logs" {
  count = var.enable_logging ? 1 : 0
  
  name              = "/aws/ssm/commands"
  retention_in_days = var.backup_retention_days > 0 ? var.backup_retention_days : 7
  
  tags = merge(
    local.default_tags,
    {
      Name = "SSM Command Execution Logs"
      Type = "CloudWatch Log Group"
    }
  )
}