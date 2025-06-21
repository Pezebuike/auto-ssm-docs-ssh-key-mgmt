# SSM Document Outputs
output "add_ssh_key_document" {
  description = "SSH Key Addition Automation Document details"
  value = {
    name              = aws_ssm_document.add_ssh_key_automation.name
    arn               = aws_ssm_document.add_ssh_key_automation.arn
    status            = aws_ssm_document.add_ssh_key_automation.status
    document_version  = aws_ssm_document.add_ssh_key_automation.document_version
    created_date      = aws_ssm_document.add_ssh_key_automation.created_date
    hash              = aws_ssm_document.add_ssh_key_automation.hash
    hash_type         = aws_ssm_document.add_ssh_key_automation.hash_type
    latest_version    = aws_ssm_document.add_ssh_key_automation.latest_version
    default_version   = aws_ssm_document.add_ssh_key_automation.default_version
    tags_all          = aws_ssm_document.add_ssh_key_automation.tags_all
  }
}

output "remove_ssh_key_document" {
  description = "SSH Key Removal Automation Document details"
  value = {
    name              = aws_ssm_document.remove_ssh_key_automation.name
    arn               = aws_ssm_document.remove_ssh_key_automation.arn
    status            = aws_ssm_document.remove_ssh_key_automation.status
    document_version  = aws_ssm_document.remove_ssh_key_automation.document_version
    created_date      = aws_ssm_document.remove_ssh_key_automation.created_date
    hash              = aws_ssm_document.remove_ssh_key_automation.hash
    hash_type         = aws_ssm_document.remove_ssh_key_automation.hash_type
    latest_version    = aws_ssm_document.remove_ssh_key_automation.latest_version
    default_version   = aws_ssm_document.remove_ssh_key_automation.default_version
    tags_all          = aws_ssm_document.remove_ssh_key_automation.tags_all
  }
}

# IAM Role Outputs
output "automation_execution_role" {
  description = "IAM role for executing the automation documents"
  value = {
    name         = aws_iam_role.ssm_automation_execution_role.name
    arn          = aws_iam_role.ssm_automation_execution_role.arn
    id           = aws_iam_role.ssm_automation_execution_role.id
    unique_id    = aws_iam_role.ssm_automation_execution_role.unique_id
    created_date = aws_iam_role.ssm_automation_execution_role.create_date
    tags_all     = aws_iam_role.ssm_automation_execution_role.tags_all
  }
}

# Quick Reference Outputs
output "document_names" {
  description = "Names of created SSM automation documents"
  value = {
    add_ssh_key    = aws_ssm_document.add_ssh_key_automation.name
    remove_ssh_key = aws_ssm_document.remove_ssh_key_automation.name
  }
}

output "document_arns" {
  description = "ARNs of created SSM automation documents"
  value = {
    add_ssh_key    = aws_ssm_document.add_ssh_key_automation.arn
    remove_ssh_key = aws_ssm_document.remove_ssh_key_automation.arn
  }
}

# Execution Examples
output "cli_execution_examples" {
  description = "Example CLI commands to execute the automation documents"
  value = {
    add_key_basic = "aws ssm start-automation-execution --document-name '${aws_ssm_document.add_ssh_key_automation.name}' --parameters 'InstanceIds=[\"i-1234567890abcdef0\"],PublicKey=\"ssh-rsa AAAAB3NzaC1yc2EAAAA...\",Username=\"${var.default_username}\"'"
    
    add_key_with_user_creation = "aws ssm start-automation-execution --document-name '${aws_ssm_document.add_ssh_key_automation.name}' --parameters 'InstanceIds=[\"i-1234567890abcdef0\"],PublicKey=\"ssh-rsa AAAAB3NzaC1yc2EAAAA...\",Username=\"newuser\",CreateUser=\"true\"'"
    
    remove_key = "aws ssm start-automation-execution --document-name '${aws_ssm_document.remove_ssh_key_automation.name}' --parameters 'InstanceIds=[\"i-1234567890abcdef0\"],PublicKey=\"ssh-rsa AAAAB3NzaC1yc2EAAAA...\",Username=\"${var.default_username}\"'"
    
    multiple_instances = "aws ssm start-automation-execution --document-name '${aws_ssm_document.add_ssh_key_automation.name}' --parameters 'InstanceIds=[\"i-1234567890abcdef0\",\"i-0987654321fedcba0\"],PublicKey=\"ssh-rsa AAAAB3NzaC1yc2EAAAA...\",Username=\"${var.default_username}\"'"
  }
}

# Terraform Module Usage Examples
output "terraform_usage_examples" {
  description = "Example Terraform configurations for using this module"
  value = {
    basic_usage = <<-EOT
      module "ssh_key_automation" {
        source = "./path/to/this/module"
        
        add_ssh_key_document_name    = "MyAddSSHKeyDocument"
        remove_ssh_key_document_name = "MyRemoveSSHKeyDocument"
        default_username             = "ubuntu"
        
        common_tags = {
          Environment = "production"
          Project     = "my-project"
        }
      }
    EOT
    
    advanced_usage = <<-EOT
      module "ssh_key_automation" {
        source = "./path/to/this/module"
        
        add_ssh_key_document_name    = "CustomAddSSHKey"
        remove_ssh_key_document_name = "CustomRemoveSSHKey"
        iam_role_name               = "CustomSSMRole"
        default_username            = "admin"
        default_create_user         = true
        execution_timeout           = 600
        backup_retention_days       = 14
        enable_logging              = true
        
        custom_add_commands = [
          "echo 'Starting custom pre-add operations'",
          "systemctl status sshd"
        ]
        
        custom_iam_policy_statements = [
          {
            effect    = "Allow"
            actions   = ["s3:GetObject"]
            resources = ["arn:aws:s3:::my-ssh-keys/*"]
          }
        ]
        
        common_tags = {
          Environment = "production"
          Project     = "security-automation"
          Owner       = "platform-team"
        }
      }
    EOT
  }
}

# Configuration Summary
output "configuration_summary" {
  description = "Summary of module configuration"
  value = {
    default_username      = var.default_username
    default_create_user   = var.default_create_user
    execution_timeout     = var.execution_timeout
    backup_retention_days = var.backup_retention_days
    enable_logging        = var.enable_logging
    working_directory     = var.working_directory
    allowed_ssh_key_types = var.allowed_ssh_key_types
  }
}