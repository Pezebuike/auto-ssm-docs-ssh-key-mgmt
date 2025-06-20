# Document Configuration
variable "add_ssh_key_document_name" {
  description = "Name of the SSH key addition automation document"
  type        = string
  
  validation {
    condition     = can(regex("^[a-zA-Z0-9_.-]+$", var.add_ssh_key_document_name))
    error_message = "Document name must contain only alphanumeric characters, underscores, hyphens, and periods."
  }
}

variable "remove_ssh_key_document_name" {
  description = "Name of the SSH key removal automation document"
  type        = string
  
  validation {
    condition     = can(regex("^[a-zA-Z0-9_.-]+$", var.remove_ssh_key_document_name))
    error_message = "Document name must contain only alphanumeric characters, underscores, hyphens, and periods."
  }
}

# IAM Configuration
variable "iam_role_name" {
  description = "Name of the IAM role for SSM automation execution"
  type        = string
}

variable "iam_policy_name" {
  description = "Name of the IAM policy for SSM automation"
  type        = string
}

variable "custom_iam_policy_statements" {
  description = "Additional IAM policy statements to attach to the automation role"
  type = list(object({
    effect    = string
    actions   = list(string)
    resources = list(string)
    condition = optional(map(object({
      test     = string
      variable = string
      values   = list(string)
    })))
  }))
}

# Default SSH Configuration
variable "default_username" {
  description = "Default username for SSH key operations"
  type        = string
  
  validation {
    condition     = can(regex("^[a-z_]([a-z0-9_-]{0,31}|[a-z0-9_-]{0,30}\\$)$", var.default_username))
    error_message = "Username must follow Linux username conventions."
  }
}

variable "default_create_user" {
  description = "Default setting for creating user if it doesn't exist"
  type        = bool
}

variable "execution_timeout" {
  description = "Timeout for SSH key operations in seconds"
  type        = number
  
  validation {
    condition     = var.execution_timeout > 0 && var.execution_timeout <= 3600
    error_message = "Execution timeout must be between 1 and 3600 seconds."
  }
}

# Tagging
variable "common_tags" {
  description = "Common tags to apply to all resources"
  type        = map(string)
}

variable "iam_role_tags" {
  description = "Additional tags for the IAM role"
  type        = map(string)
}

variable "document_tags" {
  description = "Additional tags for SSM documents"
  type        = map(string)
}

# Advanced Configuration
variable "enable_logging" {
  description = "Enable detailed logging in automation scripts"
  type        = bool
}

variable "backup_retention_days" {
  description = "Number of days to keep backup files (0 for no automatic cleanup)"
  type        = number
  
  validation {
    condition     = var.backup_retention_days >= 0
    error_message = "Backup retention days must be a non-negative number."
  }
}

variable "allowed_instance_patterns" {
  description = "Allowed patterns for instance IDs (regex)"
  type        = list(string)
}

variable "allowed_ssh_key_types" {
  description = "Allowed SSH key types"
  type        = list(string)
}

# Document Content Customization
variable "custom_add_commands" {
  description = "Custom commands to run before adding SSH key"
  type        = list(string)
}

variable "custom_remove_commands" {
  description = "Custom commands to run before removing SSH key"
  type        = list(string)
}

variable "working_directory" {
  description = "Working directory for command execution"
  type        = string
}