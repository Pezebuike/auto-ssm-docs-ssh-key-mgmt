# Document Configuration
add_ssh_key_document_name    = "AddSSHKeyToInstance"
remove_ssh_key_document_name = "RemoveSSHKeyFromInstance"

# IAM Configuration
iam_role_name   = "SSMAutomationExecutionRole-SSHKey"
iam_policy_name = "SSMAutomationPolicy-SSHKey"

# Additional IAM policy statements (empty by default)
custom_iam_policy_statements = []

# Default SSH Configuration
default_username    = "ec2-user"
default_create_user = false
execution_timeout   = 300

# Tagging
common_tags = {
  Environment = "production"
  ManagedBy   = "terraform"
  Purpose     = "ssh-key-management"
}

iam_role_tags = {}

document_tags = {}

# Advanced Configuration
enable_logging         = true
backup_retention_days  = 7

# Allowed patterns and types
allowed_instance_patterns = ["^i-[0-9a-f]{8,17}$"]
allowed_ssh_key_types     = ["rsa", "dss", "ed25519", "ecdsa"]

# Document Content Customization
custom_add_commands    = []
custom_remove_commands = []
working_directory      = "/tmp"