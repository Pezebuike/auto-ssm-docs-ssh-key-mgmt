# Local values for dynamic content generation
locals {
  ssh_key_pattern = "^ssh-(${join("|", var.allowed_ssh_key_types)})\\s+[A-Za-z0-9+/]+[=]{0,3}(\\s+.*)?$"
  instance_pattern = join("|", var.allowed_instance_patterns)
  
  # Generate custom commands for add operation
  add_custom_commands = length(var.custom_add_commands) > 0 ? concat([
    "# Custom commands before adding SSH key"
  ], var.custom_add_commands, [
    "# End of custom commands",
    ""
  ]) : []
  
  # Generate custom commands for remove operation
  remove_custom_commands = length(var.custom_remove_commands) > 0 ? concat([
    "# Custom commands before removing SSH key"
  ], var.custom_remove_commands, [
    "# End of custom commands",
    ""
  ]) : []
  
  # Logging configuration
  log_level = var.enable_logging ? "INFO" : "ERROR"
  
  # Backup cleanup command (if retention is set)
  backup_cleanup_commands = var.backup_retention_days > 0 ? [
    "# Cleanup old backup files",
    "find \"$SSH_DIR\" -name \"authorized_keys.backup.*\" -type f -mtime +${var.backup_retention_days} -delete 2>/dev/null || true",
    "log_info \"Cleaned up backup files older than ${var.backup_retention_days} days\""
  ] : []
}

# Main SSM Automation Document for adding SSH keys
resource "aws_ssm_document" "add_ssh_key_automation" {
  name            = var.add_ssh_key_document_name
  document_type   = "Automation"
  document_format = "YAML"
  
  content = yamlencode({
    schemaVersion = "0.3"
    description   = "Enhanced SSM Automation Document to add SSH public key to EC2 instances with proper permissions and validation"
    assumeRole    = aws_iam_role.ssm_automation_execution_role.arn
    
    parameters = {
      InstanceIds = {
        type            = "StringList"
        description     = "List of EC2 Instance IDs to add SSH key to"
        allowedPattern  = local.instance_pattern
      }
      PublicKey = {
        type           = "String"
        description    = "SSH public key content to add"
        allowedPattern = local.ssh_key_pattern
      }
      Username = {
        type           = "String"
        description    = "Username to add the SSH key for"
        default        = var.default_username
        allowedPattern = "^[a-z_]([a-z0-9_-]{0,31}|[a-z0-9_-]{0,30}\\$)$"
      }
      CreateUser = {
        type          = "String"
        description   = "Create user if it doesn't exist (true/false)"
        default       = tostring(var.default_create_user)
        allowedValues = ["true", "false"]
      }
      EnableLogging = {
        type          = "String"
        description   = "Enable detailed logging (true/false)"
        default       = tostring(var.enable_logging)
        allowedValues = ["true", "false"]
      }
    }

    mainSteps = [
      {
        name      = "ValidateInstances"
        action    = "aws:executeAwsApi"
        onFailure = "Abort"
        inputs = {
          Service = "EC2"
          Api     = "DescribeInstanceStatus"
          InstanceIds = "{{ InstanceIds }}"
        }
        outputs = [
          {
            Name     = "InstanceStatuses"
            Selector = "$.InstanceStatuses"
            Type     = "MapList"
          }
        ]
      },
      {
        name      = "AddSSHKeyToInstances"
        action    = "aws:runCommand"
        onFailure = "Continue"
        inputs = {
          DocumentName = "AWS-RunShellScript"
          InstanceIds  = "{{ InstanceIds }}"
          Parameters = {
            commands = concat([
              "#!/bin/bash",
              "set -euo pipefail",
              "",
              "# Input parameters",
              "USERNAME='{{ Username }}'",
              "PUBLIC_KEY='{{ PublicKey }}'",
              "CREATE_USER='{{ CreateUser }}'",
              "ENABLE_LOGGING='{{ EnableLogging }}'",
              "LOG_LEVEL='${local.log_level}'",
              "",
              "# Colors for output",
              "RED='\\033[0;31m'",
              "GREEN='\\033[0;32m'",
              "YELLOW='\\033[1;33m'",
              "BLUE='\\033[0;34m'",
              "NC='\\033[0m' # No Color",
              "",
              "# Function to log messages",
              "log_info() {",
              "    if [[ \"$ENABLE_LOGGING\" == \"true\" ]]; then",
              "        echo -e \"${GREEN}[INFO]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1\"",
              "    fi",
              "}",
              "",
              "log_warn() {",
              "    echo -e \"${YELLOW}[WARN]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1\"",
              "}",
              "",
              "log_error() {",
              "    echo -e \"${RED}[ERROR]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1\"",
              "}",
              "",
              "log_debug() {",
              "    if [[ \"$LOG_LEVEL\" == \"DEBUG\" ]]; then",
              "        echo -e \"${BLUE}[DEBUG]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1\"",
              "    fi",
              "}",
              "",
              "echo -e \"${GREEN}=== SSH Key Management Script Started ===${NC}\"",
              "log_info \"Target Username: $USERNAME\"",
              "log_info \"Create User: $CREATE_USER\"",
              "log_info \"Logging Enabled: $ENABLE_LOGGING\"",
              ""
            ], local.add_custom_commands, [
              "# Check if running as root or with sudo",
              "if [[ $EUID -ne 0 ]]; then",
              "    if ! command -v sudo &> /dev/null; then",
              "        log_error \"Neither root access nor sudo available\"",
              "        exit 1",
              "    fi",
              "    SUDO='sudo'",
              "    log_debug \"Using sudo for privileged operations\"",
              "else",
              "    SUDO=''",
              "    log_debug \"Running as root\"",
              "fi",
              "",
              "# Validate SSH key format",
              "if ! echo \"$PUBLIC_KEY\" | grep -E '^ssh-(rsa|dss|ed25519|ecdsa)' &>/dev/null; then",
              "    log_error \"Invalid SSH key format\"",
              "    exit 1",
              "fi",
              "log_info \"SSH key format validated\"",
              "",
              "# Check if user exists",
              "if ! id \"$USERNAME\" &>/dev/null; then",
              "    if [[ \"$CREATE_USER\" == \"true\" ]]; then",
              "        log_info \"Creating user: $USERNAME\"",
              "        if $SUDO useradd -m -s /bin/bash \"$USERNAME\"; then",
              "            log_info \"User $USERNAME created successfully\"",
              "        else",
              "            log_error \"Failed to create user $USERNAME\"",
              "            exit 1",
              "        fi",
              "    else",
              "        log_error \"User $USERNAME does not exist and CREATE_USER is false\"",
              "        exit 1",
              "    fi",
              "else",
              "    log_info \"User $USERNAME already exists\"",
              "fi",
              "",
              "# Get user's home directory",
              "USER_HOME=$(getent passwd \"$USERNAME\" | cut -d: -f6)",
              "if [[ -z \"$USER_HOME\" ]]; then",
              "    log_error \"Could not determine home directory for user $USERNAME\"",
              "    exit 1",
              "fi",
              "log_info \"User home directory: $USER_HOME\"",
              "",
              "# Create .ssh directory",
              "SSH_DIR=\"$USER_HOME/.ssh\"",
              "log_info \"Ensuring SSH directory exists: $SSH_DIR\"",
              "$SUDO mkdir -p \"$SSH_DIR\"",
              "",
              "# Set ownership and permissions for .ssh directory",
              "log_info \"Setting permissions on .ssh directory\"",
              "$SUDO chown \"$USERNAME:$USERNAME\" \"$SSH_DIR\"",
              "$SUDO chmod 700 \"$SSH_DIR\"",
              "",
              "# Handle authorized_keys file",
              "AUTHORIZED_KEYS=\"$SSH_DIR/authorized_keys\"",
              "",
              "# Check if the key already exists",
              "KEY_EXISTS=false",
              "if [[ -f \"$AUTHORIZED_KEYS\" ]]; then",
              "    if grep -Fxq \"$PUBLIC_KEY\" \"$AUTHORIZED_KEYS\"; then",
              "        log_warn \"SSH key already exists in authorized_keys\"",
              "        KEY_EXISTS=true",
              "    fi",
              "else",
              "    log_info \"Creating new authorized_keys file\"",
              "    $SUDO touch \"$AUTHORIZED_KEYS\"",
              "fi",
              "",
              "# Add the public key if it doesn't exist",
              "if [[ \"$KEY_EXISTS\" == \"false\" ]]; then",
              "    log_info \"Adding SSH public key to authorized_keys\"",
              "    echo \"$PUBLIC_KEY\" | $SUDO tee -a \"$AUTHORIZED_KEYS\" > /dev/null",
              "    log_info \"SSH key added successfully\"",
              "fi",
              "",
              "# Set proper ownership and permissions for authorized_keys",
              "log_info \"Setting permissions on authorized_keys file\"",
              "$SUDO chown \"$USERNAME:$USERNAME\" \"$AUTHORIZED_KEYS\"",
              "$SUDO chmod 600 \"$AUTHORIZED_KEYS\"",
              "",
              "# Create backup of authorized_keys",
              "BACKUP_FILE=\"$AUTHORIZED_KEYS.backup.$(date +%Y%m%d_%H%M%S)\"",
              "$SUDO cp \"$AUTHORIZED_KEYS\" \"$BACKUP_FILE\"",
              "log_info \"Backup created: $BACKUP_FILE\"",
              ""
            ], local.backup_cleanup_commands, [
              "",
              "# Verification",
              "echo -e \"${GREEN}=== Verification Results ===${NC}\"",
              "echo \"SSH directory:\"",
              "ls -ld \"$SSH_DIR\"",
              "echo \"\"",
              "echo \"Authorized keys file:\"",
              "ls -l \"$AUTHORIZED_KEYS\"",
              "echo \"\"",
              "echo \"Number of keys in authorized_keys:\"",
              "wc -l < \"$AUTHORIZED_KEYS\"",
              "",
              "# Validate permissions",
              "SSH_PERMS=$(stat -c \"%a\" \"$SSH_DIR\")",
              "AUTH_PERMS=$(stat -c \"%a\" \"$AUTHORIZED_KEYS\")",
              "",
              "if [[ \"$SSH_PERMS\" == \"700\" ]]; then",
              "    log_info \"SSH directory permissions correct: $SSH_PERMS\"",
              "else",
              "    log_error \"SSH directory permissions incorrect: $SSH_PERMS (expected: 700)\"",
              "    exit 1",
              "fi",
              "",
              "if [[ \"$AUTH_PERMS\" == \"600\" ]]; then",
              "    log_info \"Authorized keys permissions correct: $AUTH_PERMS\"",
              "else",
              "    log_error \"Authorized keys permissions incorrect: $AUTH_PERMS (expected: 600)\"",
              "    exit 1",
              "fi",
              "",
              "echo -e \"${GREEN}=== SSH Key Management Completed Successfully! ===${NC}\""
            ])
            workingDirectory  = var.working_directory
            executionTimeout  = tostring(var.execution_timeout)
          }
        }
        outputs = [
          {
            Name     = "CommandId"
            Selector = "$.CommandId"
            Type     = "String"
          }
        ]
      }
    ]

    outputs = [
      {
        Name  = "ExecutionStatus"
        Value = "{{ AddSSHKeyToInstances.Status }}"
        Type  = "String"
      },
      {
        Name  = "CommandId"
        Value = "{{ AddSSHKeyToInstances.CommandId }}"
        Type  = "String"
      }
    ]
  })

  tags = merge(
    var.common_tags,
    var.document_tags,
    {
      Name = "SSH Key Addition Automation"
      Type = "SSM Automation Document"
    }
  )
}

# SSM Automation Document for removing SSH keys
resource "aws_ssm_document" "remove_ssh_key_automation" {
  name            = var.remove_ssh_key_document_name
  document_type   = "Automation"
  document_format = "YAML"
  
  content = yamlencode({
    schemaVersion = "0.3"
    description   = "Enhanced SSM Automation Document to remove SSH public key from EC2 instances"
    assumeRole    = aws_iam_role.ssm_automation_execution_role.arn
    
    parameters = {
      InstanceIds = {
        type           = "StringList"
        description    = "List of EC2 Instance IDs to remove SSH key from"
        allowedPattern = local.instance_pattern
      }
      PublicKey = {
        type           = "String"
        description    = "SSH public key content to remove"
        allowedPattern = local.ssh_key_pattern
      }
      Username = {
        type           = "String"
        description    = "Username to remove the SSH key from"
        default        = var.default_username
        allowedPattern = "^[a-z_]([a-z0-9_-]{0,31}|[a-z0-9_-]{0,30}\\$)$"
      }
      EnableLogging = {
        type          = "String"
        description   = "Enable detailed logging (true/false)"
        default       = tostring(var.enable_logging)
        allowedValues = ["true", "false"]
      }
    }

    mainSteps = [
      {
        name      = "RemoveSSHKeyFromInstances"
        action    = "aws:runCommand"
        onFailure = "Continue"
        inputs = {
          DocumentName = "AWS-RunShellScript"
          InstanceIds  = "{{ InstanceIds }}"
          Parameters = {
            commands = concat([
              "#!/bin/bash",
              "set -euo pipefail",
              "",
              "USERNAME='{{ Username }}'",
              "PUBLIC_KEY='{{ PublicKey }}'",
              "ENABLE_LOGGING='{{ EnableLogging }}'",
              "",
              "# Colors for output",
              "RED='\\033[0;31m'",
              "GREEN='\\033[0;32m'",
              "YELLOW='\\033[1;33m'",
              "NC='\\033[0m'",
              "",
              "# Logging functions",
              "log_info() {",
              "    if [[ \"$ENABLE_LOGGING\" == \"true\" ]]; then",
              "        echo -e \"${GREEN}[INFO]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1\"",
              "    fi",
              "}",
              "",
              "log_warn() {",
              "    echo -e \"${YELLOW}[WARN]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1\"",
              "}",
              "",
              "log_error() {",
              "    echo -e \"${RED}[ERROR]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1\"",
              "}",
              "",
              "echo -e \"${GREEN}=== SSH Key Removal Started ===${NC}\"",
              ""
            ], local.remove_custom_commands, [
              "# Check sudo availability",
              "if [[ $EUID -ne 0 ]]; then",
              "    if ! command -v sudo &> /dev/null; then",
              "        log_error \"Neither root access nor sudo available\"",
              "        exit 1",
              "    fi",
              "    SUDO='sudo'",
              "else",
              "    SUDO=''",
              "fi",
              "",
              "# Check if user exists",
              "if ! id \"$USERNAME\" &>/dev/null; then",
              "    log_error \"User $USERNAME does not exist\"",
              "    exit 1",
              "fi",
              "",
              "USER_HOME=$(getent passwd \"$USERNAME\" | cut -d: -f6)",
              "AUTHORIZED_KEYS=\"$USER_HOME/.ssh/authorized_keys\"",
              "",
              "if [[ ! -f \"$AUTHORIZED_KEYS\" ]]; then",
              "    log_warn \"No authorized_keys file found for user $USERNAME\"",
              "    exit 0",
              "fi",
              "",
              "# Create backup before modification",
              "BACKUP_FILE=\"$AUTHORIZED_KEYS.backup.$(date +%Y%m%d_%H%M%S)\"",
              "$SUDO cp \"$AUTHORIZED_KEYS\" \"$BACKUP_FILE\"",
              "log_info \"Backup created: $BACKUP_FILE\"",
              "",
              "# Count keys before removal",
              "KEYS_BEFORE=$(wc -l < \"$AUTHORIZED_KEYS\")",
              "",
              "# Remove the key",
              "if grep -Fxq \"$PUBLIC_KEY\" \"$AUTHORIZED_KEYS\"; then",
              "    grep -Fxv \"$PUBLIC_KEY\" \"$AUTHORIZED_KEYS\" | $SUDO tee \"$AUTHORIZED_KEYS.tmp\" > /dev/null",
              "    $SUDO mv \"$AUTHORIZED_KEYS.tmp\" \"$AUTHORIZED_KEYS\"",
              "    $SUDO chown \"$USERNAME:$USERNAME\" \"$AUTHORIZED_KEYS\"",
              "    $SUDO chmod 600 \"$AUTHORIZED_KEYS\"",
              "    ",
              "    KEYS_AFTER=$(wc -l < \"$AUTHORIZED_KEYS\")",
              "    log_info \"SSH key removed successfully\"",
              "    log_info \"Keys before: $KEYS_BEFORE, Keys after: $KEYS_AFTER\"",
              "else",
              "    log_warn \"SSH key not found in authorized_keys\"",
              "fi",
              ""
            ], local.backup_cleanup_commands, [
              "",
              "echo -e \"${GREEN}=== SSH Key Removal Completed ===${NC}\""
            ])
            workingDirectory = var.working_directory
            executionTimeout = tostring(var.execution_timeout)
          }
        }
        outputs = [
          {
            Name     = "CommandId"
            Selector = "$.CommandId"
            Type     = "String"
          }
        ]
      }
    ]
    
    outputs = [
      {
        Name  = "ExecutionStatus"
        Value = "{{ RemoveSSHKeyFromInstances.Status }}"
        Type  = "String"
      },
      {
        Name  = "CommandId"
        Value = "{{ RemoveSSHKeyFromInstances.CommandId }}"
        Type  = "String"
      }
    ]
  })

  tags = merge(
    var.common_tags,
    var.document_tags,
    {
      Name = "SSH Key Removal Automation"
      Type = "SSM Automation Document"
    }
  )
}