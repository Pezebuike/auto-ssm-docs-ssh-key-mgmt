# Main SSM Automation Document for adding SSH keys
resource "aws_ssm_document" "add_ssh_key_automation" {
  name            = var.add_ssh_key_document_name
  document_type   = "Automation"
  document_format = "YAML"
  
  content = yamlencode({
    schemaVersion = "0.3"
    description   = "SSM Automation Document to add SSH public key to EC2 instances"
    assumeRole    = aws_iam_role.ssm_automation_execution_role.arn
    
    parameters = {
      InstanceIds = {
        type            = "StringList"
        description     = "List of EC2 Instance IDs to add SSH key to"
        allowedPattern  = "^i-[0-9a-f]{8,17}$"
      }
      PublicKey = {
        type           = "String"
        description    = "SSH public key content to add"
        allowedPattern = "^ssh-(rsa|dss|ed25519|ecdsa)\\s+[A-Za-z0-9+/]+[=]{0,3}(\\s+.*)?$"
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
    }

    mainSteps = [
      {
        name   = "AddSSHKeyToInstances"
        action = "aws:runCommand"
        inputs = {
          DocumentName = "AWS-RunShellScript"
          InstanceIds  = "{{ InstanceIds }}"
          Parameters = {
            commands = [
              "#!/bin/bash",
              "set -euo pipefail",
              "",
              "USERNAME='{{ Username }}'",
              "PUBLIC_KEY='{{ PublicKey }}'", 
              "CREATE_USER='{{ CreateUser }}'",
              "",
              "# Colors for output",
              "RED='\\033[0;31m'",
              "GREEN='\\033[0;32m'",
              "YELLOW='\\033[1;33m'",
              "NC='\\033[0m'",
              "",
              "log_info() { echo -e \"$${GREEN}[INFO]$${NC} $1\"; }",
              "log_warn() { echo -e \"$${YELLOW}[WARN]$${NC} $1\"; }",
              "log_error() { echo -e \"$${RED}[ERROR]$${NC} $1\"; }",
              "",
              "echo -e \"$${GREEN}=== SSH Key Management Started ===$${NC}\"",
              "",
              "# Check sudo access",
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
              "# Validate SSH key format",
              "if ! echo \"$PUBLIC_KEY\" | grep -E '^ssh-(rsa|dss|ed25519|ecdsa)' &>/dev/null; then",
              "    log_error \"Invalid SSH key format\"",
              "    exit 1",
              "fi",
              "",
              "# Check if user exists",
              "if ! id \"$USERNAME\" &>/dev/null; then",
              "    if [[ \"$CREATE_USER\" == \"true\" ]]; then",
              "        log_info \"Creating user: $USERNAME\"",
              "        $SUDO useradd -m -s /bin/bash \"$USERNAME\"",
              "    else",
              "        log_error \"User $USERNAME does not exist and CREATE_USER is false\"",
              "        exit 1",
              "    fi",
              "fi",
              "",
              "# Get user home directory",
              "USER_HOME=$(getent passwd \"$USERNAME\" | cut -d: -f6)",
              "SSH_DIR=\"$USER_HOME/.ssh\"",
              "AUTHORIZED_KEYS=\"$SSH_DIR/authorized_keys\"",
              "",
              "# Create .ssh directory",
              "$SUDO mkdir -p \"$SSH_DIR\"",
              "$SUDO chown \"$USERNAME:$USERNAME\" \"$SSH_DIR\"",
              "$SUDO chmod 700 \"$SSH_DIR\"",
              "",
              "# Check if key already exists",
              "if [[ -f \"$AUTHORIZED_KEYS\" ]] && grep -Fxq \"$PUBLIC_KEY\" \"$AUTHORIZED_KEYS\"; then",
              "    log_warn \"SSH key already exists\"",
              "    exit 0",
              "fi",
              "",
              "# Add the public key",
              "echo \"$PUBLIC_KEY\" | $SUDO tee -a \"$AUTHORIZED_KEYS\" > /dev/null",
              "$SUDO chown \"$USERNAME:$USERNAME\" \"$AUTHORIZED_KEYS\"",
              "$SUDO chmod 600 \"$AUTHORIZED_KEYS\"",
              "",
              "log_info \"SSH key added successfully\"",
              "echo -e \"$${GREEN}=== SSH Key Management Completed ===$${NC}\""
            ]
            workingDirectory  = "/tmp"
            executionTimeout  = "3600"
          }
        }
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
    description   = "SSM Automation Document to remove SSH public key from EC2 instances"
    assumeRole    = aws_iam_role.ssm_automation_execution_role.arn
    
    parameters = {
      InstanceIds = {
        type           = "StringList"
        description    = "List of EC2 Instance IDs to remove SSH key from"
        allowedPattern = "^i-[0-9a-f]{8,17}$"
      }
      PublicKey = {
        type           = "String"
        description    = "SSH public key content to remove"
        allowedPattern = "^ssh-(rsa|dss|ed25519|ecdsa)\\s+[A-Za-z0-9+/]+[=]{0,3}(\\s+.*)?$"
      }
      Username = {
        type           = "String"
        description    = "Username to remove the SSH key from"
        default        = var.default_username
        allowedPattern = "^[a-z_]([a-z0-9_-]{0,31}|[a-z0-9_-]{0,30}\\$)$"
      }
    }

    mainSteps = [
      {
        name   = "RemoveSSHKeyFromInstances"
        action = "aws:runCommand"
        inputs = {
          DocumentName = "AWS-RunShellScript"
          InstanceIds  = "{{ InstanceIds }}"
          Parameters = {
            commands = [
              "#!/bin/bash",
              "set -euo pipefail",
              "",
              "USERNAME='{{ Username }}'",
              "PUBLIC_KEY='{{ PublicKey }}'",
              "",
              "# Colors for output",
              "RED='\\033[0;31m'",
              "GREEN='\\033[0;32m'",
              "YELLOW='\\033[1;33m'",
              "NC='\\033[0m'",
              "",
              "log_info() { echo -e \"$${GREEN}[INFO]$${NC} $1\"; }",
              "log_warn() { echo -e \"$${YELLOW}[WARN]$${NC} $1\"; }",
              "log_error() { echo -e \"$${RED}[ERROR]$${NC} $1\"; }",
              "",
              "echo -e \"$${GREEN}=== SSH Key Removal Started ===$${NC}\"",
              "",
              "# Check sudo access",
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
              "    log_warn \"No authorized_keys file found\"",
              "    exit 0",
              "fi",
              "",
              "# Create backup",
              "BACKUP_FILE=\"$AUTHORIZED_KEYS.backup.$(date +%Y%m%d_%H%M%S)\"",
              "$SUDO cp \"$AUTHORIZED_KEYS\" \"$BACKUP_FILE\"",
              "",
              "# Remove the key",
              "if grep -Fxq \"$PUBLIC_KEY\" \"$AUTHORIZED_KEYS\"; then",
              "    grep -Fxv \"$PUBLIC_KEY\" \"$AUTHORIZED_KEYS\" | $SUDO tee \"$AUTHORIZED_KEYS.tmp\" > /dev/null",
              "    $SUDO mv \"$AUTHORIZED_KEYS.tmp\" \"$AUTHORIZED_KEYS\"",
              "    $SUDO chown \"$USERNAME:$USERNAME\" \"$AUTHORIZED_KEYS\"",
              "    $SUDO chmod 600 \"$AUTHORIZED_KEYS\"",
              "    log_info \"SSH key removed successfully\"",
              "else",
              "    log_warn \"SSH key not found\"",
              "fi",
              "",
              "echo -e \"$${GREEN}=== SSH Key Removal Completed ===$${NC}\""
            ]
            workingDirectory = "/tmp"
            executionTimeout = "3600"
          }
        }
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