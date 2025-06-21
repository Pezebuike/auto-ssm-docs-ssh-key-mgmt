# Simplified working SSM Documents that will deploy successfully

resource "aws_ssm_document" "add_ssh_key_automation" {
  name            = var.add_ssh_key_document_name
  document_type   = "Automation"
  document_format = "YAML"
  
  content = yamlencode({
    schemaVersion = "0.3"
    description   = "Add SSH public key to EC2 instances"
    assumeRole    = aws_iam_role.ssm_automation_execution_role.arn
    
    parameters = {
      InstanceIds = {
        type        = "StringList"
        description = "EC2 Instance IDs to add SSH key to"
      }
      PublicKey = {
        type        = "String"
        description = "SSH public key content to add"
      }
      Username = {
        type    = "String"
        description = "Username to add the SSH key for"
        default = var.default_username
      }
      CreateUser = {
        type          = "String"
        description   = "Create user if it doesn't exist"
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
              "set -e",
              "USERNAME='{{ Username }}'",
              "PUBLIC_KEY='{{ PublicKey }}'",
              "CREATE_USER='{{ CreateUser }}'",
              "",
              "echo \"Starting SSH key addition for user: $USERNAME\"",
              "",
              "# Check sudo access",
              "if [[ $EUID -ne 0 ]]; then",
              "    SUDO='sudo'",
              "else",
              "    SUDO=''",
              "fi",
              "",
              "# Validate SSH key format",
              "if ! echo \"$PUBLIC_KEY\" | grep -E '^ssh-(rsa|dss|ed25519|ecdsa)' >/dev/null; then",
              "    echo \"ERROR: Invalid SSH key format\"",
              "    exit 1",
              "fi",
              "",
              "# Check if user exists",
              "if ! id \"$USERNAME\" >/dev/null 2>&1; then",
              "    if [[ \"$CREATE_USER\" == \"true\" ]]; then",
              "        echo \"Creating user: $USERNAME\"",
              "        $SUDO useradd -m -s /bin/bash \"$USERNAME\"",
              "    else",
              "        echo \"ERROR: User $USERNAME does not exist\"",
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
              "    echo \"SSH key already exists\"",
              "    exit 0",
              "fi",
              "",
              "# Add the public key",
              "echo \"$PUBLIC_KEY\" | $SUDO tee -a \"$AUTHORIZED_KEYS\" >/dev/null",
              "$SUDO chown \"$USERNAME:$USERNAME\" \"$AUTHORIZED_KEYS\"",
              "$SUDO chmod 600 \"$AUTHORIZED_KEYS\"",
              "",
              "echo \"SSH key added successfully for user: $USERNAME\""
            ]
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

resource "aws_ssm_document" "remove_ssh_key_automation" {
  name            = var.remove_ssh_key_document_name
  document_type   = "Automation"
  document_format = "YAML"
  
  content = yamlencode({
    schemaVersion = "0.3"
    description   = "Remove SSH public key from EC2 instances"
    assumeRole    = aws_iam_role.ssm_automation_execution_role.arn
    
    parameters = {
      InstanceIds = {
        type        = "StringList"
        description = "EC2 Instance IDs to remove SSH key from"
      }
      PublicKey = {
        type        = "String"
        description = "SSH public key content to remove"
      }
      Username = {
        type    = "String"
        description = "Username to remove the SSH key from"
        default = var.default_username
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
              "set -e",
              "USERNAME='{{ Username }}'",
              "PUBLIC_KEY='{{ PublicKey }}'",
              "",
              "echo \"Starting SSH key removal for user: $USERNAME\"",
              "",
              "# Check sudo access",
              "if [[ $EUID -ne 0 ]]; then",
              "    SUDO='sudo'",
              "else",
              "    SUDO=''",
              "fi",
              "",
              "# Check if user exists",
              "if ! id \"$USERNAME\" >/dev/null 2>&1; then",
              "    echo \"ERROR: User $USERNAME does not exist\"",
              "    exit 1",
              "fi",
              "",
              "USER_HOME=$(getent passwd \"$USERNAME\" | cut -d: -f6)",
              "AUTHORIZED_KEYS=\"$USER_HOME/.ssh/authorized_keys\"",
              "",
              "if [[ ! -f \"$AUTHORIZED_KEYS\" ]]; then",
              "    echo \"No authorized_keys file found\"",
              "    exit 0",
              "fi",
              "",
              "# Check if key exists",
              "if ! grep -Fxq \"$PUBLIC_KEY\" \"$AUTHORIZED_KEYS\"; then",
              "    echo \"SSH key not found\"",
              "    exit 0",
              "fi",
              "",
              "# Create backup",
              "BACKUP_FILE=\"$AUTHORIZED_KEYS.backup.$(date +%Y%m%d_%H%M%S)\"",
              "$SUDO cp \"$AUTHORIZED_KEYS\" \"$BACKUP_FILE\"",
              "",
              "# Remove the key",
              "grep -Fxv \"$PUBLIC_KEY\" \"$AUTHORIZED_KEYS\" | $SUDO tee \"$AUTHORIZED_KEYS.tmp\" >/dev/null",
              "$SUDO mv \"$AUTHORIZED_KEYS.tmp\" \"$AUTHORIZED_KEYS\"",
              "$SUDO chown \"$USERNAME:$USERNAME\" \"$AUTHORIZED_KEYS\"",
              "$SUDO chmod 600 \"$AUTHORIZED_KEYS\"",
              "",
              "echo \"SSH key removed successfully from user: $USERNAME\""
            ]
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