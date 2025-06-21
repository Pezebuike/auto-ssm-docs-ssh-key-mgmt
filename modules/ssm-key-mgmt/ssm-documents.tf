# Corrected SSM Automation Document for removing SSH keys with properly escaped shell variables
resource "aws_ssm_document" "remove_ssh_key_automation" {
  name            = var.remove_ssh_key_document_name
  document_type   = "Automation"
  document_format = "YAML"
  
  content = yamlencode({
    schemaVersion = "0.3"
    description   = "SSM Automation Document to remove SSH public key from EC2 instances with debugging"
    assumeRole    = aws_iam_role.ssm_automation_execution_role.arn
    
    parameters = {
      InstanceIds = {
        type            = "StringList"
        description     = "Specific EC2 Instance IDs to remove SSH key from"
        allowedPattern  = "^i-[0-9a-f]{8,17}$"
        default         = []
      }
      TagKey = {
        type        = "String"
        description = "Tag key to filter instances (optional)"
        default     = ""
      }
      TagValue = {
        type        = "String"
        description = "Tag value to filter instances (optional)"
        default     = ""
      }
      InstanceNamePattern = {
        type        = "String"
        description = "Instance name pattern to filter (optional)"
        default     = ""
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
      DebugMode = {
        type          = "String"
        description   = "Enable debug mode for troubleshooting (true/false)"
        default       = "true"
        allowedValues = ["true", "false"]
      }
    }

    mainSteps = [
      {
        name   = "DebugInputs"
        action = "aws:executeScript"
        timeoutSeconds = 60
        inputs = {
          Runtime = "python3.8"
          Handler = "debug_inputs"
          Script = <<-EOF
import json

def debug_inputs(events, context):
    print("=== DEBUG: Remove SSH Key Input Parameters ===")
    for key, value in events.items():
        if key == 'PublicKey':
            print(f"{key}: {str(value)[:50]}... (truncated)")
        else:
            print(f"{key}: {value}")
    
    return {
        'Status': 'Success',
        'Message': 'Input parameters logged successfully'
    }
EOF
          InputPayload = {
            InstanceIds = "{{ InstanceIds }}"
            TagKey = "{{ TagKey }}"
            TagValue = "{{ TagValue }}"
            InstanceNamePattern = "{{ InstanceNamePattern }}"
            Username = "{{ Username }}"
            DebugMode = "{{ DebugMode }}"
          }
        }
      },
      {
        name   = "GetAllRunningInstances"
        action = "aws:executeAwsApi"
        timeoutSeconds = 120
        inputs = {
          Service = "EC2"
          Api     = "DescribeInstances"
          Filters = [
            {
              Name   = "instance-state-name"
              Values = ["running"]
            }
          ]
        }
        outputs = [
          {
            Name     = "AllInstances"
            Selector = "$.Reservations[*].Instances[*].InstanceId"
            Type     = "StringList"
          }
        ]
      },
      {
        name   = "CheckSSMManagedInstances"
        action = "aws:executeAwsApi"
        timeoutSeconds = 120
        inputs = {
          Service = "SSM"
          Api     = "DescribeInstanceInformation"
        }
        outputs = [
          {
            Name     = "ManagedInstances"
            Selector = "$.InstanceInformationList[*].InstanceId"
            Type     = "StringList"
          }
        ]
      },
      {
        name   = "FilterAndValidateInstances"
        action = "aws:executeScript"
        timeoutSeconds = 120
        inputs = {
          Runtime = "python3.8"
          Handler = "filter_and_validate"
          Script = <<-EOF
import boto3
import json

def filter_and_validate(events, context):
    print("=== DEBUG: Starting Instance Filtering for SSH Key Removal ===")
    
    instance_ids = events.get('InstanceIds', [])
    tag_key = events.get('TagKey', '')
    tag_value = events.get('TagValue', '')
    name_pattern = events.get('InstanceNamePattern', '')
    all_instances = events.get('AllInstances', [])
    managed_instances = events.get('ManagedInstances', [])
    
    print(f"Input InstanceIds: {instance_ids}")
    print(f"All running instances: {len(all_instances)} found")
    print(f"SSM managed instances: {len(managed_instances)} found")
    
    target_instances = []
    
    if instance_ids and len(instance_ids) > 0 and instance_ids[0] != '':
        target_instances = instance_ids
    else:
        ec2 = boto3.client('ec2')
        filters = [{'Name': 'instance-state-name', 'Values': ['running']}]
        
        if tag_key and tag_value:
            filters.append({'Name': f'tag:{tag_key}', 'Values': [tag_value]})
        
        if name_pattern:
            filters.append({'Name': 'tag:Name', 'Values': [f'*{name_pattern}*']})
        
        try:
            response = ec2.describe_instances(Filters=filters)
            for reservation in response['Reservations']:
                for instance in reservation['Instances']:
                    target_instances.append(instance['InstanceId'])
            
            if not target_instances and not tag_key and not tag_value and not name_pattern:
                target_instances = all_instances[:5]
        
        except Exception as e:
            print(f"ERROR filtering instances: {str(e)}")
            return {
                'TargetInstances': [],
                'ManagedTargetInstances': [],
                'Error': f"Failed to filter instances: {str(e)}"
            }
    
    managed_target_instances = [i for i in target_instances if i in managed_instances]
    unmanaged_instances = [i for i in target_instances if i not in managed_instances]
    
    print(f"Target instances that are SSM-managed: {managed_target_instances}")
    print(f"Target instances that are NOT SSM-managed: {unmanaged_instances}")
    
    return {
        'TargetInstances': target_instances,
        'ManagedTargetInstances': managed_target_instances,
        'UnmanagedInstances': unmanaged_instances,
        'Status': 'Success' if managed_target_instances else 'NoManagedInstances'
    }
EOF
          InputPayload = {
            InstanceIds = "{{ InstanceIds }}"
            TagKey = "{{ TagKey }}"
            TagValue = "{{ TagValue }}"
            InstanceNamePattern = "{{ InstanceNamePattern }}"
            AllInstances = "{{ GetAllRunningInstances.AllInstances }}"
            ManagedInstances = "{{ CheckSSMManagedInstances.ManagedInstances }}"
          }
        }
        outputs = [
          {
            Name     = "TargetInstances"
            Selector = "$.Payload.TargetInstances"
            Type     = "StringList"
          },
          {
            Name     = "ManagedTargetInstances"
            Selector = "$.Payload.ManagedTargetInstances"
            Type     = "StringList"
          },
          {
            Name     = "ValidationStatus"
            Selector = "$.Payload.Status"
            Type     = "String"
          }
        ]
      },
      {
        name   = "ValidateHasManagedInstances"
        action = "aws:branch"
        inputs = {
          Choices = [
            {
              NextStep = "RemoveSSHKeyFromInstances"
              Variable = "{{ FilterAndValidateInstances.ValidationStatus }}"
              StringEquals = "Success"
            }
          ]
          Default = "HandleNoManagedInstances"
        }
      },
      {
        name   = "HandleNoManagedInstances"
        action = "aws:executeScript"
        timeoutSeconds = 30
        inputs = {
          Runtime = "python3.8"
          Handler = "handle_no_managed"
          Script = <<-EOF
def handle_no_managed(events, context):
    print("=== ERROR: No SSM-Managed Instances Found for SSH Key Removal ===")
    print("This automation requires instances to be managed by Systems Manager.")
    return {'Error': 'No SSM-managed instances available'}
EOF
          InputPayload = {
            UnmanagedInstances = "{{ FilterAndValidateInstances.UnmanagedInstances }}"
          }
        }
        isEnd = true
      },
      {
        name   = "RemoveSSHKeyFromInstances"
        action = "aws:runCommand"
        timeoutSeconds = 300
        inputs = {
          DocumentName = "AWS-RunShellScript"
          InstanceIds  = "{{ FilterAndValidateInstances.ManagedTargetInstances }}"
          Parameters = {
            commands = [
              "#!/bin/bash",
              "set -euo pipefail",
              "",
              "USERNAME='{{ Username }}'",
              "PUBLIC_KEY='{{ PublicKey }}'",
              "DEBUG_MODE='{{ DebugMode }}'",
              "",
              "# Colors for output",
              "RED='\\033[0;31m'",
              "GREEN='\\033[0;32m'",
              "YELLOW='\\033[1;33m'",
              "BLUE='\\033[0;34m'",
              "NC='\\033[0m'",
              "",
              "log_info() { echo -e \"$${GREEN}[INFO]$${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1\"; }",
              "log_warn() { echo -e \"$${YELLOW}[WARN]$${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1\"; }",
              "log_error() { echo -e \"$${RED}[ERROR]$${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1\"; }",
              "log_debug() { [[ \"$DEBUG_MODE\" == \"true\" ]] && echo -e \"$${BLUE}[DEBUG]$${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1\" || true; }",
              "",
              "echo -e \"$${GREEN}=== SSH Key Removal Started ===$${NC}\"",
              "log_info \"Instance ID: $(curl -s http://169.254.169.254/latest/meta-data/instance-id 2>/dev/null || echo 'Unknown')\"",
              "log_info \"Target Username: $USERNAME\"",
              "log_debug \"Debug Mode: $DEBUG_MODE\"",
              "",
              "# Check sudo access",
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
              "# Check if user exists",
              "log_debug \"Checking if user '$USERNAME' exists...\"",
              "if ! id \"$USERNAME\" &>/dev/null; then",
              "    log_error \"User $USERNAME does not exist\"",
              "    log_debug \"Available users: $(cut -d: -f1 /etc/passwd | tail -10)\"",
              "    exit 1",
              "fi",
              "log_info \"User $USERNAME found\"",
              "",
              "USER_HOME=$(getent passwd \"$USERNAME\" | cut -d: -f6)",
              "AUTHORIZED_KEYS=\"$USER_HOME/.ssh/authorized_keys\"",
              "log_debug \"Authorized keys file: $AUTHORIZED_KEYS\"",
              "",
              "if [[ ! -f \"$AUTHORIZED_KEYS\" ]]; then",
              "    log_warn \"No authorized_keys file found for user $USERNAME\"",
              "    echo -e \"$${GREEN}=== SSH Key Removal Completed (Nothing to Remove) ===$${NC}\"",
              "    exit 0",
              "fi",
              "",
              "# Check current file status",
              "KEYS_BEFORE=$(wc -l < \"$AUTHORIZED_KEYS\")",
              "log_info \"Current authorized_keys file has $KEYS_BEFORE keys\"",
              "log_debug \"File permissions: $(stat -c '%a' \"$AUTHORIZED_KEYS\")\"",
              "log_debug \"File owner: $(stat -c '%U:%G' \"$AUTHORIZED_KEYS\")\"",
              "",
              "# Check if key exists",
              "log_debug \"Searching for SSH key in authorized_keys...\"",
              "if ! grep -Fxq \"$PUBLIC_KEY\" \"$AUTHORIZED_KEYS\"; then",
              "    log_warn \"SSH key not found in authorized_keys\"",
              "    echo -e \"$${GREEN}=== SSH Key Removal Completed (Key Not Found) ===$${NC}\"",
              "    exit 0",
              "fi",
              "log_info \"SSH key found in authorized_keys\"",
              "",
              "# Create backup",
              "BACKUP_FILE=\"$AUTHORIZED_KEYS.backup.$(date +%Y%m%d_%H%M%S)\"",
              "log_debug \"Creating backup: $BACKUP_FILE\"",
              "$SUDO cp \"$AUTHORIZED_KEYS\" \"$BACKUP_FILE\"",
              "log_info \"Backup created: $BACKUP_FILE\"",
              "",
              "# Remove the key",
              "log_info \"Removing SSH key from authorized_keys\"",
              "log_debug \"Creating temporary file without the target key...\"",
              "grep -Fxv \"$PUBLIC_KEY\" \"$AUTHORIZED_KEYS\" | $SUDO tee \"$AUTHORIZED_KEYS.tmp\" > /dev/null",
              "$SUDO mv \"$AUTHORIZED_KEYS.tmp\" \"$AUTHORIZED_KEYS\"",
              "",
              "# Restore proper ownership and permissions",
              "log_debug \"Restoring ownership and permissions...\"",
              "$SUDO chown \"$USERNAME:$USERNAME\" \"$AUTHORIZED_KEYS\"",
              "$SUDO chmod 600 \"$AUTHORIZED_KEYS\"",
              "",
              "# Verify removal",
              "KEYS_AFTER=$(wc -l < \"$AUTHORIZED_KEYS\")",
              "KEYS_REMOVED=$((KEYS_BEFORE - KEYS_AFTER))",
              "",
              "log_info \"SSH key removed successfully\"",
              "log_info \"Keys before: $KEYS_BEFORE, Keys after: $KEYS_AFTER\"",
              "log_info \"Keys removed: $KEYS_REMOVED\"",
              "",
              "# Final verification",
              "log_debug \"Verifying key is no longer present...\"",
              "if grep -Fxq \"$PUBLIC_KEY\" \"$AUTHORIZED_KEYS\"; then",
              "    log_error \"ERROR: SSH key still found in file after removal!\"",
              "    exit 1",
              "else",
              "    log_debug \"Verification passed - key successfully removed\"",
              "fi",
              "",
              "echo -e \"$${GREEN}=== SSH Key Removal Completed Successfully ===$${NC}\""
            ]
            workingDirectory = "/tmp"
            executionTimeout = "180"
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
        Name  = "TargetInstances"
        Value = "{{ FilterAndValidateInstances.TargetInstances }}"
        Type  = "StringList"
      },
      {
        Name  = "ManagedInstances"
        Value = "{{ FilterAndValidateInstances.ManagedTargetInstances }}"
        Type  = "StringList"
      },
      {
        Name  = "ExecutionStatus"
        Value = "{{ RemoveSSHKeyFromInstances.Status }}"
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