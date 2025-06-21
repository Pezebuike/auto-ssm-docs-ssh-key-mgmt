# Enhanced SSM Automation Document for removing SSH keys with comprehensive debugging
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
              "log_info() { echo -e \"${GREEN}[INFO]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1\"; }",
              "log_warn() { echo -e \"${YELLOW}[WARN]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1\"; }",
              "log_error() { echo -e \"${RED}[ERROR]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1\"; }",
              "log_debug() { [[ \"$DEBUG_MODE\" == \"true\" ]] && echo -e \"${BLUE}[DEBUG]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1\" || true; }",
              "",
              "echo -e \"${GREEN}=== SSH Key Removal Started ===${NC}\"",
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
              "    echo -e \"${GREEN}=== SSH Key Removal Completed (Nothing to Remove) ===${NC}\"",
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
              "    echo -e \"${GREEN}=== SSH Key Removal Completed (Key Not Found) ===${NC}\"",
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
              "echo -e \"${GREEN}=== SSH Key Removal Completed Successfully ===${NC}\""
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

# Enhanced SSM Automation Document for adding SSH keys with comprehensive debugging
resource "aws_ssm_document" "add_ssh_key_automation" {
  name            = var.add_ssh_key_document_name
  document_type   = "Automation"
  document_format = "YAML"
  
  content = yamlencode({
    schemaVersion = "0.3"
    description   = "SSM Automation Document to add SSH public key to EC2 instances with debugging"
    assumeRole    = aws_iam_role.ssm_automation_execution_role.arn
    
    parameters = {
      InstanceIds = {
        type            = "StringList"
        description     = "Specific EC2 Instance IDs to add SSH key to (e.g., i-1234567890abcdef0)"
        allowedPattern  = "^i-[0-9a-f]{8,17}$"
        default         = []
      }
      TagKey = {
        type        = "String"
        description = "Tag key to filter instances (optional - use with TagValue)"
        default     = ""
      }
      TagValue = {
        type        = "String"
        description = "Tag value to filter instances (optional - use with TagKey)"
        default     = ""
      }
      InstanceNamePattern = {
        type        = "String"
        description = "Instance name pattern to filter (optional - uses Name tag)"
        default     = ""
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
    print("=== DEBUG: Input Parameters ===")
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
            CreateUser = "{{ CreateUser }}"
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
          },
          {
            Name     = "InstanceDetails"
            Selector = "$.Reservations[*].Instances[*]"
            Type     = "MapList"
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
          },
          {
            Name     = "ManagedInstanceDetails"
            Selector = "$.InstanceInformationList[*]"
            Type     = "MapList"
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
    print("=== DEBUG: Starting Instance Filtering and Validation ===")
    
    instance_ids = events.get('InstanceIds', [])
    tag_key = events.get('TagKey', '')
    tag_value = events.get('TagValue', '')
    name_pattern = events.get('InstanceNamePattern', '')
    all_instances = events.get('AllInstances', [])
    managed_instances = events.get('ManagedInstances', [])
    debug_mode = events.get('DebugMode', 'false')
    
    print(f"Input InstanceIds: {instance_ids}")
    print(f"All running instances: {len(all_instances)} found")
    print(f"SSM managed instances: {len(managed_instances)} found")
    print(f"Managed instance list: {managed_instances}")
    
    target_instances = []
    
    # If specific instance IDs provided, use them
    if instance_ids and len(instance_ids) > 0 and instance_ids[0] != '':
        print(f"Using specific instance IDs: {instance_ids}")
        target_instances = instance_ids
    else:
        print("No specific instance IDs provided, filtering by tags/name...")
        
        # Filter based on tags or name pattern
        ec2 = boto3.client('ec2')
        filters = [{'Name': 'instance-state-name', 'Values': ['running']}]
        
        if tag_key and tag_value:
            filters.append({'Name': f'tag:{tag_key}', 'Values': [tag_value]})
            print(f"Filtering by tag: {tag_key}={tag_value}")
        
        if name_pattern:
            filters.append({'Name': 'tag:Name', 'Values': [f'*{name_pattern}*']})
            print(f"Filtering by name pattern: {name_pattern}")
        
        try:
            response = ec2.describe_instances(Filters=filters)
            for reservation in response['Reservations']:
                for instance in reservation['Instances']:
                    target_instances.append(instance['InstanceId'])
            
            print(f"Filtered instances: {target_instances}")
            
            # If no filters specified, use all running instances
            if not target_instances and not tag_key and not tag_value and not name_pattern:
                target_instances = all_instances[:5]  # Limit to first 5 for safety
                print(f"No filters specified, using first 5 running instances: {target_instances}")
        
        except Exception as e:
            print(f"ERROR filtering instances: {str(e)}")
            return {
                'TargetInstances': [],
                'ManagedTargetInstances': [],
                'Error': f"Failed to filter instances: {str(e)}"
            }
    
    # Check which target instances are SSM-managed
    managed_target_instances = []
    unmanaged_instances = []
    
    for instance_id in target_instances:
        if instance_id in managed_instances:
            managed_target_instances.append(instance_id)
        else:
            unmanaged_instances.append(instance_id)
    
    print(f"Target instances that are SSM-managed: {managed_target_instances}")
    print(f"Target instances that are NOT SSM-managed: {unmanaged_instances}")
    
    # Detailed validation
    validation_results = []
    for instance_id in target_instances:
        result = {
            'InstanceId': instance_id,
            'IsRunning': instance_id in all_instances,
            'IsSSMManaged': instance_id in managed_instances,
            'CanExecuteCommands': instance_id in managed_instances and instance_id in all_instances
        }
        validation_results.append(result)
        print(f"Instance {instance_id}: Running={result['IsRunning']}, SSM-Managed={result['IsSSMManaged']}")
    
    return {
        'TargetInstances': target_instances,
        'ManagedTargetInstances': managed_target_instances,
        'UnmanagedInstances': unmanaged_instances,
        'ValidationResults': validation_results,
        'TotalTargets': len(target_instances),
        'TotalManaged': len(managed_target_instances),
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
            DebugMode = "{{ DebugMode }}"
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
              NextStep = "AddSSHKeyToInstances"
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
    print("=== ERROR: No SSM-Managed Instances Found ===")
    print("This automation requires instances to be managed by Systems Manager.")
    print("")
    print("To fix this issue:")
    print("1. Ensure instances have the SSM Agent installed")
    print("2. Attach the 'AmazonSSMManagedInstanceCore' IAM policy to your EC2 instances")
    print("3. Or use AWS Systems Manager Quick Setup to configure instances")
    print("")
    print("Target instances found but not SSM-managed:")
    
    unmanaged = events.get('UnmanagedInstances', [])
    for instance_id in unmanaged:
        print(f"  - {instance_id}")
    
    return {
        'Error': 'No SSM-managed instances available',
        'Solution': 'Configure instances with SSM Agent and proper IAM role'
    }
EOF
          InputPayload = {
            UnmanagedInstances = "{{ FilterAndValidateInstances.UnmanagedInstances }}"
          }
        }
        isEnd = true
      },
      {
        name   = "AddSSHKeyToInstances"
        action = "aws:runCommand"
        timeoutSeconds = 300  # Reduced timeout for faster failure detection
        inputs = {
          DocumentName = "AWS-RunShellScript"
          InstanceIds  = "{{ FilterAndValidateInstances.ManagedTargetInstances }}"
          Parameters = {
            commands = [
              "#!/bin/bash",
              "set -euo pipefail",
              "",
              "# Input parameters",
              "USERNAME='{{ Username }}'",
              "PUBLIC_KEY='{{ PublicKey }}'", 
              "CREATE_USER='{{ CreateUser }}'",
              "DEBUG_MODE='{{ DebugMode }}'",
              "",
              "# Colors for output",
              "RED='\\033[0;31m'",
              "GREEN='\\033[0;32m'",
              "YELLOW='\\033[1;33m'",
              "BLUE='\\033[0;34m'",
              "NC='\\033[0m'",
              "",
              "# Enhanced logging functions",
              "log_info() { echo -e \"$${GREEN}[INFO]$${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1\"; }",
              "log_warn() { echo -e \"$${YELLOW}[WARN]$${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1\"; }",
              "log_error() { echo -e \"$${RED}[ERROR]$${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1\"; }",
              "log_debug() { [[ \"$DEBUG_MODE\" == \"true\" ]] && echo -e \"$${BLUE}[DEBUG]$${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1\" || true; }",
              "",
              "echo -e \"$${GREEN}=== SSH Key Management Started ===$${NC}\"",
              "log_info \"Instance ID: $(curl -s http://169.254.169.254/latest/meta-data/instance-id 2>/dev/null || echo 'Unknown')\"",
              "log_info \"Instance Type: $(curl -s http://169.254.169.254/latest/meta-data/instance-type 2>/dev/null || echo 'Unknown')\"",
              "log_info \"Region: $(curl -s http://169.254.169.254/latest/meta-data/placement/region 2>/dev/null || echo 'Unknown')\"",
              "log_info \"Target Username: $USERNAME\"",
              "log_info \"Create User: $CREATE_USER\"",
              "log_info \"Debug Mode: $DEBUG_MODE\"",
              "",
              "# System information for debugging",
              "log_debug \"OS Information: $(cat /etc/os-release | head -2 || uname -a)\"",
              "log_debug \"Current user: $(whoami)\"",
              "log_debug \"User ID: $(id)\"",
              "log_debug \"Working directory: $(pwd)\"",
              "",
              "# Check sudo access with detailed logging",
              "if [[ $EUID -ne 0 ]]; then",
              "    log_debug \"Not running as root, checking sudo access...\"",
              "    if ! command -v sudo &> /dev/null; then",
              "        log_error \"Neither root access nor sudo available\"",
              "        log_error \"Current user: $(whoami), UID: $EUID\"",
              "        exit 1",
              "    fi",
              "    SUDO='sudo'",
              "    log_info \"Using sudo for privileged operations\"",
              "    log_debug \"Testing sudo access...\"",
              "    if ! sudo -n true 2>/dev/null; then",
              "        log_warn \"Sudo requires password or is not configured for passwordless access\"",
              "    fi",
              "else",
              "    SUDO=''",
              "    log_info \"Running as root\"",
              "fi",
              "",
              "# Validate SSH key format with detailed feedback",
              "log_debug \"Validating SSH key format...\"",
              "if [[ -z \"$PUBLIC_KEY\" ]]; then",
              "    log_error \"Public key is empty\"",
              "    exit 1",
              "fi",
              "",
              "KEY_TYPE=$(echo \"$PUBLIC_KEY\" | awk '{print $1}')",
              "log_debug \"Detected key type: $KEY_TYPE\"",
              "",
              "if ! echo \"$PUBLIC_KEY\" | grep -E '^ssh-(rsa|dss|ed25519|ecdsa)' &>/dev/null; then",
              "    log_error \"Invalid SSH key format. Expected format: ssh-rsa/ssh-ed25519/etc...\"",
              "    log_error \"Received key starts with: $(echo \"$PUBLIC_KEY\" | head -c 50)...\"",
              "    exit 1",
              "fi",
              "log_info \"SSH key format validated ($KEY_TYPE)\"",
              "",
              "# Check if user exists with detailed logging",
              "log_debug \"Checking if user '$USERNAME' exists...\"",
              "if ! id \"$USERNAME\" &>/dev/null; then",
              "    log_warn \"User $USERNAME does not exist\"",
              "    if [[ \"$CREATE_USER\" == \"true\" ]]; then",
              "        log_info \"Creating user: $USERNAME\"",
              "        log_debug \"Executing: $SUDO useradd -m -s /bin/bash $USERNAME\"",
              "        if $SUDO useradd -m -s /bin/bash \"$USERNAME\"; then",
              "            log_info \"User $USERNAME created successfully\"",
              "            # Verify user creation",
              "            if id \"$USERNAME\" &>/dev/null; then",
              "                log_debug \"User creation verified\"",
              "            else",
              "                log_error \"User creation failed - user still doesn't exist\"",
              "                exit 1",
              "            fi",
              "        else",
              "            log_error \"Failed to create user $USERNAME\"",
              "            log_debug \"useradd exit code: $?\"",
              "            exit 1",
              "        fi",
              "    else",
              "        log_error \"User $USERNAME does not exist and CREATE_USER is false\"",
              "        log_debug \"Available users: $(cut -d: -f1 /etc/passwd | tail -10)\"",
              "        exit 1",
              "    fi",
              "else",
              "    log_info \"User $USERNAME already exists\"",
              "    log_debug \"User info: $(id $USERNAME)\"",
              "fi",
              "",
              "# Get user home directory with validation",
              "log_debug \"Getting user home directory...\"",
              "USER_HOME=$(getent passwd \"$USERNAME\" | cut -d: -f6)",
              "if [[ -z \"$USER_HOME\" ]]; then",
              "    log_error \"Could not determine home directory for user $USERNAME\"",
              "    log_debug \"getent passwd output: $(getent passwd $USERNAME)\"",
              "    exit 1",
              "fi",
              "log_info \"User home directory: $USER_HOME\"",
              "",
              "# Validate home directory exists",
              "if [[ ! -d \"$USER_HOME\" ]]; then",
              "    log_warn \"Home directory $USER_HOME does not exist, creating...\"",
              "    $SUDO mkdir -p \"$USER_HOME\"",
              "    $SUDO chown \"$USERNAME:$USERNAME\" \"$USER_HOME\"",
              "fi",
              "",
              "# SSH directory setup with detailed logging",
              "SSH_DIR=\"$USER_HOME/.ssh\"",
              "AUTHORIZED_KEYS=\"$SSH_DIR/authorized_keys\"",
              "",
              "log_info \"Setting up SSH directory: $SSH_DIR\"",
              "log_debug \"Creating SSH directory if it doesn't exist...\"",
              "$SUDO mkdir -p \"$SSH_DIR\"",
              "",
              "log_debug \"Setting ownership and permissions on SSH directory...\"",
              "$SUDO chown \"$USERNAME:$USERNAME\" \"$SSH_DIR\"",
              "$SUDO chmod 700 \"$SSH_DIR\"",
              "",
              "# Verify SSH directory setup",
              "SSH_OWNER=$(stat -c '%U:%G' \"$SSH_DIR\")",
              "SSH_PERMS=$(stat -c '%a' \"$SSH_DIR\")",
              "log_debug \"SSH directory owner: $SSH_OWNER, permissions: $SSH_PERMS\"",
              "",
              "# Check if key already exists",
              "log_debug \"Checking if SSH key already exists...\"",
              "if [[ -f \"$AUTHORIZED_KEYS\" ]]; then",
              "    CURRENT_KEY_COUNT=$(wc -l < \"$AUTHORIZED_KEYS\")",
              "    log_debug \"Current authorized_keys file has $CURRENT_KEY_COUNT keys\"",
              "    ",
              "    if grep -Fxq \"$PUBLIC_KEY\" \"$AUTHORIZED_KEYS\"; then",
              "        log_warn \"SSH key already exists in authorized_keys\"",
              "        echo -e \"$${GREEN}=== SSH Key Management Completed (No Changes) ===$${NC}\"",
              "        exit 0",
              "    fi",
              "else",
              "    log_debug \"No existing authorized_keys file found\"",
              "    CURRENT_KEY_COUNT=0",
              "fi",
              "",
              "# Create backup if file exists",
              "if [[ -f \"$AUTHORIZED_KEYS\" ]]; then",
              "    BACKUP_FILE=\"$AUTHORIZED_KEYS.backup.$(date +%Y%m%d_%H%M%S)\"",
              "    log_debug \"Creating backup: $BACKUP_FILE\"",
              "    $SUDO cp \"$AUTHORIZED_KEYS\" \"$BACKUP_FILE\"",
              "    log_info \"Backup created: $BACKUP_FILE\"",
              "fi",
              "",
              "# Add the public key",
              "log_info \"Adding SSH public key to authorized_keys\"",
              "log_debug \"Appending key to $AUTHORIZED_KEYS\"",
              "echo \"$PUBLIC_KEY\" | $SUDO tee -a \"$AUTHORIZED_KEYS\" > /dev/null",
              "",
              "# Set proper ownership and permissions",
              "log_debug \"Setting ownership and permissions on authorized_keys...\"",
              "$SUDO chown \"$USERNAME:$USERNAME\" \"$AUTHORIZED_KEYS\"",
              "$SUDO chmod 600 \"$AUTHORIZED_KEYS\"",
              "",
              "# Verify the addition",
              "NEW_KEY_COUNT=$(wc -l < \"$AUTHORIZED_KEYS\")",
              "AUTH_OWNER=$(stat -c '%U:%G' \"$AUTHORIZED_KEYS\")",
              "AUTH_PERMS=$(stat -c '%a' \"$AUTHORIZED_KEYS\")",
              "",
              "log_info \"SSH key added successfully\"",
              "log_info \"Keys before: $CURRENT_KEY_COUNT, Keys after: $NEW_KEY_COUNT\"",
              "log_debug \"authorized_keys owner: $AUTH_OWNER, permissions: $AUTH_PERMS\"",
              "",
              "# Final verification",
              "log_debug \"Performing final verification...\"",
              "if [[ \"$SSH_PERMS\" == \"700\" ]] && [[ \"$AUTH_PERMS\" == \"600\" ]]; then",
              "    log_info \"Permissions verified: SSH directory (700), authorized_keys (600)\"",
              "else",
              "    log_error \"Permission verification failed\"",
              "    log_error \"SSH directory permissions: $SSH_PERMS (expected: 700)\"",
              "    log_error \"authorized_keys permissions: $AUTH_PERMS (expected: 600)\"",
              "    exit 1",
              "fi",
              "",
              "# Test key format in file",
              "if grep -q \"ssh-\" \"$AUTHORIZED_KEYS\"; then",
              "    log_debug \"SSH key format verification passed\"",
              "else",
              "    log_warn \"SSH key format verification failed\"",
              "fi",
              "",
              "echo -e \"$${GREEN}=== SSH Key Management Completed Successfully ===$${NC}\"",
              "log_info \"Summary: Added SSH key for user $USERNAME\"",
              "log_info \"Total keys in authorized_keys: $NEW_KEY_COUNT\"",
              "log_info \"Key type: $KEY_TYPE\""
            ]
            workingDirectory  = "/tmp"
            executionTimeout  = "180"  # Reduced from 3600
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
        Value = "{{ AddSSHKeyToInstances.Status }}"
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