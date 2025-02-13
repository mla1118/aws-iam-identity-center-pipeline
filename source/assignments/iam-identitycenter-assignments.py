import boto3
import json
import os
import logging
import re
import argparse
import traceback
import subprocess
from botocore.config import Config

# Logging configuration
logging.basicConfig(format='%(asctime)s,%(msecs)03d %(levelname)-8s [%(filename)s:%(lineno)d] %(message)s',
    datefmt='%Y-%m-%d:%H:%M:%S',
    level=logging.INFO)
log = logging.getLogger()
log.setLevel(logging.INFO)

# Config to handle throttling
config = Config(
   retries = {
      'max_attempts': 1000,
      'mode': 'adaptive'
   }
)

# Setting arguments
parser = argparse.ArgumentParser(description='AWS SSO Permission Set Management')
parser.add_argument('--mgmt_account', action="store", dest='mgmtAccount')
args = parser.parse_args()

def get_current_permissionset_list():
    """Fetch all AWS SSO permission sets and return a mapping of Name -> ARN"""
    client = boto3.client('sso-admin', config=config)
    perm_set_dict = {}

    response = client.list_permission_sets(InstanceArn=ssoInstanceArn)
    results = response.get("PermissionSets", [])

    while "NextToken" in response:
        response = client.list_permission_sets(InstanceArn=ssoInstanceArn, NextToken=response["NextToken"])
        results.extend(response["PermissionSets"])

    for permission_set in results:
        response = client.describe_permission_set(InstanceArn=ssoInstanceArn, PermissionSetArn=permission_set)
        perm_set_dict[response["PermissionSet"]["Name"]] = permission_set

    return perm_set_dict

def sanitize_terraform_key(value):
    """Replace special characters to make Terraform-compatible keys."""
    return re.sub(r'[^a-zA-Z0-9_-]', '_', value)  # Replace invalid characters with underscores

def generate_import_commands(assignments):
    """Generate Terraform import commands only for new assignments (skip existing ones)."""
    commands = []
    existing_assignments = get_existing_assignments()

    for assignment in assignments:
        required_keys = ["Target", "PrincipalId", "PermissionSetName", "PrincipalType"]
        if not all(key in assignment for key in required_keys):
            log.warning(f"Skipping invalid assignment (missing fields): {assignment}")
            continue

        for target in assignment["Target"]:
            if ":" in target:
                target_id = target.split(":")[-1]  # Extract AWS Account ID
            else:
                log.warning(f"Skipping invalid Target format: {target}")
                continue

            # Convert permission set name to ARN
            ps_arn = getPermissionSetArn(assignment["PermissionSetName"])
            if not ps_arn:
                log.warning(f"Skipping assignment due to missing Permission Set ARN: {assignment['PermissionSetName']}")
                continue

            # Generate a Terraform-compatible index key
            assignment_key = f'{target_id}_{assignment["PrincipalId"]}_{assignment["PermissionSetName"]}'
            sanitized_key = sanitize_terraform_key(assignment_key)

            # Properly escape the key for Terraform import
            sid = f'"{sanitized_key}"'

            # Construct the resource ID
            resource_id = f'{ssoInstanceArn},{target_id},AWS_ACCOUNT,{ps_arn},{assignment["PrincipalType"]},{assignment["PrincipalId"]}'

            # Generate Terraform import command
            command = f'terraform import aws_ssoadmin_account_assignment.assignment[{sid}] {resource_id}'
            commands.append(command)

    return commands

def is_already_imported(sid):
    """Check if an assignment is already imported in Terraform state."""
    try:
        result = subprocess.run(
            f'terraform state list | grep -F "aws_ssoadmin_account_assignment.assignment[{sid}]"',
            shell=True,
            capture_output=True,
            text=True
        )
        return sid in result.stdout.strip()
    except Exception as error:
        log.error(f"Error checking Terraform state: {error}")
        return False

def run_imports(commands):
    """Run Terraform import commands only if they haven't been imported."""
    
    # Ensure Terraform is initialized before running imports
    log.info("Checking Terraform initialization...")
    init_result = subprocess.run("terraform init -input=false -reconfigure", shell=True, capture_output=True, text=True)
    if init_result.returncode != 0:
        log.error(f"Terraform initialization failed: {init_result.stderr}")
        exit(1)
    
    for command in commands:
        # Extract SID from the Terraform command format
        match = re.search(r'assignment\["(.+?)"\]', command)
        if not match:
            log.warning(f"Skipping malformed import command: {command}")
            continue
        
        sid = match.group(1)

        # Skip if already imported
        if is_already_imported(sid):
            log.info(f"Skipping already imported assignment: {sid}")
            continue

        # Execute Terraform import
        log.info(f"Executing Terraform import: {command}")
        import_result = subprocess.run(command, shell=True, capture_output=True, text=True)
        if import_result.returncode != 0:
            log.error(f"Terraform import failed: {import_result.stderr}")

    # Refresh Terraform state after imports
    log.info("Refreshing Terraform state after imports...")
    refresh_result = subprocess.run("terraform refresh", shell=True, capture_output=True, text=True)
    if refresh_result.returncode != 0:
        log.error(f"Terraform refresh failed: {refresh_result.stderr}")
        exit(1)

def main():
    print("#######################################")
    print("# Starting AWS SSO Assignments Script #")
    print("#######################################\n")

    global ssoInstanceArn
    global permissionSetsArn
    global identitystore
    global resolvedAssingmnets
    global managementAccount
    resolvedAssingmnets = {"Assignments": []}

    managementAccount = args.mgmtAccount

    # Get Identity Store and SSO Instance ARN
    sso_client = boto3.client('sso-admin', config=config)
    response = sso_client.list_instances()
    ssoInstanceArn = response['Instances'][0]['InstanceArn']
    identitystore = response['Instances'][0]['IdentityStoreId']
    
    permissionSetsArn = get_current_permissionset_list()

    repositoryAssignments = load_assignments_from_file()
    commands = generate_import_commands(repositoryAssignments["Assignments"])

    if commands:
        print("\nImporting existing SSO assignments into Terraform...\n")
        run_imports(commands)
        print("\nAll existing assignments have been imported into Terraform.")

    else:
        print("\nNo existing assignments found to import.")

    # Ensure Terraform is initialized before applying
    print("Initializing Terraform backend...")
    try:
        subprocess.run("terraform init -reconfigure", shell=True, check=True)
    except subprocess.CalledProcessError as e:
        log.error(f"Terraform initialization failed: {e}")
        return  # Stop execution if Terraform init fails

    # Apply Terraform changes after updating state
    print("Applying Terraform changes...")
    try:
        subprocess.run("terraform apply -auto-approve", shell=True, check=True)
        log.info('Terraform apply completed successfully.')
    except subprocess.CalledProcessError as e:
        log.error(f"Terraform apply failed: {e}")

if __name__ == "__main__":
    main()