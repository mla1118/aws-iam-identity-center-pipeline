# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.

# Permission is hereby granted, free of charge, to any person obtaining a copy of this
# software and associated documentation files (the "Software"), to deal in the Software
# without restriction, including without limitation the rights to use, copy, modify,
# merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
# INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
# PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

## + -----------------------
## | AWS SSO Assignments Managemnet
## +-----------------------------------

import boto3
import json
import os
import logging
from botocore.config import Config
import re
import argparse
import traceback
import subprocess

# Logging configuration
logging.basicConfig(format='%(asctime)s,%(msecs)03d %(levelname)-8s [%(filename)s:%(lineno)d] %(message)s',
    datefmt='%Y-%m-%d:%H:%M:%S',
    level=logging.DEBUG)
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
    client = boto3.client('sso-admin', config=config)
    perm_set_dict = {}

    response = client.list_permission_sets(InstanceArn=ssoInstanceArn)

    results = response["PermissionSets"]
    while "NextToken" in response:
        response = client.list_permission_sets(InstanceArn=ssoInstanceArn, NextToken=response["NextToken"]) 
        results.extend(response["PermissionSets"])

    for permission_set in results:
        response = client.list_tags_for_resource(InstanceArn=ssoInstanceArn,ResourceArn=permission_set)
        for eachTag in response['Tags']:
            if (eachTag['Key'] in 'SSOPipeline'):
                perm_description = client.describe_permission_set(InstanceArn=ssoInstanceArn,PermissionSetArn=permission_set)
                perm_set_dict[perm_description["PermissionSet"]["Name"]] = permission_set
    
    return perm_set_dict

def load_assignments_from_file():
    assigments_file = os.listdir('../../templates/assignments/')
    assig_dic = {}
    assignments_list = []
    

    for eachFile in assigments_file:
        path = '../../templates/assignments/'+eachFile
        f = open(path)
        data = json.load(f)
        assignments_list.extend(data['Assignments'])
        f.close()
    assig_dic['Assignments'] = assignments_list
    log.info('Assignments successfully loaded from repository files')
    return assig_dic



def list_all_accounts():
    client = boto3.client('organizations')

    response = client.list_accounts()
    results = response["Accounts"]
    while "NextToken" in response:
        response = client.list_accounts(NextToken=response["NextToken"]) 
        results.extend(response["Accounts"])

    accounts = []
    for eachAccount in results:
        if eachAccount['Status'] == 'ACTIVE':
            accounts.append(eachAccount['Id'])
    
    return accounts

def list_active_accounts_in_ou_not_nested(ou_id):
    client = boto3.client('organizations')

    def get_active_accounts_in_ou(ou_id):
        active_accounts = []
        paginator = client.get_paginator('list_accounts_for_parent')
        
        for page in paginator.paginate(ParentId=ou_id):
            for account in page['Accounts']:
                if account['Status'] == 'ACTIVE':
                    active_accounts.append(account['Id'])
        
        return active_accounts
    
    return get_active_accounts_in_ou(ou_id)

def list_accounts_in_ou_nested(ou_id):
    client = boto3.client('organizations')
    def get_accounts_in_ou(ou_id):
        accounts = []
        paginator = client.get_paginator('list_accounts_for_parent')
        
        for page in paginator.paginate(ParentId=ou_id):
            for account in page['Accounts']:
                if account["Status"] == "ACTIVE":
                    accounts.append(account['Id'])
        
        return accounts
    
    def get_nested_ous(ou_id):
        ous = []
        paginator = client.get_paginator('list_organizational_units_for_parent')
        
        for page in paginator.paginate(ParentId=ou_id):
            for ou in page['OrganizationalUnits']:
                ous.append(ou['Id'])
        
        return ous
    
    def list_all_accounts_recursive(ou_id):
        all_accounts = get_accounts_in_ou(ou_id)
        nested_ous = get_nested_ous(ou_id)
        
        for nested_ou_id in nested_ous:
            all_accounts.extend(list_all_accounts_recursive(nested_ou_id))
        
        return all_accounts

    return list_all_accounts_recursive(ou_id)

def list_accounts_in_ou(ouid):
    client = boto3.client('organizations', config=config)
    root_id = client.list_roots()['Roots'][0]['Id']
    
    try:
        account_list = []
        if 'ou-' in ouid:
            if ':*' in ouid:
                log.info(f"[OU: {ouid}] Nested association found (:*). Listing accounts inside nested OUs.")
                account_list = list_accounts_in_ou_nested(str(ouid.split(":")[0]))
            else:
                account_list = list_active_accounts_in_ou_not_nested(ouid)
        elif root_id in ouid or 'ROOT' in ouid.upper():
            account_list = list_all_accounts()      
        else:
            log.error('Target is not in valid format.')
            exit (1)
                
    except Exception as error:
        log.error('It was not possible to list accounts from Organization Unit. Reason: ' + str(error))
        log.error(traceback.format_exc())
        exit (1)
    return account_list

def lookup_principal_id(principalName, principalType):
    try:
        client = boto3.client('identitystore', config=config)
        if principalType == 'GROUP':
            response = client.list_groups(
                IdentityStoreId=identitystore,
                Filters=[
                    {
                        'AttributePath': 'DisplayName',
                        'AttributeValue': principalName
                    },
                ]
            )
            groupId = getGroupId(principalName)
            return groupId
        if principalType == 'USER':
            response = client.list_users(
                IdentityStoreId=identitystore,
                Filters=[
                    {
                        'AttributePath': 'UserName',
                        'AttributeValue': principalName
                    },
                ]
            )
            return response['Users'][0]['UserId']
    except Exception as error:
        log.error(f"[PR: {principalName}] [{principalType}]  It was not possible lookup target. Reason: " + str(error))
        log.error(traceback.format_exc())

def resolve_targets(eachCurrentAssignments):
    try:
        account_list = []
        log.info(f"[SID: {eachCurrentAssignments['SID']}] Resolving target in accounts")
        for eachTarget in eachCurrentAssignments['Target']:
            pattern = re.compile(r'\d{12}') # Regex for AWS Account Id
            if pattern.match(eachTarget.split(":")[1]):
                account_list.append(eachTarget.split(":")[1])
            else:
                account_list.extend(list_accounts_in_ou(eachTarget.split(":", 1)[1]))                
        return account_list
    except Exception as error:
        log.error(f"[SID: {eachCurrentAssignments['SID']}] It was not possible to resolve the targets from assignment. Reason: " + str(error))
        log.error(traceback.format_exc())

def getGroupId(group_name):
    '''
    Retrieves the ID of given group

    Arguments:
    - group_name -> name of group to find

    Returns:
    - ID of group found, None if no group found
    '''
    identity_store_client = boto3.client('identitystore')
    group_id = None
    paginator = identity_store_client.get_paginator('list_groups')
    page_iterator = paginator.paginate(IdentityStoreId=identitystore)

    for page in page_iterator:
        for group in page['Groups']:
            if group['DisplayName'] == group_name:
                group_id = group['GroupId']
                break
    
    return group_id

def create_assignment_file(repositoryAssignments):
    log.info('Creating assignment file')
    
    try:
        for assignment in repositoryAssignments['Assignments']:
            accounts = resolve_targets(assignment)
            principalId = getGroupId(assignment['PrincipalId'])
            if principalId is None:
                description = f"Allows users access to {accounts} with {assignment['PermissionSetName']} permissions"
                principalId = createGroup(assignment['PrincipalId'], description)

            
            for eachAccount in accounts:
                if eachAccount != managementAccount:
                    ps_arn = getPermissionSetArn(assignment['PermissionSetName'])
                    resolvedAssingmnets['Assignments'].append(
                        {
                            "Sid": str(eachAccount)+str(assignment['PrincipalId'])+str(assignment['PrincipalType'])+str(assignment['PermissionSetName']),
                            "PrincipalId": principalId,
                            "PrincipalType": assignment['PrincipalType'],
                            "PermissionSetName": ps_arn,
                            "Target": eachAccount
                        }
                    )                
        return True
    except Exception as error:
        log.error("Error: " + str(error))
        log.error(traceback.format_exc())
        exit (1)

def getPermissionSetName(permission_set_arn):
    '''
    This function gets the permission set name
    Arguments:
    permission_set_arn - ARN (Amazon Resource Name) of permission set name to find

    Returns:
    - permission set name
    '''
    sso_admin_client = boto3.client('sso-admin', config=config)
    # get all info on the given permission set
    response = sso_admin_client.describe_permission_set(InstanceArn=ssoInstanceArn, PermissionSetArn=permission_set_arn)
    # return only the name from the recieved response
    return response['PermissionSet']['Name']


def getPermissionSetArn(permission_set_name):
    '''
    This function gets the permission set ARN 
    Arguments:
    permission_set_name - name of permission set to find

    Returns:
    - permission set ARN

    If permission set is not found, then this function will print "<>
    '''
    # get list of all permission sets
    permission_set_arns = listPermissionSets()
    # be tranparent with user
    print(f"Looking for the ARN for {permission_set_name}...")
    # loop through permission set list 
    for arn in permission_set_arns:
        # get the name of the current permission set in list
        ps_name = getPermissionSetName(arn)
        # check if this is the permission set to find
        if ps_name == permission_set_name:
            # if so, print the ARN to the console for user
            print(f"{permission_set_name} ARN: {arn}")
            # return the found ARN
            return arn
    # if permission set name given is not found in the list, tell user
    print(f"{permission_set_name} not found")
    return False

def sanitize_terraform_key(value):
    """Replace special characters to make Terraform-compatible keys."""
    return re.sub(r'[^a-zA-Z0-9_-]', '_', value)  # Replace invalid characters with underscores

def createGroup(group_name, group_description):
    '''
    Creates a new group in Identity Center

    Arguments:
    - group_name -> name for the new group to create
    - permission_set_name -> permission set to be attached to the group
    - group_description -> description for group (DEFAULT: None)

    Returns:
    - group_id -> ID of group created
    '''
    identity_store_client = boto3.client('identitystore', config=config)
    # if no group description given, create default:  "Allows users access to <accountName> with <permissionSet> permissions"
    print(f"Creating group {group_name}...")
    # create group
    response = identity_store_client.create_group(IdentityStoreId=identitystore, DisplayName=group_name, Description=group_description)

    return response['GroupId']

def get_existing_assignments():
    """Fetch all existing SSO assignments."""
    sso_admin_client = boto3.client('sso-admin', config=config)
    assignments = []
    
    # Get all permission sets
    permission_sets = sso_admin_client.list_permission_sets(InstanceArn=ssoInstanceArn)["PermissionSets"]

    for ps_arn in permission_sets:
        # Get all AWS account assignments for this permission set
        accounts = sso_admin_client.list_accounts_for_provisioned_permission_set(
            InstanceArn=ssoInstanceArn, PermissionSetArn=ps_arn
        ).get("AccountIds", [])

        for account in accounts:
            response = sso_admin_client.list_account_assignments(
                InstanceArn=ssoInstanceArn, AccountId=account, PermissionSetArn=ps_arn
            )

            for assignment in response["AccountAssignments"]:
                assignments.append({
                    "InstanceArn": ssoInstanceArn,
                    "TargetId": account,
                    "TargetType": "AWS_ACCOUNT",
                    "PermissionSetArn": ps_arn,
                    "PrincipalType": assignment["PrincipalType"],
                    "PrincipalId": assignment["PrincipalId"],
                })
    
    return assignments

def generate_import_commands(assignments):
    """Generate Terraform import commands for existing assignments."""
    commands = []
    
    for assignment in assignments:
        # Ensure the Terraform key is safe and wrapped in double quotes
        sid = f'"{sanitize_terraform_key(f"{assignment["TargetId"]}-{assignment["PrincipalId"]}-{assignment["PermissionSetArn"]}")}"'
        
        resource_id = f'{assignment["InstanceArn"]},{assignment["TargetId"]},{assignment["TargetType"]},{assignment["PermissionSetArn"]},{assignment["PrincipalType"]},{assignment["PrincipalId"]}'
        command = f'terraform import aws_ssoadmin_account_assignment.assignment[{sid}] {resource_id}'
        commands.append(command)

    return commands

def is_already_imported(sid):
    """Check if an assignment is already imported in Terraform."""
    result = subprocess.run(
        f"terraform state list | grep aws_ssoadmin_account_assignment.assignment[\"{sid}\"]",
        shell=True,
        capture_output=True,
        text=True
    )
    return sid in result.stdout

def run_imports(commands):
    """Run Terraform import commands only if they haven't been imported."""
    for command in commands:
        sid = command.split('assignment["')[1].split('"]')[0]  # Extract the assignment SID
        if is_already_imported(sid):
            print(f"Skipping already imported assignment: {sid}")
            continue
        print(f"Executing: {command}")
        subprocess.run(command, shell=True)
  

# gets a list of all permission sets ARNs
def listPermissionSets():
    """
    Retrieves a list of all permission set ARNs used in all AWS accounts in the organization

    """
    sso_admin_client = boto3.client('sso-admin', config=config)
    paginator = sso_admin_client.get_paginator('list_permission_sets')
    permission_sets = (ps for page in paginator.paginate(InstanceArn=ssoInstanceArn)
                    for ps in page['PermissionSets'])

    return permission_sets

def main():
    print("#######################################")
    print("# Starting AWS SSO Assignments Script #")
    print("#######################################\n")
    
    # Put arguments in a global variable to be used latter on in the code
    global ssoInstanceArn
    global permissionSetsArn
    global identitystore
    global resolvedAssingmnets
    global managementAccount
    resolvedAssingmnets = {}
    resolvedAssingmnets['Assignments'] = []

    managementAccount = args.mgmtAccount

    # Get Identity Store and SSO Instance ARN
    sso_client = boto3.client('sso-admin', config=config)
    response = sso_client.list_instances()
    ssoInstanceArn = response['Instances'][0]['InstanceArn']
    identitystore = response['Instances'][0]['IdentityStoreId']
    
    permissionSetsArn = get_current_permissionset_list()

    repositoryAssignments = load_assignments_from_file()
    existing_assignments = get_existing_assignments()
    commands = generate_import_commands(existing_assignments)

    if commands:
        print("\nImporting existing SSO assignments into Terraform...\n")
        run_imports(commands)
        print("\nAll existing assignments have been imported into Terraform.")
    else:
        print("\nNo existing assignments found to import.")
    
    create_assignment_file(repositoryAssignments) 

    seen = []
    for eachSID in resolvedAssingmnets['Assignments']:
        if eachSID not in seen:
            seen.append(eachSID)

    with open('assignments.json', 'w') as convert_file:
        convert_file.write(json.dumps(seen))
    
    log.info('Association file created.')
main()