import os
import json
import logging
import pprint
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

client = boto3.client('iam')

unused_days = os.environ.get('DAYS_UNUSED', 90)

def list_roles():
    """
    :return: Roles which have not been used in last 90 days.
    """
    
    try:
        roles = client.list_roles()
        logger.info("Total %s roles.", len(roles))
        ununsed_roles = []
        
        for role in roles.get('Roles'):
            if not role.get('Path').startswith('/aws-service-role'):
                lastUsed = get_last_used(role.get('RoleName'))
                daysFromLastUsed = days_between(role.get('CreateDate'), lastUsed)
                if daysFromLastUsed >= int(unused_days):
                    ununsed_roles.append(role.get('RoleName'))
    except ClientError:
        logger.exception("Couldn't list roles")
        raise
    else:
        print(str(ununsed_roles)[1:-1]) 
        return ununsed_roles


def get_last_used(role_name):
    try:
        role = client.get_role(RoleName=role_name)
        
        if role.get('Role').get('RoleLastUsed') is not None:
            return role.get('Role').get('RoleLastUsed').get('LastUsedDate')
        else:
            return None
    except ClientError:
        logger.exception("Couldn't list roles")
        raise
     

def days_between(created, lastUsed):
    today = datetime.now(timezone.utc)
    if lastUsed: 
        daysFromLastUsed =  (today - lastUsed).days
    else:
        daysFromLastUsed =  (today - created).days
    return daysFromLastUsed

def delete_role(role_name):
    """
    Deletes a role.

    :param role_name: The name of the role to delete.
    """
    try:
        client.delete_role(
                RoleName=role_name
                )
        logger.info("Deleted role %s.", role_name)
    except ClientError:
        logger.exception("Couldn't delete role %s.", role_name)
        raise


def remove_instanceprofile_role(role_name):
    """
    Detaches a policy from a role.

    :param role_name: The name of the role. **Note** this is the name, not the ARN.
    :param policy_arn: The ARN of the policy.
    """
    try:
        instance_profiles = get_instanceprofile_role(role_name)
        for ip in [ip for ip in (instance_profiles or [])]:
            client.remove_role_from_instance_profile(
                        InstanceProfileName=ip.get('InstanceProfileName'),
                        RoleName=role_name
            )
            logger.info("Deleted instance profile %s from role %s.", ip.get('InstanceProfileName'), role_name)
    except ClientError:
        logger.exception(
            "Couldn't get instance policy from role %s.", role_name)
        raise

def get_instanceprofile_role(role_name):
    """
    Detaches a policy from a role.

    :param role_name: The name of the role. **Note** this is the name, not the ARN.
    :param policy_arn: The ARN of the policy.
    """
    try:
        instance_profile = client.list_instance_profiles_for_role(RoleName=role_name)
        print(instance_profile)
    except ClientError:
        logger.exception("Couldn't list instance policies from role %s.", role_name)
        raise
    else:
        return instance_profile.get('InstanceProfiles')

def detach_policy(role_name):
    """
    Detaches a policy from a role.

    :param role_name: The name of the role. **Note** this is the name, not the ARN.
    :param policy_arn: The ARN of the policy.
    """
    try:
        policies = get_policy(role_name)
        
        for p in [p for p in (policies or [])]:
            print(p.get('PolicyArn'))
            #detach = client.detach_role_policy(RoleName=role_name,
                #PolicyArn=p.get('PolicyArn'))
            logger.info("Detached policy %s from role %s.", p.get('PolicyArn'), role_name)
    except ClientError:
        logger.exception(
            "Couldn't detach policies from role %s.", role_name)
        raise


def get_policy(role_name):
    """
    Detaches a policy from a role.

    :param role_name: The name of the role. **Note** this is the name, not the ARN.
    :param policy_arn: The ARN of the policy.
    """
    try:
        role_policies = client.list_attached_role_policies(RoleName=role_name)
        
    except ClientError:
        logger.exception(
            "Couldn't list attached policies from role %s.", role_name)
        raise
    else:
        return role_policies.get('AttachedPolicies')


def delete_role_policy(role_name):
    """
    Detaches a policy from a role.

    :param role_name: The name of the role. **Note** this is the name, not the ARN.
    :param policy_arn: The ARN of the policy.
    """
    try:
        role_policies = get_role_policy(role_name)
        
        for rp in [rp for rp in (role_policies or [])]:
            
            client.delete_role_policy(RoleName=role_name,
                PolicyName=rp)
            logger.info("Detached policy %s from role %s.", rp, role_name)
    except ClientError:
        logger.exception(
            "Couldn't detach policies from role %s.", role_name)
        raise


def get_role_policy(role_name):
    """
    Detaches a policy from a role.

    :param role_name: The name of the role. **Note** this is the name, not the ARN.
    :param policy_arn: The ARN of the policy.
    """
    try:
        role_policies = client.list_role_policies(RoleName=role_name)
        
    except ClientError:
        logger.exception(
            "Couldn't list policies from role %s.", role_name)
        raise
    else:
        return role_policies.get('PolicyNames')


def demo(event=None, context=None):
    """Shows how to use the role functions."""
    logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
    print('-'*80)
    print("AWS Identity and Account Management role cleanup.")
    print('-'*80)
    role = list_roles()
    print("Roles which have not been used: ", len(role))
    for r in [r for r in (role or [])]:
        #remove-role-from-instance-profile
        remove_instanceprofile_role(r)
        #detach-role-policy
        detach_policy(r)
        #delete-role-policy
        delete_role_policy(r)
        
        delete_role(r)
        print("Deleted ", r)

    print("Thanks for using!")


#if __name__ == '__main__':
#   demo()