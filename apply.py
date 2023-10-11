#!/usr/bin/python3

#===============================================================================
#=================================== L I B S ===================================
#===============================================================================

import re
import yaml
import boto3
import dateutil.parser

#===============================================================================
#====================== G L O B A L   V A R I A B L E S ========================
#===============================================================================

# Global variables
__version__ = "1.0"


################################################################################
######## U P D A T E   T H E S E   V A R I A B L E S   I F   N E E D E D #######
################################################################################
INSTANCE_ARN="arn:aws:sso:::instance/XXXXXXXXXXXXX" # to set only once

PERMISSION_SETS_CONFIG_FILE="./permission_sets.yml"

DEFAULT_SESSION_DURATION="PT03H0M0S"
################################################################################
################################################################################

MAX_RESULTS_FROM_AWS_API=100


ERRORS = {
    "permission_set_config_file_var": {
        # Error codes range: [100, 109]
        "undefined_or_empty": {
            "msg": "PERMISSION_SETS_CONFIG_FILE global variable must not be empty or undefined.",
            "code": 100 },

        "file_not_found": {
            "msg": "Permission Sets configuration file not found.",
            "code": 101
        }
    },

    "permission_set_management": {
        # Error codes range: [110, 119]
        "unable_to_retrieve_from_response": {
            "msg": "Unable to retrieve ARN of newly created permission set or after its update.",
            "code": 110
        }
    }
}


#===============================================================================
#===================== G E N E R I C   F U N C T I O N S =======================
#===============================================================================

def exit_error(error: dict,
               custom_msg: str = None) -> None:
    """
    Print an error and exit with a specific exit code.

    Parameters:
        error (dict): the error details to raise.
        custom_msg (str, default=None): a custom message to print with the default one.

    Returns:
        None.
    """
    if custom_msg: print(f"Error! {error['msg']} {custom_msg}")
    else: print(f"Error! {error['msg']}")
    print(f"Exiting. (RC={error['code']})")
    exit(error["code"])

#---------------------------------------

def load_permission_set_config_file(file_path: str) -> dict:
    """
    Load a YAML dictionary from a file.

    Parameters:
        file_path (str): the path to the YAML file.

    Returns:
        dict: the dictionary loaded from the file.
    """
    # Check if the provided path is correct
    if not file_path: exit_error(error=ERRORS["permission_set_config_file_var"]["undefined_or_empty"])

    # Check if the file exists and is in YAML format
    try:
        with open(file=file_path, mode='r') as f:
            config = yaml.load(stream=f, Loader=yaml.loader.SafeLoader)
    except FileNotFoundError:
        exit_error(error=ERRORS["permission_set_config_file_var"]["file_not_found"],
                   custom_msg=f"File path: {file_path}")
    
    return config

#---------------------------------------

def convert_time_to_iso_8601(time_to_convert: str) -> str:
    """
    Convert a time to ISO 8601.
    This format is mandatory when updating the permission set's session duration.

    Parameters:
        time_to_convert (str): the time to first convert with dateutil lib.

    Returns:
        str: the same time in ISO 8601 format.
    """
    session_duration_range = {"min": {
                                  "seconds": 3600,
                                  "iso_8601": "PT1H0M0S"},
                              "max": {
                                  "seconds": 43200,
                                  "iso_8601": "PT12H0M0S"}
                             }
    default_message = f"Default session duration will be used instead: {DEFAULT_SESSION_DURATION}."

    if time_to_convert  is None:
       print(f"Null value provided for session duration. {default_message}")
       
    elif type(time_to_convert) != str:
       print(f"Provided value for session duration is not of type 'string'. {default_message}")
       
    elif time_to_convert == "":
       print(f"No value provided for session duration. {default_message}")

    else:
        # Convert time to seconds if needed
        parsed_time = dateutil.parser.parse(timestr=time_to_convert)
        parsed_time_seconds = (parsed_time.hour * 60 * 60) + (parsed_time.minute * 60) + parsed_time.second

        # Check range
        if parsed_time_seconds < session_duration_range["min"]["seconds"]:
            print(f"Provided value for session duration ({parsed_time.strftime('%Hh%Mm%Ss')}) is lesser than minimum: {session_duration_range['min']['iso_8601'][2:]}. "
                  "Using it instead.")
            return session_duration_range["min"]["iso_8601"]
        
        elif parsed_time_seconds > session_duration_range["max"]["seconds"]:
            print(f"Provided value for session duration ({parsed_time.strftime('%Hh%Mm%Ss')}) is greater than maximum: {session_duration_range['max']['iso_8601'][2:]}. "
                  "Using it instead.")
            return session_duration_range["max"]['iso_8601']
        
        else:
            # Removing leading zeros if any
            parsed_time_processed = re.sub(pattern="([THM]{1})[0]{1}([0-9]{1})",
                                           repl="\\1\\2",
                                           string=parsed_time.strftime('PT%HH%MM%SS'))
            
            # Removing single zeros if any
            for i in range(3):
                parsed_time_processed = re.sub(pattern="([THM]{1})([0]{1}[HMS]{1})", repl="\\1", string=parsed_time_processed)
            return parsed_time_processed

    return DEFAULT_SESSION_DURATION

#===============================================================================
#================================= C L A S S E S ===============================
#===============================================================================

class AWSClient():
    """
    This class contains all variables and functions to interact with AWS Services.
    
    Official Boto3 documentaion:
      https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sso-admin.html
    """

    def __init__(self) -> None:
        # Initializing AWS clients
        self.__client_iam = boto3.client("iam")
        self.__client_sso = boto3.client("sso-admin")

        # Retrieving all AWS Managed policies
        self.__aws_managed_policies = {}
        print("Gathering all existing AWS managed IAM policies...")
        response = self.__client_iam.list_policies(Scope="AWS",
                                                   OnlyAttached=False,
                                                   PolicyUsageFilter="PermissionsPolicy",
                                                   MaxItems=MAX_RESULTS_FROM_AWS_API)
        for policy in response['Policies']:
                    self.__aws_managed_policies[policy['Arn']] = policy['PolicyName']
        while "Marker" in response.keys():
                response = self.__client_iam.list_policies(Scope="AWS",
                                                           OnlyAttached=False,
                                                           Marker=response['Marker'],
                                                           PolicyUsageFilter="PermissionsPolicy",
                                                           MaxItems=MAX_RESULTS_FROM_AWS_API)
                for policy in response['Policies']:
                    self.__aws_managed_policies[policy['Arn']] = policy['PolicyName']


    
    #---------------------------------------

    def check_aws_managed_policy_exists(self,
                                        policy_name: str) -> str:
        """
        Check if an AWS managed policy exists from a name.

        Official documentation:
            https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam/client/list_policies.html

        Parameters:
            policy_name (str): the policy's name.

        Returns:
          str: policy's ARN if it exists, empty string otherwise
        """
        if policy_name:
            if policy_name in self.__aws_managed_policies.values():
                for key, value in self.__aws_managed_policies.items():
                    if value == policy_name: return key
            else: return ""
        else:
            raise ValueError("No policy name was passed.")
        
    #---------------------------------------
        
    def describe_permission_set(self,
                                permission_set_arn: str) -> dict:
        """
        This function will list ARNs of all existing Permission Sets.

        Official documentation:
            https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sso-admin/client/describe_permission_set.html
        
        Parameters:
            permission_set_arn (str): the permission set's ARN.

        Returns:
            dict: the permission set's details from the AWS API.
        """
        try:
            if permission_set_arn:
                permission_set_details = self.__client_sso.describe_permission_set(InstanceArn=INSTANCE_ARN,
                                                                                   PermissionSetArn=permission_set_arn)
                return permission_set_details["PermissionSet"]
            
        except self.__client_sso.exceptions.ResourceNotFoundException:
            print(f"Permission set [{permission_set_arn}] does not seem to exist. Considering its details as empty.")
            return {"PermissionSet": {
                "Name": "",
                "PermissionSetArn": permission_set_arn,
                "Description": "",
                "SessionDuration": DEFAULT_SESSION_DURATION,
                "RelayState": ""
            }}

    #---------------------------------------

    def list_permission_sets(self) -> list:
        """
        This function will list ARNs of all existing Permission Sets.
        
        Parameters:
            None.

        Returns:
            list: a list containing all existing permission sets.
        """
        permission_sets = self.__client_sso.list_permission_sets(InstanceArn=INSTANCE_ARN,
                                                                 MaxResults=MAX_RESULTS_FROM_AWS_API)
        try:
            return permission_sets["PermissionSets"]
        except KeyError:
            return []
        
    #---------------------------------------

    def create_permission_set(self,
                              permission_set_name: str,
                              permission_set: dict) -> str:
        """
        Create a Permisssion Set if it does not exist.
        Note: it will be created WITHOUT its policies.

        Official documentation:
            https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sso-admin/client/create_permission_set.html

        Parameters:
            permission_set_name (str): the name of the permission set.
            permission_set (dict): the dictionary containing all details about the permission set to create.

        Returns:
            str: permission set's ARN if it was successfully created. An empty string if the permission set already exists.

        """
        try:
            # Mandatory args
            args = {"InstanceArn": INSTANCE_ARN,
                    "Name": permission_set_name}
            # Optional args
            for key, value in permission_set.items():
                if   key == "description":      args["Description"] = value
                elif key == "relay_state":      args["RelayState"] = value
                elif key == "session_duration": args["SessionDuration"] = convert_time_to_iso_8601(value)
                elif key == "tags":             args["Tags"] = [{"Key": list(tag.keys())[0],
                                                                 "Value": list(tag.values())[0]}
                                                                for tag in permission_set["tags"] or []]
            print(f"Creating permission set [{permission_set_name}]... ", end="")
            response = self.__client_sso.create_permission_set(**args)
            print("Done!")
            permission_set["arn"] = response["PermissionSet"]["PermissionSetArn"]

            # Creating policies
            self.update_permission_set_policies(permission_set_name=permission_set_name,
                                                permission_set=permission_set,
                                                apply=True,
                                                new_permission_set=True)

            # Creating tags
            if "tags" in list(permission_set.keys()):
                permission_set_tags_changes = { "creation": permission_set["tags"], "update": [], "deletion": [] }
            else: permission_set_tags_changes = { "creation": [], "update": [], "deletion": [] }

            if len(permission_set_tags_changes) > 0: self.__update_resource_tags(resource_arn=permission_set["arn"],
                                                                                 resource_tags_changes=permission_set_tags_changes)


            # Return ARN
            try:
                return permission_set["arn"]
            except KeyError:
                exit_error(error=ERRORS["permission_set_management"]["unable_to_retrieve_arn_after_creation"],
                           custom_msg=f"Permission set: {permission_set_name}")
            
        # When the permission set already exists (by its name)
        except self.__client_sso.exceptions.ConflictException:
            print(f"Permission set [{permission_set_name}] seems to exist already. Skipping.")
            return ""
        
    #---------------------------------------

    def list_permission_set_aws_managed_policies(self,
                                                 permission_set_arn: str) -> dict:
        """
        List AWS managed policies of a specific permission set.

        Official documentation:
            https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sso-admin/client/list_managed_policies_in_permission_set.html

        Parameters:
            permission_set_arn (str, default=""): the permission set's ARN.

        Returns:
            dict: the response from the AWS API regarding update of permission set's policies.
        """
        if permission_set_arn:
            return self.__client_sso.list_managed_policies_in_permission_set(InstanceArn=INSTANCE_ARN,
                                                                             PermissionSetArn= permission_set_arn,
                                                                             MaxResults=MAX_RESULTS_FROM_AWS_API)
        else:
            raise ValueError("Permission set's ARN should not be empty or null. Exiting.")

    #---------------------------------------

    def provision_permission_set(self,
                                 permission_set_arn: str,
                                 account_id: str = "") -> dict:
        """
        Provision a permission on a single AWS account, or all of them.
        This means an updated permission set will be loaded by AWS accounts where is already provisioned.

        Official documentation:
            https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sso-admin/client/provision_permission_set.html

        Parameters:
            permission_set_arn (str): the permission set's ARN.
            account_id (str, default=""): the account ID to provision the permission set. If empty, all AWS accounts will be provisioned.

        Returns:
            dict: the response from the AWS API.
        """
        if permission_set_arn:
            args = {"InstanceArn":INSTANCE_ARN,
                    "PermissionSetArn": permission_set_arn}

            # Single account provisioning
            if account_id:
                args["TargetType"], args["TargetId"] = "AWS_ACCOUNT", account_id
                msg = f"AWS account {account_id}"

            # All accounts provisioning
            else:
                args["TargetType"] = "ALL_PROVISIONED_ACCOUNTS"
                msg = "all currently provisioned AWS accounts"

            print(f"Provisioning permission set [{permission_set_arn}] on {msg}... ", end="")
            self.__client_sso.provision_permission_set(**args)
            print("Done!")

        else:
            raise ValueError("Permission set's ARN should not be empty or null. Exiting.")

    #---------------------------------------

    def list_permission_set_customer_managed_policies(self,
                                                      permission_set_arn: str) -> dict:
        """
        List customer managed policies of a specific permission set.

        Official documentation:
            https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sso-admin/client/list_customer_managed_policy_references_in_permission_set.html

        Parameters:
            permission_set_arn (str, default=""): the permission set's ARN.

        Returns:
            dict: the response from the AWS API regarding update of permission set's policies.
        """
        if permission_set_arn:
            customer_managed_policies = self.__client_sso.list_customer_managed_policy_references_in_permission_set(InstanceArn=INSTANCE_ARN,
                                                                                                                    PermissionSetArn= permission_set_arn,
                                                                                                                    MaxResults=MAX_RESULTS_FROM_AWS_API)
            for policy in customer_managed_policies["CustomerManagedPolicyReferences"]:
                if "Path" in policy.keys(): policy["Name"] = policy["Path"] + policy["Name"]
                else:                       policy["Name"] = "/" + policy["Name"]
            return customer_managed_policies["CustomerManagedPolicyReferences"]
        else:
            raise ValueError("Permission set's ARN should not be empty or null. Exiting.")
        
    #---------------------------------------

    def attach_aws_managed_policy_to_permission_set(self,
                                                permission_set_arn: str = "",
                                                aws_managed_policy_arn: str = "",
                                                aws_managed_policy_name: str = "",
                                                apply: bool = False) -> dict:
        """
        Attach an AWS manage policy to a permission set.

        Official documentation:
            https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sso-admin/client/attach_managed_policy_to_permission_set.html

        Parameters:
            permission_set_arn (str, default=""): the permission set's ARN.
            aws_managed_policy_arn (str, default=""): the AWS managed policy's ARN to attach. If unspecified, the function will try to retrieve it from the policy's name.
            aws_managed_policy_name (str, default=""): the AWS managed policy's name to attach.
            apply (bool, default=""): wheteher to apply the change or not.

        Returns:
            dict: the response from the AWS API regarding update of permission set's policies.
        """
        # Check also if the ARN exists
        if not aws_managed_policy_arn and aws_managed_policy_name:
            aws_managed_policy_arn = self.check_aws_managed_policy_exists(policy_name=aws_managed_policy_name)
            if not aws_managed_policy_arn:
                print(f"AWS Managed policy '{aws_managed_policy_name}' does not exist. Skipping.")
                return None
        
        if permission_set_arn and aws_managed_policy_arn:
            if apply:
                print(f"Attaching AWS managed policy [{aws_managed_policy_arn}] to permission set [{permission_set_arn}]... ", end="")
                resp = self.__client_sso.attach_managed_policy_to_permission_set(InstanceArn=INSTANCE_ARN,
                                                                                 PermissionSetArn= permission_set_arn,
                                                                                 ManagedPolicyArn=aws_managed_policy_arn)
                print("Done!")
                return resp
        else:
            raise ValueError("Permission set's ARN and the AWS managed policy's ARN should not be empty or null. Exiting.")
        
    #---------------------------------------

    def attach_customer_managed_policy_to_permission_set(self,
                                                         permission_set_arn: str = "",
                                                         customer_managed_policy_name: str = "",
                                                         apply: bool = False) -> dict:
        """
        Attach a customer managed policy to a permission set.

        Official documentation:
            https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sso-admin/client/attach_customer_managed_policy_reference_to_permission_set.html

        Parameters:
            permission_set_arn (str, default=""): the permission set's ARN.
            customer_managed_policy_name (str, default=""): the customer managed policy's name to attach.
            apply (bool, default=""): wheteher to apply the change or not.

        Returns:
            dict: the response from the AWS API regarding update of permission set's policies.
        """
        if permission_set_arn and customer_managed_policy_name:
            if apply:
                customer_managed_policy_name_splitted = customer_managed_policy_name.split('/')
                if len(customer_managed_policy_name_splitted) == 1:
                    policy_name = customer_managed_policy_name_splitted[0]
                    policy_path = "/"
                else:
                    policy_name = customer_managed_policy_name_splitted[-1]
                    policy_path = "/".join(customer_managed_policy_name_splitted[:-1]) + "/"
                    if policy_path.startswith("//"): policy_path = policy_path[1:]
                print(f"Attaching customer managed policy [{customer_managed_policy_name}] to permission set [{permission_set_arn}]... ", end="")
                resp = self.__client_sso.attach_customer_managed_policy_reference_to_permission_set(InstanceArn=INSTANCE_ARN,
                                                                                                    PermissionSetArn= permission_set_arn,
                                                                                                    CustomerManagedPolicyReference={
                                                                                                        "Name": policy_name,
                                                                                                        "Path": policy_path
                                                                                                    })
                print("Done!")
                return resp
        else:
            raise ValueError("Permission set's ARN should not be empty or null. Exiting.")

    #---------------------------------------

    def detach_aws_managed_policy_to_permission_set(self,
                                                    permission_set_arn: str = "",
                                                    aws_managed_policy_arn: str = "",
                                                    aws_managed_policy_name: str = "",
                                                    apply: bool = False) -> dict:
        """
        Detach an AWS managed policy from a permission set.

        Official documentation:
            https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sso-admin/client/detach_managed_policy_from_permission_set.html

        Parameters:
            permission_set_arn (str, default=""): the permission set's ARN.
            aws_managed_policy_arn (str, default=""): the AWS managed policy's ARN to detach. If unspecified, the function will try to retrieve it from the policy's name.
            aws_managed_policy_name (str, default=""): the AWS managed policy's name to detach.
            apply (bool, default=""): wheteher to apply the change or not.

        Returns:
            dict: the response from the AWS API regarding update of permission set's policies.
        """
        # Check also if the ARN exists
        if not aws_managed_policy_arn and aws_managed_policy_name:
            aws_managed_policy_arn = self.check_aws_managed_policy_exists(policy_name=aws_managed_policy_name)
            if not aws_managed_policy_arn:
                print(f"AWS Managed policy '{aws_managed_policy_name}' does not exist. Skipping.")
                return None
        
        if permission_set_arn and aws_managed_policy_arn:
            if apply:
                print(f"Detaching AWS managed policy [{aws_managed_policy_arn}] to permission set [{permission_set_arn}]... ", end="")
                resp = self.__client_sso.detach_managed_policy_from_permission_set(InstanceArn=INSTANCE_ARN,
                                                                                   PermissionSetArn= permission_set_arn,
                                                                                   ManagedPolicyArn=aws_managed_policy_arn)
                print("Done!")
                return resp
        else:
            raise ValueError("Permission set's ARN and the AWS managed policy's ARN should not be empty or null. Exiting.")
        
    #---------------------------------------

    def detach_customer_managed_policy_to_permission_set(self,
                                                         permission_set_arn: str = "",
                                                         customer_managed_policy_name: str = "",
                                                         apply: bool = False) -> dict:
        """
        Detach a customer managed policy from a permission set.

        Official documentation:
            https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sso-admin/client/detach_customer_managed_policy_reference_from_permission_set.html

        Parameters:
            permission_set_arn (str, default=""): the permission set's ARN.
            customer_managed_policy_name (str, default=""): the customer managed policy's name to detach.
            apply (bool, default=""): wheteher to apply the change or not.

        Returns:
            dict: the response from the AWS API regarding update of permission set's policies.
        """
        if permission_set_arn and customer_managed_policy_name:
            if apply:
                customer_managed_policy_name_splitted = customer_managed_policy_name.split('/')
                if len(customer_managed_policy_name_splitted) == 1:
                    policy_name = customer_managed_policy_name_splitted[0]
                    policy_path = "/"
                else:
                    policy_name = customer_managed_policy_name_splitted[-1]
                    policy_path = "/".join(customer_managed_policy_name_splitted[:-1]) + "/"
                    if policy_path.startswith("//"): policy_path = policy_path[1:]
                print(f"Detaching customer managed policy [{customer_managed_policy_name}] to permission set [{permission_set_arn}]... ", end="")
                resp = self.__client_sso.detach_customer_managed_policy_reference_from_permission_set(InstanceArn=INSTANCE_ARN,
                                                                                                      PermissionSetArn= permission_set_arn,
                                                                                                      CustomerManagedPolicyReference={
                                                                                                          "Name": policy_name,
                                                                                                          "Path": policy_path
                                                                                                      })
                return resp
        else:
            raise ValueError("Permission set's ARN should not be empty or null. Exiting.")

    #---------------------------------------

    def update_permission_set_policies(self,
                                       permission_set_name: str,
                                       permission_set: dict,
                                       apply: bool = False,
                                       new_permission_set: bool = False) -> bool:
        """
        Update an existing permisssion set's policies.
        Note: only AWS managed and customer managed policies are currently supported.

        Official documentation:
            ###https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sso-admin/client/get_permissions_boundary_for_permission_set.html
            ###https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sso-admin/client/put_permissions_boundary_to_permission_set.html
            ###https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sso-admin/client/delete_permissions_boundary_from_permission_set.html

        Parameters:
            permission_set_name (str): the name of the permission set to update. Only used for logging errors.
            permission_set (dict): the permission set dictionary defined in the configuration file.
            apply (bool): whether to apply the changes or not.

        Returns:
          True if the permission set's policies was successfully updated.
          False otherwise.
        """
        try:
            # List existing policies
            try:
                if new_permission_set:
                    existing_policies = { "aws_managed": [], "customer_managed": [] }
                else:
                    existing_policies_tmp = {
                        "aws_managed": self.list_permission_set_aws_managed_policies(permission_set_arn=permission_set["arn"])["AttachedManagedPolicies"],
                        "customer_managed": self.list_permission_set_customer_managed_policies(permission_set_arn=permission_set["arn"])
                    }
                    existing_policies = {}
                    for poltype in existing_policies_tmp:
                        if len(existing_policies_tmp[poltype]) != 0: existing_policies[poltype] = [p['Name'] for p in existing_policies_tmp[poltype]]
                        else:                                        existing_policies[poltype] = []
            except KeyError:
                print(f"An error occured when trying to retrieve existing policies. Skipping.")
                return False

            # Setting empty list for non-defined policy types
            if not "policies" in permission_set.keys(): permission_set["policies"] = {}
            if not "aws_managed" in permission_set["policies"].keys():          permission_set["policies"]["aws_managed"] = []
            if not "customer_managed" in permission_set["policies"].keys():     permission_set["policies"]["customer_managed"] = []
            if not "permissions_boundary" in permission_set["policies"].keys(): permission_set["policies"]["permissions_boundary"] = []

            permission_set_changes_count = 0
            for policy_type, policies in permission_set["policies"].items():
                if policy_type == "aws_managed":
                    for policy in policies:
                        if policy not in existing_policies[policy_type]:
                            if policy.startswith("arn:aws:iam::"):
                                self.attach_aws_managed_policy_to_permission_set(permission_set_arn=permission_set["arn"],
                                                                                 aws_managed_policy_arn=policy,
                                                                                 apply=apply)
                                permission_set_changes_count += 1
                            else:
                                self.attach_aws_managed_policy_to_permission_set(permission_set_arn=permission_set["arn"],
                                                                                 aws_managed_policy_name=policy,
                                                                                 apply=apply)
                                permission_set_changes_count += 1
                        else: 
                            existing_policies[policy_type].remove(policy)
                    for existing_policy in existing_policies[policy_type]:
                        if policy.startswith("arn:aws:iam::"):
                            self.detach_aws_managed_policy_to_permission_set(permission_set_arn=permission_set["arn"],
                                                                             aws_managed_policy_arn=existing_policy,
                                                                             apply=apply)
                            permission_set_changes_count += 1
                        else:
                            self.detach_aws_managed_policy_to_permission_set(permission_set_arn=permission_set["arn"],
                                                                             aws_managed_policy_name=existing_policy,
                                                                             apply=apply)
                            permission_set_changes_count += 1

                elif policy_type == "customer_managed":
                    for policy in policies:
                        if policy not in existing_policies[policy_type]:
                            self.attach_customer_managed_policy_to_permission_set(permission_set_arn=permission_set["arn"],
                                                                                  customer_managed_policy_name=policy,
                                                                                  apply=apply)
                            permission_set_changes_count += 1
                        else:
                            existing_policies[policy_type].remove(policy)

                    for existing_policy in existing_policies[policy_type]:
                        self.detach_customer_managed_policy_to_permission_set(permission_set_arn=permission_set["arn"],
                                                                              customer_managed_policy_name=existing_policy,
                                                                              apply=apply)
                        permission_set_changes_count += 1
                        
            # Provisioning all AWS accounts with the newly updated permission set
            if apply and permission_set_changes_count > 0:
                self.provision_permission_set(permission_set_arn=permission_set["arn"])

            return True
            
        # When the permission set does not exist (by its ARN)
        except self.__client_sso.exceptions.ResourceNotFoundException:
            print(f"Permission set [{permission_set_name}] does not seem to exist. Skipping.")
            return False

    #---------------------------------------

    def __create_update_resource_tags(self,
                                      resource_arn: str,
                                      tags: list) -> dict:
        """
        Create or update tags of a SSO resource.

        Official documentation:
            https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sso-admin/client/tag_resource.html

        Parameters:
            resource_arn (str): the SSO resource's ARN.
            tags (list): the list of tags to create or update.

        Returns:
            dict: the response from the AWS API regarding update of permission set's policies.
        """
        if resource_arn:
            print(f"Creating/Updating tags for resource [{resource_arn}]... ", end="")
            resp = self.__client_sso.tag_resource(InstanceArn=INSTANCE_ARN,
                                                  ResourceArn=resource_arn,
                                                  Tags=tags)
            print("Done!")
            return resp
        else:
            raise ValueError(f"Resource ARN [{resource_arn}] does not seem to exist. Skipping.")
        
    #---------------------------------------

    def __delete_resource_tags(self,
                              resource_arn: str,
                              tags: list) -> dict:
        """
        Delete tags from a SSO resource.

        Official documentation:
            https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sso-admin/client/untag_resource.html

        Parameters:
            resource_arn (str): the SSO resource's ARN.
            tags (list): the list of tags to remove.

        Returns:
            dict: the response from the AWS API regarding update of permission set's policies.
        """
        if resource_arn:
            print(f"Deleting tags for resource [{resource_arn}]... ", end="")
            resp = self.__client_sso.untag_resource(InstanceArn=INSTANCE_ARN,
                                                    ResourceArn=resource_arn,
                                                    TagKeys=tags)
            print("Done!")
            return resp
        else:
            raise ValueError(f"Resource ARN [{resource_arn}] does not seem to exist. Skipping.")

    #---------------------------------------

    def __update_resource_tags(self,
                               resource_arn: str,
                               resource_tags_changes: dict) -> None:
        """
        Create, update or delete tags of a SSO resource.

        Parameters:
            resource_arn (str): the SSO resource's ARN to update.

        Returns:
            None.
        """
        # Formatting tags
        for action_type in resource_tags_changes:
            if action_type == "deletion":
                resource_tags_changes[action_type] = [list(t.keys())[0] for t in resource_tags_changes[action_type]]
            else:
                resource_tags_changes[action_type] = [{"Key": list(t.keys())[0], "Value": list(t.values())[0]}
                                                      for t in resource_tags_changes[action_type]]
        tags = resource_tags_changes["creation"] + resource_tags_changes["update"]

        # Create/Update tags
        if len(tags) != 0:
            self.__create_update_resource_tags(resource_arn=resource_arn,
                                               tags=tags)

        # Delete tags
        if len(resource_tags_changes['deletion']) != 0:
            self.__delete_resource_tags(resource_arn=resource_arn,
                                        tags=resource_tags_changes['deletion'])

        return

    #---------------------------------------

    def update_permission_set(self,
                              permission_set_name: str,
                              permission_set: dict,
                              permission_set_tags_changes: dict,
                              apply: bool = False) -> dict:
        """
        Update an existing permisssion set including its details, tags and policies.

        Official documentation:
            https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sso-admin/client/update_permission_set.html

        Parameters:
            permission_set_name (str): the name of the permission set.
            permission_set (dict): the permission set's details (info, policies...) from the configuration file.
            permission_set_tags_changes (dict): the changes of the permission set's tags, whether to create, update or delete them.
            apply (bool, default=False): whether to apply the changes or not.

        Returns:
            dict: the response from the AWS API regarding update of permission set's policies.
            None if an error occured.
        """
        # Update details
        try:
            # Mandatory args
            try:
                args = {"InstanceArn": INSTANCE_ARN,
                        "PermissionSetArn": permission_set["arn"]}
            except KeyError:
                print(f"Permission set [{permission_set_name}] does not have its ARN defined in its configuration "
                       "(are you sure it exists?). Skipping.")
                return None

            # Optional args
            for key, value in permission_set.items():
                if   key == "description":      args["Description"] = value
                elif key == "relay_state":      args["RelayState"] = value
                elif key == "session_duration": args["SessionDuration"] = convert_time_to_iso_8601(value)

            # Update the permission set's details
            if apply:
                existing_permission_set = self.describe_permission_set(permission_set_arn=permission_set['arn'])
                for key, value in args.items():
                    if key in ["Description", "RelayState", "SessionDuration"] and \
                       value != existing_permission_set[key]:
                        print(f"Updating details of permission set [{permission_set['arn']}]... ", end="")
                        self.__client_sso.update_permission_set(**args)
                        print("Done!")
                        break # all fields listed above will be updated

            # Update the permission set's tags
            for v in permission_set_tags_changes.values():
                if len(v) > 0 and apply: self.__update_resource_tags(resource_arn=permission_set["arn"],
                                                                     resource_tags_changes=permission_set_tags_changes)
            
            # Update policies
            return self.update_permission_set_policies(permission_set_name=permission_set_name,
                                                       permission_set=permission_set,
                                                       apply=apply)

        # When the permission set does not exist (by its ARN)
        except self.__client_sso.exceptions.ResourceNotFoundException:
            print(f"Permission set [{permission_set_name}] does not seem to exist. Skipping.")
            return None

    #---------------------------------------

    def delete_permission_set(self,
                              permission_set_arn: str) -> dict:
        """
        Delete a permission set.

        Official documentation:
            https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sso-admin/client/delete_permission_set.html

        Parameters:
            permission_set_arn (str): the ARN of the permission set to delete.

        Returns:
            dict: a dictionary containing the response of the AWS API.
        """
        if permission_set_arn:
            print(f"Deleting permission set [{permission_set_arn}]... ", end="")
            resp = self.__client_sso.delete_permission_set(InstanceArn=INSTANCE_ARN,
                                                           PermissionSetArn= permission_set_arn)
            print("Done!")
            return resp
        else:
            raise ValueError("Permission set's ARN should not be empty or null. Exiting.")
        

    #---------------------------------------

    def get_sso_resource_tags(self,
                              resource_arn: str) -> list:
        """
        Get tags of any SSO resource.

        Official documentation:
            https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sso-admin/client/list_tags_for_resource.html

        Parameters:
            resource_arn (str): the ARN of the SSO resource to retrieve the tags from.

        Returns:
            list: the SSO resource's tags list.
        """
        if resource_arn:
            return self.__client_sso.list_tags_for_resource(InstanceArn=INSTANCE_ARN,
                                                            ResourceArn= resource_arn)
        else:
            raise ValueError("Permission set's ARN should not be empty or null. Exiting.")


#---------------------------------------

class Main():
    """
    The default class constructor.
    """
    def __init__(self) -> None:
        self.__permisson_sets_config = load_permission_set_config_file(PERMISSION_SETS_CONFIG_FILE)
        self.__aws_client = AWSClient()

    #---------------------------------------

    def __dump_permission_set_config_to_file(self,
                                             file_path: str) -> None:
        """
        Dump permission set configuration to file it initialy read from.
        This task is only called when a new permission set is created and its ARN is saved there.

        Parameters:
            file_path (str): the file's path to dump the new configuration to.

        Returns:
            None.
        """
        # Check if the provided path is correct
        if not file_path: exit_error(error=ERRORS["permission_set_config_file_var"]["undefined_or_empty"])

        # Check if the file exists and is in YAML format
        try:
            # Writting updated configuration
            with open(file=file_path, mode='w') as f:
                yaml.dump(data=self.__permisson_sets_config,
                          stream=f)
                          #Dumper=yaml.CDumper)
                
            # Format file for better understanding
            with open(file=file_path, mode='r') as f:
                lines = f.readlines()
            with open(file=file_path, mode='w') as f:
                for l in lines:
                    if not re.match(pattern=r"  [a-zA-Z0-9].+", string=l) is None:
                        f.write("\n  #===============================================\n\n")
                    f.write(l)
        except FileNotFoundError:
            exit_error(error=ERRORS["permission_set_config_file_var"]["file_not_found"],
                       custom_msg=f"File path: {file_path}")

    #---------------------------------------

    def __check_for_perm_set_policies_creation_deletion(self,
                                                        policies: list,
                                                        existing_policies: list) -> dict:
        """
        Check the differences between existing policies and those described in the configuration file.
        Note: only AWS managed and Customer managed policies are currently supported.

        Parameters:
            policies (list): a list of policies to add/update/delete from the configuration file.
            existing_policies (list): a list of policies currently defined for the permission set.

        Returns:
            dict: a dictionary containing permission set's policies to add or remove.
        """
        permission_set_policies = {
            "creation": [],
            "deletion": []
        }

        # Creating
        for policy in policies:
            if policy not in existing_policies:
                permission_set_policies["creation"].append(policy)
        # Deleting
        for existing_policy in existing_policies:
            if existing_policy not in policies:
                permission_set_policies["deletion"].append(existing_policy)
        return permission_set_policies

    #---------------------------------------

    def __check_tags_diff(self,
                          config_tags: list,
                          existing_tags: list) -> dict:
        """
        Check the differences between existing tags and those described in the configuration file.

        Parameters:
            config_tags (list): a list of tags to add/update/delete from the configuration file.
            existing_tags (list): a list of tags currently defined for the permission set.

        Returns:
            dict: a dictionary containing permission set's tags to create, update or delete.
        """
        permission_set_tags = {
            "creation": [],  # list of tag dicts
            "update": [],    # list of tag dicts
            "deletion": []   # list of tag dicts
        }

        for config_tag in config_tags:
            # Tags to update
            if list(config_tag.keys())[0] in [list(t.keys())[0] for t in existing_tags] and \
               not list(config_tag.values())[0] in [list(t.values())[0] for t in existing_tags]:
                permission_set_tags["update"].append(config_tag)

                # Removing tag from deletion list
                for tag in existing_tags:
                    if list(tag.keys())[0] == list(config_tag.keys())[0]:
                        existing_tags.remove({list(tag.keys())[0]: list(tag.values())[0]})

            # Tags to create
            elif not config_tag in existing_tags: permission_set_tags["creation"].append(config_tag)

            # Tags to delete
            else: existing_tags.remove(config_tag)

        permission_set_tags["deletion"] = existing_tags[:]

        return permission_set_tags

    #---------------------------------------

    def __check_permission_set_diff(self,
                                    config_permission_set: dict) :
        """
        Check permission set's details and policies differences between existing ones and those described in the configuration file.

        Parameters:
            config_permission_set (dict): the dictionary defined in the configuration file.
        
        Returns:
            list, dict: a list of differences to print to the user and a dictionary containing tags changes to perform.
        """
        changelogs = []

        # Describe existing permission set
        existing_permission_set = self.__aws_client.describe_permission_set(permission_set_arn=config_permission_set["arn"])
        for field in ["Description", "SessionDuration", "RelayState"]:
            if field not in existing_permission_set.keys(): existing_permission_set[field] = ""


        # List existing permission set's policies
        try:
            existing_policies = {
                "aws_managed": self.__aws_client.list_permission_set_aws_managed_policies(permission_set_arn=config_permission_set["arn"])["AttachedManagedPolicies"],
                "customer_managed": self.__aws_client.list_permission_set_customer_managed_policies(permission_set_arn=config_permission_set["arn"])
            }
            for poltype in existing_policies:
                if len(existing_policies[poltype]) != 0: existing_policies[poltype] = [p['Name'] for p in existing_policies[poltype]]
        except KeyError:
            print(f"An error occured when trying to retrieve existing policies. Skipping.")
            return False
        
        
        # Get permission set's tags
        if not "tags" in config_permission_set.keys(): config_permission_set["tags"] = []
        try:
            existing_permission_set["Tags"] = self.__aws_client.get_sso_resource_tags(resource_arn=existing_permission_set['PermissionSetArn'])["Tags"]
            existing_permission_set["Tags"] = [{t["Key"]: t["Value"]} for t in existing_permission_set["Tags"]]
        except KeyError: existing_permission_set["Tags"] = []


        # Compare
        for field, value in config_permission_set.items():
            # Compare current configuration and exisiting permission set details
            if (field == "description" and value and value != existing_permission_set["Description"]):
                changelogs.append(f"     ~ Description:              '{existing_permission_set['Description']}' -> '{value}'")
            elif field == "session_duration" and convert_time_to_iso_8601(value) != existing_permission_set["SessionDuration"]:
                changelogs.append(f"     ~ Session Duration:         '{existing_permission_set['SessionDuration']}' -> '{convert_time_to_iso_8601(value)}'")
            elif field == "relay_state" and value != existing_permission_set["RelayState"]:
                changelogs.append(f"     ~ Relay State:              '{existing_permission_set['RelayState']}' -> '{value}'")

            # Compare current configuration and existing permission set policies
            elif field == "policies":
                # Setting empty list for non-defined policy types
                if not "aws_managed" in value.keys(): value["aws_managed"] = []
                if not "customer_managed" in value.keys(): value["customer_managed"] = []
                if not "permissions_boundary" in value.keys(): value["permissions_boundary"] = []

                for policy_type, policies in value.items():
                    if policy_type == "aws_managed":
                        # Check if the speficied policies really exist
                        sorted_policies = policies[:]
                        for policy in policies:
                            if not self.__aws_client.check_aws_managed_policy_exists(policy_name=policy):
                                sorted_policies.remove(policy)

                        # Retrieve changes
                        policy_changes = self.__check_for_perm_set_policies_creation_deletion(policies=sorted_policies,
                                                                                              existing_policies=existing_policies[policy_type])
                        for policy_change in policy_changes["creation"]:
                            changelogs.append(f"     + AWS Managed policy:       '{policy_change}'")
                        for policy_change in policy_changes["deletion"]:
                            changelogs.append(f"     - AWS Managed policy:       '{policy_change}'")

                    elif policy_type == "customer_managed":
                        # Check if the default path is specified
                        policy_changes = self.__check_for_perm_set_policies_creation_deletion(policies=policies,
                                                                                              existing_policies=existing_policies[policy_type])
                        for policy_change in policy_changes["creation"]:
                            changelogs.append(f"     + Customer Managed policy:  '{policy_change}'")
                        for policy_change in policy_changes["deletion"]:
                            changelogs.append(f"     - Customer Managed policy:  '{policy_change}'")

            # Compare current configuration and existing permission set tags
            elif field == "tags":
                permission_set_tags_changes = self.__check_tags_diff(config_tags=value,
                                                                     existing_tags=existing_permission_set['Tags'])
                if sum([len(l) for l in permission_set_tags_changes.values()]) != 0:
                    changelogs.append(f"     ~ Tags:")
                    for tag in permission_set_tags_changes["creation"]:
                        changelogs.append(f"       + '{list(tag.keys())[0]}': '{list(tag.values())[0]}'")
                    for tag in permission_set_tags_changes["update"]:
                        changelogs.append(f"       ~ '{list(tag.keys())[0]}': '{list(tag.values())[0]}'")
                    for tag in permission_set_tags_changes["deletion"]:
                        changelogs.append(f"       - '{list(tag.keys())[0]}': '{list(tag.values())[0]}'")

        return changelogs, permission_set_tags_changes

    #---------------------------------------

    def __apply_config(self,
                       apply: bool = False) -> bool:
        """
        Check and apply configuration file submitted by the user.

        Parameters:
            apply (bool): whethere to apply the configuration or not.

        Returns:
            bool: True if it is possible to apply the configuration file, False otherwise.
        """
        # List permission set ARNs
        existing_permission_set_arns = self.__aws_client.list_permission_sets()

        # Check if each permission set's ARN is in this list.
        changelogs, warninglogs  = [], []
        config_permission_set_arns = []

        # Check for permission set creation/update
        if not apply:
            print("Checking for any permission set change...")
        for permission_set_name, permission_set_details in self.__permisson_sets_config["permission_sets"].items():
            # Adding leading '/' for customer managed policies
            if "policies" in permission_set_details.keys() and "customer_managed" in permission_set_details["policies"].keys():
                tmplist = []
                for p in permission_set_details["policies"]["customer_managed"]:
                    if not p.startswith('/'): tmplist.append('/' + p)
                    else:                     tmplist.append(p)
                permission_set_details["policies"]["customer_managed"] = tmplist[:]


            # ARN is not defined
            if not "arn" in permission_set_details.keys() or \
               permission_set_details["arn"] == "(know after apply)":
                # Create permission set
                changelogs.append(f"  + {permission_set_name}")

                if apply:
                    permission_set_arn = self.__aws_client.create_permission_set(permission_set_name=permission_set_name,
                                                                                 permission_set=permission_set_details)
                    # Save its ARN in the configuration file
                    if permission_set_arn:
                        permission_set_details["arn"] = permission_set_arn
                        self.__dump_permission_set_config_to_file(file_path=PERMISSION_SETS_CONFIG_FILE)
                else:
                    permission_set_details["arn"] = "(know after apply)"
                    
            
            # ARN is defined and at least one permission set in config has the same ARN
            if permission_set_details["arn"] in config_permission_set_arns and \
               permission_set_details["arn"] != "(know after apply)":
                warninglogs.append(f"Permission set [{permission_set_name}]'s ARN is already assigned to "
                                   "another permission set in configuration file. Skipping.")
            
            # ARN is defined and in list, update the permission set
            elif permission_set_details["arn"] in existing_permission_set_arns and \
                 permission_set_details["arn"] != "(know after apply)":
                tmp_changelogs, permission_set_tags_changes = self.__check_permission_set_diff(config_permission_set=permission_set_details)
                if len(tmp_changelogs) != 0:
                    changelogs.append(f"  ~ {permission_set_name}")
                    changelogs += tmp_changelogs[:]
                self.__aws_client.update_permission_set(permission_set_name=permission_set_name,
                                                        permission_set=permission_set_details,
                                                        permission_set_tags_changes=permission_set_tags_changes,
                                                        apply=apply)
            # ARN is defined and not in list, print a warning and skip
            else:
                # This condition is only accessed when apply=False
                if permission_set_details["arn"] == "(know after apply)":
                    changelogs.append(f"    + ARN:                      {permission_set_details['arn']}")
                    for field, value in permission_set_details.items():
                        if (field == "description"):      changelogs.append(f"    + Description:              '{value}'")
                        elif field == "session_duration": changelogs.append(f"    + Session Duration:         '{convert_time_to_iso_8601(value)}'")
                        elif field == "relay_state":      changelogs.append(f"    + Relay State:              '{value}'")
                else: 
                    warninglogs.append(f"You should either remove the ARN field for permission set [{permission_set_name}] "
                                       "or ensure it was not modified. Skipping")

            # Add permission set ARN into list for processing later
            config_permission_set_arns.append(permission_set_details["arn"])

        
        # Check for permission set removal
        for existing_permission_set_arn in existing_permission_set_arns:
            try:
                if existing_permission_set_arn not in config_permission_set_arns:
                    permission_set_details = self.__aws_client.describe_permission_set(permission_set_arn=existing_permission_set_arn)
                    changelogs.append(f"  - {permission_set_details['Name']}")
                    changelogs.append(f"    - ARN:                      '{permission_set_details['PermissionSetArn']}'")
                    for key, value in permission_set_details.items():
                        if key == "Description":       changelogs.append(f"    - Description:              '{value}'")
                        elif key == "SessionDuration": changelogs.append(f"    - Session Duration:         '{value}'")
                        elif key == "RelayState":      changelogs.append(f"    - Relay State:              '{value}'")
                    if apply:
                        self.__aws_client.delete_permission_set(permission_set_arn=permission_set_details['PermissionSetArn'])
            except KeyError:
                print(f"An unexpected error occured when trying to delete permission set {permission_set_details['Name']} ({existing_permission_set_arn}). Skipping")


        # Print warnings if any and changelogs
        if not apply:
            for warning in warninglogs:
                print(f"\nWARNING: {warning}")

            if len(changelogs) == 0:
                print("\nNothing to do!")
                return False

            else:
                print("\n*** Changelogs:")
                for change in changelogs:
                    print(change)
                return True
            
        else:
            return True


    #---------------------------------------

    def run(self) -> None:
        """
        Main function to be run by this class.

        Parameters:
            None.

        Returns:
            None.
        """
        try:
            # Print changelog
            is_there_changes_to_perform = self.__apply_config(apply=False)
            if not is_there_changes_to_perform: return

            # Ask the user to apply the changes or not
            print("\n*** Do you want to apply these changes?")
            user_choice = input("     y|n:  ")
            if user_choice.lower() in ["y", "ye", "yes", "o", "ou", "oui"]:
                print()
                self.__apply_config(apply=True)
            elif user_choice.lower() in ["n", "no", "non"]:
                print("\nNo changes were applied. Exiting.")
                return
            else:
                print(f"\nUnknown answer: '{user_choice}'. No changes were applied. Exiting.")
                return
        except KeyboardInterrupt:
            print("\nKeyboard interruption! Exiting.")
            exit(0)

#===============================================================================
#============================== E N T R Y P O I N T ============================
#===============================================================================

if __name__ == "__main__":
    main = Main()
    main.run()
    print("\nThanks for using this program!")
    exit(0)

