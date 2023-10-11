# Context
Currently (2023-08-23), `aws` provider on Terraform does not support AWS IAM Identity Center (IAMIC)'s Permission Sets and accounts management.

Thus, I implemented a Python3 script using the AWS SDK (`boto3`) to reproduce Terraform until it officially supports them.

The file [`./permission_sets.yml`](./permission_sets.yml) aims to keep track of AWS IAM Identity Center Permission Sets management.

***This script was written only to temporary replace a missing Terraform resource (IAM Identity Center - IAMIC). It's is not optimized nor perfect, but it does the job rather than managing all of these permission sets from the AWS Console.***


# Limitations
- Permission boundaries are not supported.
- [`./permission_sets.yml`](./permission_sets.yml) file name is directly written in the code.


# Usage
In order to create, update or delete permission sets, you need to:
1. Update the dedicated configuration file [`./permission_sets.yml`](./permission_sets.yml).
2. Source a Python3 virtual environment containing the required libraries listed in [`requirements.pip.txt`](./requirements.pip.txt).
3. Execute the Python3 script [`apply.py`](./apply.py).

***Note: the script admit the local configuration file is its source of truth. If you do any change usiing the AWS Console, make sure to report them in the YAML file before running the Python3 script.***

## Requirements
- `python` >= `3.8`
- An account on AWS (IAM or Identity Center) with enough permissions on AWS IAM Identity Center Service.
- An `aws` CLI profile defined OR an access keys pair. They must be **VALID**. **Also make sure to specified the SAME AWS Region (either using AWS_REGION environment variable or the one defined of the profile if any) as the one where you created your IAM Identity Center**!


## 1. Set up Python3 Virtual Environment
*This step needs to be done only once.*


### a. Create the Virtual Environment
```bash
python3 -m venv permission_sets_venv
```


### b. Source it
```bash
. ./permission_sets_venv/bin/activate
```


### c. Install required libraries
```bash
pip3 install -r requirements.pip.txt
```


## 2. Source it
```bash
. ./permission_sets_venv/bin/activate
```



## 3. Update important global variables
At the top the Python script [`./apply.py`](./apply.py), some important variables should be updated to match your needs.
```py
################################################################################
######## U P D A T E   T H E S E   V A R I A B L E S   I F   N E E D E D #######
################################################################################
INSTANCE_ARN="arn:aws:sso:::instance/XXXXXXXXXXXXX" # to set only once

PERMISSION_SETS_CONFIG_FILE="./permission_sets.yml"

DEFAULT_SESSION_DURATION="PT03H0M0S"
################################################################################
################################################################################
```

- `INSTANCE_ARN`: the ARN of your IAM Identity Center instance. **This is one is required to make the script work**.

- `PERMISSION_SETS_CONFIG_FILE`: the YAML file containing your permission sets as detailled in the sample [./permission_sets.example.yml](./permission_sets.example.yml).

- `DEFAULT_SESSION_DURATION`: the default session duration for each newly created permission sets when not set. Format must respect ISO 8601 format.


## 4. Execute the script
```bash
python3 apply.py
```

No errors should appear, only possible warnings and changes according to the permission sets configuration as defined in [`./permission_sets.yml`](./permission_sets.yml)



# Configuration file
To update permission sets, you **must** update the configuration file located in this directory and named [permission_sets.yml](./permission_sets.yml).

An **example file** is located in the same directory and named [./permission_sets.example.yml](./permission_sets.example.yml). It provides additional information about some fields and other limitiations.

The key of each element in `permission_sets` must be the permission set name.


# General notes:
- A permission set must have a simple, clear anc precise name (up to 32 characters). **Keep in mind users will have to deal with them**.
- A permission set **SHOULD HAVE A SPECIFIC FUNCTION**. They should give granular permissions.
- A permission set is ONLY a set of 0 or more IAM policy NAMES. It is not linked to a user, group nor any AWS account *here*.
- A permission set can contain up to 10 AWS managed and Customer managed permission sets both.

