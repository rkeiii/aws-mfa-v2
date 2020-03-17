# Overview 
If you want to have MFA enabled on your AWS user account and also make use of AWS profiles this script might be for you. The aws-mfa script calls AWS STS and installs the resulting temporary MFA authorized credentials into ~/.aws/credentials. 

This script is intended to be installed in a user's bin directory (~/bin).

# Requirements
This script has only been tested on Ubuntu 18.04. It requires Python 3 to be available as python3 on the PATH. It uses the following Python libraries.
- boto3
- configparser
- argparse

You can install all of the required libraries globally by executing the following command inside the root of your cloned repo.
```
sudo python3 -m pip install -r requirements.txt
```

# Usage
```
usage: aws-mfa [-h] [--duration DURATION] mfa_profile token

Obtain and make available temporary AWS credentials

positional arguments:
  mfa_profile          Named AWS profile containg the mfa_serial for use in
                       obtaining temporary credentials.
  token                Six digit token code from your MFA device

optional arguments:
  -h, --help           show this help message and exit
  --duration DURATION  STS token duration in seconds to request, defaults to
                       12 hours
```

# Basic example
Steps to run
1. Install the aws-mfa script from this repository into ~/bin and make it executable (also ensure ~/bin is on your PATH)
2. Call aws-mfa providing it the name of an existing named AWS profile and a valid MFA token code
```
aws-mfa existing-profile-name 123456 
```
3. Examine ~/.aws/credentials and see the newly added temporary credentials. Note: The script will insert the temporary STS credentials into a new named profile based on the named profile provided as the first positional argument to this script with "-mfa" appended. 
4. Try calling an AWS service using the new named profile created by the script. Following the example above:
```
aws s3 ls --profile existing-profile-name-mfa
```

# Configuration example to assume a role that requires MFA 
Following the basic example above, here's example content for ~/.aws/config
```
# This is the user we use to obtain temporary credentials from AWS STS
[profile existing-profile-name]
mfa_serial = arn:aws:iam::123456789012:mfa/existing-user
region = us-east-1

# This profile name should match the credential name the aws-mfa script added to ~/.aws/credentials
[profile existing-profile-name-mfa]
source_profile = existing-profile-name 

# A role (in this case in a different AWS account which requires MFA
[profile role-requiring-mfa]
source_profile = existing-profile-name-mfa 
role_arn = arn:aws:iam::098765432101:role/OrganizationAccountAccessRole
```

Once the configuration has been added you can use the role normally, ie:
```
aws s3 ls --profile role-requiring-mfa
```