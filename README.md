# Overview 
If you want to have MFA enabled on your AWS user account and also make use of AWS profiles this script might be for you. The aws-mfa script calls AWS STS and installs the resulting temporary MFA authorized credentials into ~/.aws/credentials. 

This script is intended to be installed in a user's bin directory (~/bin). It has only been tested on Ubuntu 18.04.

# Usage
```
usage: aws-mfa [-h] mfa_profile token

Obtain and make available temporary AWS credentials

positional arguments:
  mfa_profile  Named AWS profile containg the mfa_serial for use in obtaining
               temporary credentials.
  token        Six digit token code from your MFA device

optional arguments:
  -h, --help   show this help message and exit
```

# Example
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
