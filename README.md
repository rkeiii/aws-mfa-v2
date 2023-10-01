[![codecov](https://codecov.io/gh/rkeiii/aws-mfa-v2/branch/master/graph/badge.svg?token=4NwTgvppDW)](https://codecov.io/gh/rkeiii/aws-mfa-v2)
[![PyPI version](https://badge.fury.io/py/aws-mfa-v2.svg)](https://badge.fury.io/py/aws-mfa-v2)

# Overview

This package's purpose in life is to make it faster and easier to call [AWS STS](https://docs.aws.amazon.com/STS/latest/APIReference/welcome.html) to obtain temporary AWS
credentials and write them out to ~/.aws/credentials (which is typically required when using [MFA](https://aws.amazon.com/iam/features/mfa/)). It attempts to follow a
[batteries included philosophy](https://www.quora.com/What-does-batteries-included-philosophy-mean). The 6 digit OATH tokens required for MFA authentication can either be
provided directly via the --token argument or obtained automatically from a YubiKey by specifying the OATH credential in the `--yk-oath-credential argument`. The existing
OATH credentials stored on your YubiKey can be found using the `ykman list` command assuming that you have the[YubiKey Manager CLI](https://github.com/Yubico/yubikey-manager) installed.

# Installation

Requires Python 3.8 or later and uses Poetry for dependancy management

```
pip install aws-mfa-v2
pip install aws-mfa-v2[yubikey] # YubiKey support
```

# Usage

```
usage: aws-mfa [-h] [--mfa-profile MFA_PROFILE] [--sts-creds-profile STS_CREDS_PROFILE] [--token TOKEN]
               [--yk-oath-credential YK_OATH_CREDENTIAL] [--duration DURATION] [--write-env-file] [--force-refresh]
               [--min-remaining MIN_REMAINING]

Obtain and make available temporary AWS credentials

options:
  -h, --help            show this help message and exit
  --mfa-profile MFA_PROFILE
                        Named AWS profile containg the mfa_serial for use in obtaining temporary credentials.
  --sts-creds-profile STS_CREDS_PROFILE
                        Optional, the named AWS profile where the AWS STS credentials will be stored.
  --token TOKEN         Six digit token code from your MFA device
  --yk-oath-credential YK_OATH_CREDENTIAL
                        YubiKey Manager OATH credential to use. For use with a YubiKey. See 'ykman oath list' output for possible values.
  --duration DURATION   STS token duration in seconds to request, defaults to 12 hours
  --write-env-file      Write the temp MFA credentials for the profile specified in --mfa-profile out to ~/.aws-mfa. If set via environment
                        variable this should be set to true or false
  --force-refresh       Force a refresh even if the existing credentials are not yet expired
  --min-remaining MIN_REMAINING
                        Set a minimum number of seconds existing credentials must be valid for before a refresh is performed
```

# Environment variable configuration

The following environment variables can be used to provide configuration

```
AWS_MFA_PROFILE - See --mfa-profile
AWS_MFA_YK_OATH_CREDENTIAL - See --yk-oath-credential
AWS_MFA_DURATION - See --duration
AWS_MFA_WRITE_ENV_FILE - See --write-env-file
```

# Basic example

Steps to run

1. Install the latest version of the aws-mfa-v2 package from pypi

```
pip install aws-mfa-v2
pip install aws-mfa-v2[yubikey] # If you want YubiKey support
```

2. Call aws-mfa providing it the name of an existing AWS profile and a valid MFA token code

```
aws-mfa --mfa-profile existing-profile-name --token 123456
```

3. Examine ~/.aws/credentials and see the newly added temporary credentials. Note: The script will insert the temporary STS credentials into a new named profile based on the
   named profile provided as the first positional argument to this script with "-mfa" appended.
4. Try calling an AWS service using the new named profile created by the script. Following the example above:

```
aws sts get-caller-identity --profile existing-profile-name-mfa
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

# A role (in this case in a different AWS account) which requires MFA
[profile role]
source_profile = existing-profile-name-mfa
role_arn = arn:aws:iam::098765432101:role/OrganizationAccountAccessRole
```

Once the configuration has been added you can use the role normally, ie:

```
aws sts get-caller-identity --profile role
```

# YubiKey Support

Loading OATH tokens directly from a YubiKey is supported. You will need to provide the --yk-oath-credential argument or equivalent environment variable.
A list of valid values can be found by running `ykman oath list`.

Example command to load an MFA token directly from a YubiKey:

```
aws-mfa --mfa-profile bks-rone --yk-oath-credential "Amazon Web Services:rone-cli@bookshare"
```

# Exposing temporary credentials as environment variables

You can use the `--write-env-file` option to expose the credentials associated with the profile specified in `--mfa-profile` as environment variables. This is useful for
compatibility with other software that may not support AWS CLI profiles properly. If you set the `--write-env-file` option credentials will be written to `~/.aws-mfa`
regardless of whether the credentials are refreshed in the current CLI run. An example usage follows:

```
aws-mfa --mfa-profile role --write-env-file
. ~/.aws-mfa
aws sts get-caller-identity --profile role-mfa
```

# Contribution Guidelines

I look forward to accepting more contributions on this project. The requirements are very simple right now:

- Format the code with Black
- Submit a PR

# Release Proccess

The current release process is:

- poetry build
- poetry publish
