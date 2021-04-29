#!/usr/bin/env python

import argparse
import getpass
import os
import socket
from configparser import ConfigParser
from datetime import datetime, timezone
from pathlib import Path
from shutil import which
from subprocess import PIPE, run

import boto3
from dateutil import parser


class CLI:

    """
    Command Line Interface of aws-mfa-v2
    """

    def __init__(self):
        """
        Prepares CLI instance for use
        """
        self.aws_creds_path = f"{os.environ['HOME']}/.aws/credentials"
        self.aws_config_path = f"{os.environ['HOME']}/.aws/config"
        self.env_file_path = f"{os.environ['HOME']}/.aws-mfa"

        # parse command line args
        self.args = self._parse_args()

        # set required instance variables
        self.profile_name = self.args.mfa_profile
        self.mfa_profile_name = self.args.sts_creds_profile
        if self.mfa_profile_name is None:
            self.mfa_profile_name = f"{self.profile_name}-mfa"
        self.prefixd_profile_name = f"profile {self.profile_name}"
        self.prefixd_mfa_profile_name = f"profile {self.mfa_profile_name}"
        self.config = self._load_config(self.aws_config_path)

        self.profile = self.config[self.prefixd_profile_name]

        # validate the aws profile that was specified
        self._validate_aws_profile()

        # either load existing mfa creds or obtain new ones from sts
        # load AWS creds file
        self.creds = self._load_config(self.aws_creds_path)

    def main(self):
        """
        Run CLI with provided arguments and options
        """
        creds_updated, new_creds = self._get_mfa_creds()

        if creds_updated:
            self.creds[self.mfa_profile_name] = new_creds
            self._write_creds()
            print(
                f"Refreshed credentials for profile {self.mfa_profile_name}, they will expire at {self._utc_to_local(self._get_mfa_creds_expired())}"
            )
        else:
            print(
                f"Credentials for profile {self.mfa_profile_name} are still valid until {self._utc_to_local(self._get_mfa_creds_expired())}, skipping refresh"
            )

        # write out our STS temp creds to environment file if requested
        if bool(self._get_argument("write_env_file")):
            self._write_env_file()

    @staticmethod
    def recursive_get_config_param(config, profile_name, param_name):
        """
        Get the specified profile parameter in recursive fashion
        """
        profile = config[profile_name]

        if param_name in profile:
            return profile[param_name]
        elif param_name not in profile and "source_profile" in profile:
            if profile["source_profile"] != "default":
                return CLI.recursive_get_config_param(
                    config, f"profile {profile['source_profile']}", param_name
                )
            else:
                return CLI.recursive_get_config_param(
                    config, profile["source_profile"], param_name
                )
        else:
            return None

    def _write_env_file(self):
        """
        Write out a file containing the specified creds as environment variables
        """
        # make sure file exists
        Path(self.env_file_path).touch()
        # secure it because we're putting credentials in it
        os.chmod(self.env_file_path, 0o600)
        with open(self.env_file_path, "w") as envfile:
            envfile.write(
                f"export AWS_ACCESS_KEY_ID={self.creds[self.mfa_profile_name]['aws_access_key_id']}\n"
            )
            envfile.write(
                f"export AWS_SECRET_ACCESS_KEY={self.creds[self.mfa_profile_name]['aws_secret_access_key']}\n"
            )
            envfile.write(
                f"export AWS_SESSION_TOKEN={self.creds[self.mfa_profile_name]['aws_session_token']}\n"
            )

    def _utc_to_local(self, utc_dt):
        """
        Convert UTC datetime to local datetime
        """
        return utc_dt.replace(tzinfo=timezone.utc).astimezone(tz=None)

    def _get_mfa_creds_expired(self):
        """
        Checks if credentials are expired, returns a datetime if credentials are valid
        """
        if self.mfa_profile_name in self.creds:
            if "expiration" in self.creds[self.mfa_profile_name]:
                expiration = parser.isoparse(
                    self.creds[self.mfa_profile_name]["expiration"]
                )
                now = datetime.utcnow()
                now = now.replace(tzinfo=timezone.utc)
                if expiration < now:
                    return True
                else:
                    return expiration
        return False

    def _get_argument(self, arg_name, required=False):
        """
        Lookup the specified argument in CLI args, environment and configuration and raise
        error if the same argument is provided by more than one source.
        """
        env_var_name = "AWS_MFA_" + arg_name.upper()
        args_as_dict = vars(self.args)
        avail_sources = 0
        arg = None

        if arg_name in args_as_dict and args_as_dict[arg_name] is not None:
            # load arg from CLI args
            arg = args_as_dict[arg_name]
            avail_sources += 1

        if env_var_name in os.environ:
            # load arg from env var
            arg = os.environ[env_var_name]
            avail_sources += 1

        if (
            CLI.recursive_get_config_param(
                self.config, self.prefixd_profile_name, arg_name
            )
            is not None
        ):
            # load arg from config profile
            arg = CLI.recursive_get_config_param(
                self.config, self.prefixd_profile_name, arg_name
            )
            if arg is not None:
                avail_sources += 1

        if required and avail_sources == 0:
            raise ValueError(
                f"Required argument {arg_name} not found on CLI, in environmenbt or in configured profile"
            )

        if avail_sources > 1:
            raise RuntimeError(f"Argument {arg_name} is provided more than once")

        return arg

    def _get_ykey_token(self, yk_oath_credential):
        """
        Obtains a 6 digit OATH token from a YubiKey using the ykman utility
        """
        result = run(
            ["ykman", "oath", "code", "--single", yk_oath_credential],
            stdout=PIPE,
            check=True,
        )
        return result.stdout.decode("utf-8").rstrip()

    def _get_token(self):
        """
        Obtains a 6 digit OATH token from either the CLI args or a YubiKey using the ykman utility
        """
        if self.args.token is None and self._ykey_is_present():
            yk_oath_credential = self._get_argument("yk_oath_credential")
            return self._get_ykey_token(yk_oath_credential)
        elif isinstance(self.args.token, str):
            return self.args.token
        else:
            raise RuntimeError("No oath credential or token code provided, exiting.")

    def _write_creds(self):
        """
        Write out temp AWS credentials obtained from STS
        """
        # write out our newly obtained STS temp creds
        with open(self.aws_creds_path, "w") as credsfile:
            self.creds.write(credsfile)

    def _load_config(self, config_path):
        """
        Loads the configuration from specified path
        """
        config = ConfigParser()
        config.read(config_path)

        return config

    def _get_mfa_creds(self, sts_client=None):
        """
        Load creds from local if not expired otherwise call STS and get new ones
        """
        expiration = self._get_mfa_creds_expired()

        if self.args.force_refresh:
            return True, self._call_sts()
        elif isinstance(expiration, datetime):
            local_expiration = str(self._utc_to_local(expiration))
            return False, self.creds[self.mfa_profile_name]
        else:
            return True, self._call_sts(sts_client=sts_client)

    def _call_sts(self, sts_client=None):
        """
        Call AWS STS to obtain temporary MFA credentials
        """
        # assume if we were passed a role that our parent profile should be used to intiate the session
        if "role_arn" in self.profile and "source_profile" in self.profile:
            parent_profile = self.config[f"profile {self.profile['source_profile']}"]
            session_profile_name = parent_profile["source_profile"]
        else:
            session_profile_name = self.profile_name

        # use STS to obtain temp creds
        if sts_client is None:
            session = boto3.Session(profile_name=session_profile_name)
            client = session.client("sts")
        else:
            client = sts_client

        # set correct duration
        if self._get_argument("duration") is not None:
            duration = int(self._get_argument("duration"))
        elif "role_arn" in self.profile:
            # defualt to 1 hour for roles
            duration = 3600
        else:
            # default to 12 hours for users
            duration = 43200

        if "role_arn" in self.profile:
            username = getpass.getuser()
            hostname = socket.gethostname()
            session_name = f"{username}@{hostname}"

            response = client.assume_role(
                RoleArn=self.profile["role_arn"],
                RoleSessionName=session_name,
                DurationSeconds=duration,
                SerialNumber=CLI.recursive_get_config_param(
                    self.config, self.prefixd_profile_name, "mfa_serial"
                ),
                TokenCode=self._get_token(),
            )
        else:
            response = client.get_session_token(
                SerialNumber=CLI.recursive_get_config_param(
                    self.config, self.prefixd_profile_name, "mfa_serial"
                ),
                TokenCode=self._get_token(),
                DurationSeconds=duration,
            )

        local_expiration = self._utc_to_local(response["Credentials"]["Expiration"])

        # store credentials in ~/.aws/credentials format
        creds = {}
        creds["aws_access_key_id"] = response["Credentials"]["AccessKeyId"]
        creds["aws_secret_access_key"] = response["Credentials"]["SecretAccessKey"]
        creds["aws_session_token"] = response["Credentials"]["SessionToken"]
        creds["expiration"] = response["Credentials"]["Expiration"].isoformat()

        return creds

    def _validate_aws_profile(self):
        """
        Validate the AWS profile provided
        """
        # confirm we have a valid configuration section
        if f"profile {self.args.mfa_profile}" not in self.config.sections():
            raise ValueError(
                f"AWS profile {self.args.mfa_profile} not found in ~/.aws/config"
            )

        # confirm the specified AWS profile contains an mfa_serial parameter
        if (
            CLI.recursive_get_config_param(
                self.config, self.prefixd_profile_name, "mfa_serial"
            )
            is None
        ):
            raise ValueError(
                f"AWS profile {self.args.mfa_profile} nor it's ancestors contain an mfa_serial parameter"
            )

    def _ykey_is_present(self, ykey_count=None):
        """
        Check if a YubiKey is present
        """
        if self._ykman_is_installed():
            # find any attached YubiKeys
            result = run(["ykman", "list"], stdout=PIPE, check=True)

            if ykey_count is None:
                ykey_count = len(result.stdout.decode("utf-8").split("\n")) - 1

            if ykey_count > 1:
                raise RuntimeError(
                    "Multiple YubiKey's detected, exiting becuase this is unsupported"
                )
        elif (
            not self._ykman_is_installed()
            and self._get_argument("yk_oath_credential") is not None
        ):
            raise RuntimeError("Missing required ykman command, exiting")
        else:
            return False

        return True

    def _ykman_is_installed(self):
        """
        Check if ykman utility is installed
        """
        return which("ykman") is not None

    def _parse_args(self):
        """
        Parse arguments
        """
        description = "Obtain and make available temporary AWS credentials"
        parser = argparse.ArgumentParser(description=description)
        try:
            mfa_profile_arg = os.environ["AWS_MFA_PROFILE"]
        except KeyError:
            mfa_profile_arg = None
        parser.add_argument(
            "--mfa-profile",
            type=str,
            default=mfa_profile_arg,
            help="Named AWS profile containg the mfa_serial for use in obtaining temporary credentials.",
        )

        try:
            sts_creds_profile_arg = os.environ["AWS_STS_CREDS_PROFILE"]
        except KeyError:
            sts_creds_profile_arg = None
        parser.add_argument(
            "--sts-creds-profile",
            type=str,
            default=sts_creds_profile_arg,
            help="Optional, the named AWS profile where the AWS STS credentials will be stored.",
        )

        token_help = "Six digit token code from your MFA device"
        parser.add_argument("--token", type=str, help=token_help)

        oath_help = "YubiKey Manager OATH credential to use. For use with a YubiKey. See 'ykman oath list' output for possible values."
        parser.add_argument(
            "--yk-oath-credential", type=str, default=None, help=oath_help
        )

        duration_help = "STS token duration in seconds to request, defaults to 12 hours"
        parser.add_argument("--duration", type=int, help=duration_help)

        env_help = "Write the temp MFA credentials for the profile specified in --mfa-profile out to ~/.aws-mfa. If set via environment variable this should be set to true or false"
        parser.add_argument(
            "--write-env-file", action="store_true", default=None, help=env_help
        )

        refresh_help = (
            "Force a refresh even if the existing credentials are not yet expired"
        )
        parser.add_argument("--force-refresh", action="store_true", help=refresh_help)

        return parser.parse_args()


def main():
    """
    Entrypoint used by setup.py console scripts section
    """
    CLI().main()


if __name__ == "__main__":
    CLI().main()
