import argparse
import copy
import logging
import os
import re
import subprocess
from datetime import datetime

import boto3
from botocore.exceptions import ClientError
from configobj import ConfigObj

logging.basicConfig()
logging.getLogger().setLevel(level=logging.INFO)

# Globals
AWS_CREDS = {}
AWS_CONFIG = {}


class StsHelper(object):
    def __init__(self, **kwargs):
        self.sts_client = boto3.client('sts', **kwargs)

    def assume_into_role(self, role_arn, duration=3600):
        regex_match = re.match(r"arn:aws:iam::\d+:role\/([a-zA-Z]+)", role_arn)
        if not regex_match:
            raise ValueError(f"'{role_arn}' is not a valid ARN")
        role_name = regex_match.group(1)

        try:
            response = self.sts_client.assume_role(
                        RoleArn=role_arn,
                        RoleSessionName=role_name,
                        DurationSeconds=duration)
        except ClientError as ce:
            logging.error(f"An error occured when assumong into the role.\n{ce}")
            raise
        try:
            key_id = response['Credentials']['AccessKeyId']
            key = response['Credentials']['SecretAccessKey']
            token = response['Credentials']['SessionToken']
        except KeyError as ke:
            logging.error(f"Parsing the response failed.\n{ke}")
            raise

        return key_id, key, token

    def get_session_token(self, duration, mfa_serial, mfa_token):
        try:
            response = self.sts_client.get_session_token(
                        DurationSeconds=duration,
                        SerialNumber=mfa_serial,
                        TokenCode=mfa_token)
        except ClientError as ce:
            logging.error(f"An error occured when requesting a token.\n{ce}")
            raise

        try:
            key_id = response['Credentials']['AccessKeyId']
            key = response['Credentials']['SecretAccessKey']
            token = response['Credentials']['SessionToken']
            expiration_date = response['Credentials']['Expiration']
        except KeyError as ke:
            logging.error(f"Parsing the response failed.\n{ke}")
            raise

        return key_id, key, token, expiration_date


def set_profiles(creds, config):
    global AWS_CREDS
    global AWS_CONFIG

    AWS_CREDS = creds
    AWS_CONFIG = config


def directory(path):
    path = os.path.expanduser(path)
    if not os.path.isdir(path):
        raise argparse.ArgumentTypeError(f"readable_dir:{path} is not a valid path.")

    if os.access(path, os.R_OK):
        return path
    else:
        raise argparse.ArgumentTypeError(f"readable_dir:{path} is not a readable directory.")


def is_valid_file(path):
    if not os.path.exists(path):
        raise IOError(f"{path} does not exist.")
    if not os.path.isfile(path):
        raise IOError(f"{path} is not a valid file.")
    if os.access(path, os.R_OK):
        return path
    else:
        raise IOError(f"{path} is not a readable file.")


def parse_args():
    parser = argparse.ArgumentParser(description='A Python3 tool that simplifies usage of MFA with AWS CLI.')

    parser.add_argument("-r", "--role", help="The role name to assume into.")
    parser.add_argument("--aws_home", type=directory, default='~/.aws/',
            help="Path to AWS configuration folder. Usually located in '~/.aws/'.")
    parser.add_argument("-p", "--profile", type=str, default="default",
                        help="Name of the credential profile to be used to request temporary credentials.")
    parser.add_argument("-t", "--token", type=str,
                        help="MFA token to use. If not specified, it will be prompted.")
    parser.add_argument("-d", "--duration", type=int, default=43200, 
                        help="MFA session duration in seconds. Has to be between 900 (15 min) and 129600 (36 h). Default is 12h.")
    parser.add_argument("-s", "--span", type=int, default=3600,
                        help="Assumed role session duration. Can last from 15 minutes to 1 hour. Default is 1h.")
    parser.add_argument("--refresh", action='store_true', help="Refresh the MFA session regardless of the expiration date")
    parser.add_argument("-e", "--export", choices=['mfa', 'role'],
                        help="Provide this flag if you want to export the AWS access secrets to the environment variables instead of saving them in the shared credentials file.")
    args = parser.parse_args()

    if args.export == "role" and not args.role:
        parser.error("--export=role has to be provided together with --role argument.")
    elif args.export == "mfa" and args.role:
        parser.error("--export=mfa cannot be provided together with --role argument.")

    return args


def has_token_expired(expiration_date):
    try:
        exp_date = datetime.strptime(expiration_date, '%Y-%m-%d %H:%M:%S%z')
        logging.debug(f"MFA session expiration date = {exp_date}")
        now = datetime.now(exp_date.tzinfo)
    except Exception as ex:
        logging.error(f"An error occurred when parsing the expiration date.\n{ex}")
        raise

    if now >= exp_date:
        return 1
    else:
        return 0


def complete_profile(p_name, p_data):
    if not "aws_access_key_id" in p_data.keys():
        # look in CREDS
        if p_name in AWS_CREDS.keys():
            logging.debug(f"Profile '{p_name}' was found in shared credentials file.")
            cred_profile = copy.deepcopy(AWS_CREDS[p_name])
        elif "source_profile" in p_data.keys():
            src_profile = p_data['source_profile']
            logging.debug(f"Profile '{p_name}' has a source profile '{src_profile}'.")

            if src_profile in AWS_CREDS.keys():
                cred_profile = copy.deepcopy(AWS_CREDS[src_profile])
            else:
                raise ValueError(f"Profile '{src_profile}' does not exist in the shared credentials file.")
        else:
            raise ValueError(f"AWS access keys were not found for profile '{p_name}'.")

        if (("aws_access_key_id" in cred_profile.keys()) and
                ("aws_secret_access_key" in cred_profile.keys())):
            p_data['aws_access_key_id'] = cred_profile['aws_access_key_id']
            p_data['aws_secret_access_key'] = cred_profile['aws_secret_access_key']
        else:
            raise ValueError(f"Profile '{p_name}' is invalid.")

    # TODO check for MFA arn
    if "mfa_serial" not in p_data.keys():
        raise ValueError(f"Profile '{p_name}' does not have the 'mfa_serial' entry.")

    return p_data

def refresh_token(src_profile, args):
    logging.debug("Entering refresh_token.")
    sts_helper = StsHelper(aws_access_key_id=src_profile['aws_access_key_id'], aws_secret_access_key=src_profile['aws_secret_access_key'])

    if not args.token:
        mfa_token = input("Enter your MFA code:\n")
    else:
        mfa_token = args.token

    try:
        mfa_key_id, mfa_key, mfa_session_token, mfa_expiration_date = sts_helper.get_session_token(args.duration, src_profile['mfa_serial'], mfa_token)
    except Exception as ex:
        logging.critical(f"MFA session could not be created / refreshed.\n{ex}")
        exit(-1)

    if args.export == "mfa":
        print("Copy and paste the following to your terminal")
        print(f"export AWS_ACCESS_KEY_ID=\"{mfa_key_id}\" && export AWS_SECRET_ACCESS_KEY=\"{mfa_key}\" && export AWS_SESSION_TOKEN=\"{mfa_session_token}\"")
    else:
        AWS_CREDS['mfa'] = {'aws_access_key_id': mfa_key_id, 'aws_secret_access_key': mfa_key, 'aws_session_token': mfa_session_token, 'aws_session_expiration_date': mfa_expiration_date}
        AWS_CREDS.write()


def exec_role(role_arn, args, src_profile):
    role_name = args.role
    duration = args.span

    sts_helper = StsHelper(aws_access_key_id=src_profile['aws_access_key_id'], 
                            aws_secret_access_key=src_profile['aws_secret_access_key'], 
                            aws_session_token=src_profile['aws_session_token'])

    role_key_id, role_key, role_token = sts_helper.assume_into_role(role_arn, duration)

    if role_name not in AWS_CREDS.keys():
        AWS_CREDS[role_name] = {}

    if args.export == "role":
        print("Copy and paste the following to your terminal")
        print(f"export AWS_ACCESS_KEY_ID=\"{role_key_id}\" && export AWS_SECRET_ACCESS_KEY=\"{role_key}\" && export AWS_SESSION_TOKEN=\"{role_token}\"")
    else:
        AWS_CREDS[role_name]['aws_access_key_id'] = role_key_id
        AWS_CREDS[role_name]['aws_secret_access_key'] = role_key
        AWS_CREDS[role_name]['aws_session_token'] = role_token

        AWS_CREDS.write()


def get_src_profile(args):
    if args.profile in AWS_CONFIG.keys():
        src_profile = copy.deepcopy(AWS_CONFIG[args.profile])
    else:
        logging.critical(f"Profile '{args.profile}' was not found in your AWS config file. You can specify the name using --profile flag.")
        exit(-1)

    try:
        src_profile = complete_profile(args.profile, src_profile)
    except Exception as ex:
        logging.error(ex)
        exit(-1)
    logging.debug(f"Source profile has the following configuration:\n{src_profile}")

    return src_profile


def main(args):
    # TODO make vars below configurable
    config_path = os.path.join(args.aws_home, "config")
    creds_path = os.path.join(args.aws_home, "credentials")

    try:
        config = ConfigObj(is_valid_file(config_path))
        logging.debug(f"Loaded the following config profiles:\n{config.dict().keys()}")
        creds = ConfigObj(is_valid_file(creds_path))
        logging.debug(f"Loaded the following credential profiles:\n{creds.dict().keys()}")
        set_profiles(creds, config)
    except Exception as ex:
        logging.critical(f"AWS confguration files could not be parsed, aborting")
        logging.critical(ex)
        exit(-1)

    # This code is here in case the target role is broken, so the
    # program fails without asking for the MFA token
    if args.role:
        regex_match = re.match(args.role, r"profile \S+")
        if not regex_match:
            named_profile = f"profile {args.role}"
        else:
            named_profile = args.role

        if named_profile not in AWS_CONFIG.keys():
            logging.critical(f"Target role '{args.role}' was not found in {config_path}.")
            exit(-1)

        target_role = copy.deepcopy(AWS_CONFIG[named_profile])

        if "role_arn" not in target_role.keys():
            logging.critical(f"Profile '{args.role}' does not have role_arn entry.")
            exit(-1)

    if args.profile != "default":
        args.profile = f"profile {args.profile}"

    src_profile = get_src_profile(args)

    token_expired = 1
    if "mfa" in AWS_CREDS.keys():
        if "aws_session_expiration_date" in AWS_CREDS['mfa']:
            token_expired = has_token_expired(AWS_CREDS['mfa']['aws_session_expiration_date'])

    if token_expired or args.refresh:
        if token_expired:
            logging.info("The MFA token has expired.")
        elif args.refresh:
            logging.info("You have requested the MFA session refresh.")

        refresh_token(src_profile, args)
    else:
        logging.info("The MFA token is still valid")
        if args.export == "mfa":
            print("Copy and paste the following to your terminal:")
            print(f"export AWS_ACCESS_KEY_ID=\"{AWS_CREDS['mfa']['aws_access_key_id']}\" && " \
                  f"export AWS_SECRET_ACCESS_KEY=\"{AWS_CREDS['mfa']['aws_secret_access_key']}\" && " \
                  f"export AWS_SESSION_TOKEN=\"{AWS_CREDS['mfa']['aws_session_token']}\"")

    if args.role:
        mfa_profile = copy.deepcopy(AWS_CREDS['mfa'])
        exec_role(target_role['role_arn'], args, mfa_profile)


if __name__ == "__main__":
    args = parse_args()
    main(args)
