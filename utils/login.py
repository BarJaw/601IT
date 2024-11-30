import os
import json
import boto3


def get_sso_creds() -> dict[str]:
    """
    Retrieves sso credentials from the ~/.aws/sso/cache directory
        If those are not found - runs 'aws sso login' and retries
    Output (dict):
        {
            'aws_access_key_id': str,
            'aws_secret_access_key': str,
            'aws_session_token': str,
        }
    """
    try:
        home_dir_path = os.path.expanduser('~')
        aws_sso_cache_path = os.path.join(home_dir_path, '.aws', 'sso', 'cache')
        for file in os.listdir(aws_sso_cache_path):
            path = os.path.join(aws_sso_cache_path, file)
            with open(path, 'r', encoding='utf-8') as f:
                parsed_json = json.load(fp=f)
                if 'refreshToken' in parsed_json.keys():
                    return {
                        'aws_access_key_id': parsed_json['clientId'],
                        'aws_secret_access_key': parsed_json['clientSecret'],
                        'aws_session_token': parsed_json['accessToken'],
                    }
    except FileNotFoundError:
        print('File not found. Trying to run \'aws sso login\' in order to create the sso directory')
    os.system('aws sso login')
    return get_sso_creds()

def get_sso_session(profile_name: str) -> boto3.session.Session:
    session = boto3.session.Session(
        profile_name=profile_name
    )
    return session