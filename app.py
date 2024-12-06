from datetime import datetime
import argparse
import boto3
from utils.banner import banner
from utils.login import get_sso_session
from utils.enumeration_events import (
    EC2_ENUM_EVENTS,
    ECR_ENUM_EVENTS,
    ECS_ENUM_EVENTS,
    EKS_ENUM_EVENTS,
    DYNAMODB_ENUM_EVENTS,
    LAMBDA_ENUM_EVENTS,
    CLOUDTRAIL_EVENT_HISTORY_DOWNLOAD_EVENTS,
    WAF_ENUM_EVENTS,
    )
from utils.pe_events import (
    PE_CreatePolicyVersion,
    PE_AttachUserPolicy,
)
from utils.persistance_events import (
    SEC_GRP_PERSISTANCE_EVENTS,
)

def get_event_history_for_user(session: boto3.session.Session, args) -> list[dict]:
    events = []
    for region in args.regions:
        config = boto3.session.Config(region_name=region)
        cloudtrail_client = session.client('cloudtrail', config=config)
        iterator = cloudtrail_client.get_paginator('lookup_events').paginate(
            LookupAttributes=[
                {
                    'AttributeKey': 'Username',
                    'AttributeValue': args.token,
                },
            ],
            StartTime=args.start_time,
            EndTime=args.end_time,
        )
        for response in iterator:
            events.extend(response.get('Events'))
    return events


def parse_datetime(dt_str):
    try:
        return datetime.strptime(dt_str, "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"Invalid datetime format: '{dt_str}'. Expected format is 'YYYY-MM-DDTHH:MM:SS'."
        )


def check_ec2_enumeration(events: list) -> bool:
    for event in events:
        if event['EventName'] in EC2_ENUM_EVENTS and \
                event['EventSource'] == 'ec2.amazonaws.com':
            return True
    return False


def check_ecr_enumeration(events: list) -> bool:
    for event in events:
        if event['EventName'] in ECR_ENUM_EVENTS and \
                event['EventSource'] == 'ecr.amazonaws.com':
            return True
    return False


def check_ecs_enumeration(events: list) -> bool:
    for event in events:
        if event['EventName'] in ECS_ENUM_EVENTS and \
                event['EventSource'] == 'ecs.amazonaws.com':
            return True
    return False


def check_eks_enumeration(events: list) -> bool:
    for event in events:
        if event['EventName'] in EKS_ENUM_EVENTS and \
                event['EventSource'] == 'eks.amazonaws.com':
            return True
    return False


def check_dynamodb_enumeration(events: list) -> bool:
    for event in events:
        if event['EventName'] in DYNAMODB_ENUM_EVENTS and \
                event['EventSource'] == 'dynamodb.amazonaws.com':
            return True
    return False


def check_lambda_enumeration(events: list) -> bool:
    for event in events:
        if event['EventName'] in LAMBDA_ENUM_EVENTS and \
                event['EventSource'] == 'lambda.amazonaws.com':
            return True
    return False


def check_cloudtrail_event_history_download(events: list) -> bool:
    for event in events:
        if event['EventName'] in CLOUDTRAIL_EVENT_HISTORY_DOWNLOAD_EVENTS and \
                event['EventSource'] == 'cloudtrail.amazonaws.com':
            return True
    return False


def check_waf_enumeration(events: list) -> bool:
    for event in events:
        if event['EventName'] in WAF_ENUM_EVENTS and \
                event['EventSource'] in ['waf-regional.amazonaws.com', 'waf.amazonaws.com', 'wafv2.amazonaws.com']:
            return True
    return False


def check_CreatePolicyVersion_pe(events: list) -> bool:
    for event in events:
        if event['EventName'] in PE_CreatePolicyVersion and event['CloudTrailEvent'].find('"setAsDefault":true'):
            return True
    return False


def check_AttachUserPolicy_pe(events: list) -> bool:
    for event in events:
        if event['EventName'] in PE_AttachUserPolicy and event['CloudTrailEvent'].find('Pacu_token'):
            return True
    return False


def check_security_group_persistance(events: list) -> bool:
    for event in events:
        if event['EventName'] in SEC_GRP_PERSISTANCE_EVENTS:
            return True
    return False

def main():
    banner()
    parser = argparse.ArgumentParser(description='Parse command-line arguments for regions, audit role, token username, start and end time')
    parser.add_argument(
        '--regions', '-r',
        type=lambda s: s.split(','),
        required=True,
        help='Comma-separated list of regions (e.g. us-east-1,eu-central-1). If you want\
            to check IAM-related actions (e.g. privilege escalation),\
            include the us-east-1 region.'
    )
    parser.add_argument(
        '--profile', '-p',
        type=str,
        required=True,
        help='SSO profile with permissions to read CloudTrail event history.'
    )
    parser.add_argument(
        '--token', '-t',
        type=str,
        required=True,
        help='The honeytoken username.'
    )
    parser.add_argument(
        '--start-time', '-s',
        type=parse_datetime,
        required=True,
        help="Start time in ISO 8601 format (e.g., 2024-12-03T10:30:00)."
    )
    parser.add_argument(
        '--end-time', '-e',
        type=parse_datetime,
        required=True,
        help="End time in ISO 8601 format (e.g., 2024-12-03T12:30:00)."
    )

    args = parser.parse_args()
    session = get_sso_session(profile_name=args.profile)
    events = get_event_history_for_user(session, args)
    ec2_enumeration = check_ec2_enumeration(events)
    ecr_enumeration = check_ecr_enumeration(events)
    ecs_enumeration = check_ecs_enumeration(events)
    eks_enumeration = check_eks_enumeration(events)
    dynamodb_enumeration = check_dynamodb_enumeration(events)
    lambda_enumeration = check_lambda_enumeration(events)
    cloudtrail_event_history_downloaded = check_cloudtrail_event_history_download(events)
    waf_enumeration = check_waf_enumeration(events)
    create_policy_version_pe = check_CreatePolicyVersion_pe(events)
    attach_user_policy_pe = check_AttachUserPolicy_pe(events)
    security_group_persistance = check_security_group_persistance(events)
    
    print(f'ec2_enumeration: {ec2_enumeration}')
    print(f'ecr_enumeration: {ecr_enumeration}')
    print(f'ecs_enumeration: {ecs_enumeration}')
    print(f'eks_enumeration: {eks_enumeration}')
    print(f'dynamodb_enumeration: {dynamodb_enumeration}')
    print(f'lambda_enumeration: {lambda_enumeration}')
    print(f'cloudtrail_event_history_downloaded: {cloudtrail_event_history_downloaded}')
    print(f'waf_enumeration: {waf_enumeration}')
    print(f'Privilige escalation attempt using CreatePolicyVersion api call: {create_policy_version_pe}')
    print(f'Privilige escalation attempt using AttachUserPolicy api call: {attach_user_policy_pe}')
    print(f'security_group_persistance: {security_group_persistance}')


if __name__ == '__main__':
    main()
