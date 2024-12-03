from datetime import datetime
import boto3
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


DEFAULT_CONFIG = boto3.session.Config(
    region_name='eu-central-1'
)


def get_event_history_for_user(session: boto3.session.Session, username: str) -> list[dict]:
    events = []
    cloudtrail_client = session.client('cloudtrail', config=DEFAULT_CONFIG)
    iterator = cloudtrail_client.get_paginator('lookup_events').paginate(
        LookupAttributes=[
            {
                'AttributeKey': 'Username',
                'AttributeValue': username,
            },
        ],
        # StartTime=datetime(2024, 12, 2),
        # EndTime=datetime(2024, 12, 2),
    )
    for response in iterator:
        events.extend(response.get('Events'))
    return events


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
    """
    Main function
    """
    session = get_sso_session(profile_name='Admin-pot')
    events = get_event_history_for_user(session, 'Pacu_token')
    # ec2_enumeration = check_ec2_enumeration(events)
    # ecr_enumeration = check_ecr_enumeration(events)
    # ecs_enumeration = check_ecs_enumeration(events)
    # eks_enumeration = check_eks_enumeration(events)
    # dynamodb_enumeration = check_dynamodb_enumeration(events)
    # lambda_enumeration = check_lambda_enumeration(events)
    # cloudtrail_event_history_downloaded = check_cloudtrail_event_history_download(events)
    # waf_enumeration = check_waf_enumeration(events)
    # CreatePolicyVersion_pe = check_CreatePolicyVersion_pe(events)
    # AttachUserPolicy_pe = check_AttachUserPolicy_pe(events)
    security_group_persistance = check_security_group_persistance(events)
    
    # print(f'ec2_enumeration: {ec2_enumeration}')
    # print(f'ecr_enumeration: {ecr_enumeration}')
    # print(f'ecs_enumeration: {ecs_enumeration}')
    # print(f'eks_enumeration: {eks_enumeration}')
    # print(f'dynamodb_enumeration: {dynamodb_enumeration}')
    # print(f'lambda_enumeration: {lambda_enumeration}')
    # print(f'cloudtrail_event_history_downloaded: {cloudtrail_event_history_downloaded}')
    # print(f'waf_enumeration: {waf_enumeration}')
    # print(f'Privilige escalation attempt using CreatePolicyVersion api call: {CreatePolicyVersion_pe}')
    # print(f'Privilige escalation attempt using AttachUserPolicy api call: {AttachUserPolicy_pe}')
    print(f'security_group_persistance: {security_group_persistance}')
    # for event in events:
    #     print(event['EventName'])

if __name__ == '__main__':
    main()
