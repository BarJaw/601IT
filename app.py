from datetime import datetime
import boto3
# import csv
# from prettyprinter import pprint
from utils.login import get_sso_session
from utils.events import EC2_ENUM_EVENTS, ECR_ENUM_EVENTS, ECS_ENUM_EVENTS, EKS_ENUM_EVENTS, DYNAMODB_ENUM_EVENTS, LAMBDA_ENUM_EVENTS


DEFAULT_CONFIG = boto3.session.Config(
    region_name = 'eu-central-1'
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
        StartTime=datetime(2024, 12, 2),
        EndTime=datetime(2024, 12, 2),
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

def main():
    """
    Main function
    """
    session = get_sso_session(profile_name='Admin-pot')
    events = get_event_history_for_user(session, 'Pacu_token')
    ec2_enumeration = check_ec2_enumeration(events)
    ecr_enumeration = check_ecr_enumeration(events)
    ecs_enumeration = check_ecs_enumeration(events)
    eks_enumeration = check_eks_enumeration(events)
    dynamodb_enumeration = check_dynamodb_enumeration(events)
    lambda_enumeration = check_lambda_enumeration(events)
    
    
    
    print(f'ec2_enumeration: {ec2_enumeration}')
    print(f'ecr_enumeration: {ecr_enumeration}')
    print(f'ecs_enumeration: {ecs_enumeration}')
    print(f'eks_enumeration: {eks_enumeration}')
    print(f'dynamodb_enumeration: {dynamodb_enumeration}')
    print(f'lambda_enumeration: {lambda_enumeration}')


if __name__ == '__main__':
    main()
