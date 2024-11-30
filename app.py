import boto3
from utils.login import get_sso_session


def get_event_history_for_user(session: boto3.session.Session, username: str) -> list[dict]:
    events = []
    cloudtrail_client = session.client('cloudtrail')
    iterator = cloudtrail_client.get_paginator('lookup_events').paginate(
        LookupAttributes=[
            {
                'AttributeKey': 'Username',
                'AttributeValue': username,
            },
        ]
    )
    for response in iterator:
        events.extend(response.get('Events'))
    return events


def main():
    """
    Main function
    """
    session = get_sso_session(profile_name='Admin-pot')
    for event in get_event_history_for_user(session, 'Restricted_token'):
        print(event['EventName'])

if __name__ == '__main__':
    main()
