'''
Lambda function for changing passwords on multiple Cognito user pools
'''
from datetime import datetime, timezone, timedelta
import random
import string
import base64

from dateutil import parser
import boto3
from botocore.exceptions import ClientError

from_address = ''
to_addresses = []
num_days = 90
password_change_date_attr = 'custom:passwordChangeDate'
current_time = datetime.now(timezone.utc)

def main(event, context):
    user_pools = get_user_pools()
    for pool in user_pools:
        password = generate_password()
        users = get_users(pool['Id'])
        for user in users:
            print(f"Found user: {user['Username']} in pool {pool['Name']}")
            found_pcd_attr = False
            for attribute in user['Attributes']:
                if attribute['Name'] == password_change_date_attr:
                    last_modified = parser.parse(attribute['Value'])
                    found_pcd_attr = True
            if not found_pcd_attr:
                print(f"{password_change_date_attr} attribute not found. " \
                    'Creating with current time.')
                results = add_password_date_attribute(pool['Id'], user)
                print(f"Results: {results}")
                last_modified = parser.parse(current_time)
            print(f"Finding time delta for user {user['Username']}")
            time_delta = get_time_delta(last_modified)
            if time_delta > timedelta(days=num_days):
                print(f"Older than {num_days} days. Changing password.")
                password = get_secret(user['Username'])
                update_user_password(pool['Id'], user['Username'], password)
                print(f"Password for {user['Username']} has been changed.")
            elif time_delta > timedelta(days=num_days-1):
                print(f"Password will change tomorrow. Sending notification email.")
                #email_response = send_notification_email(
                #    f"Password change for {user['Username']} incoming",
                #    f"The password for {user['Username']} will change tomorrow. \n" \
                #    f"The new password is {password}."
                #    )
            else:
                print(f'Newer than {num_days} days')


def get_user_pools():
    cognito_client = boto3.client('cognito-idp')
    user_pools = []
    try:
        user_pools_list = cognito_client.list_user_pools(MaxResults=50)
        for pool in user_pools_list['UserPools']:
            user_pools.append(pool)
    except ClientError as e:
        raise e

    return user_pools

def get_users(pool):
    cognito_client = boto3.client('cognito-idp')
    users = []
    try:
        user_list = cognito_client.list_users(UserPoolId=pool)
        for user in user_list['Users']:
            users.append(user)
    except ClientError as e:
        raise e

    return users

def get_time_delta(lm_time):
    time_diff = current_time - lm_time
    print(f"Time difference: {time_diff}")
    return time_diff

def add_password_date_attribute(pool, user):
    cognito_client = boto3.client('cognito-idp')

    print("Password change date not found. Adding...")
    try: 
        results = cognito_client.admin_update_user_attributes(
            UserPoolId=pool,
            Username=user['Username'],
            UserAttributes=[
                {
                    'Name': password_change_date_attr,
                    'Value': str(current_time)
                }
            ]
        )
    except ClientError as e:
        raise e

    return results

def generate_password():
    password = []
    password_length = 16
    punc = string.punctuation
    upper = string.ascii_uppercase
    lower = string.ascii_lowercase
    num = string.digits
    while len(password) < password_length:
        password.append(random.choice(punc))
        password.append(random.choice(upper))
        password.append(random.choice(lower))
        password.append(random.choice(num))
    random.shuffle(password)
    new_password = "".join(password)
    print(f"New Password: {new_password}")
    return new_password

def send_notification_email(subject, message):
    ses_client = boto3.client('ses')

    try:
        response = ses_client.send_email(
            Source=from_address,
            Destination={
                'ToAddresses': to_addresses
            },
            Message={
                'Subject': {
                    'Data': subject
                },
                'Body': {
                    'Text': {
                        'Data': message
                    }
                }
            }
        )
    except ClientError as e:
        raise e

    return response

def get_secret(name):

    secret_name = name
    region_name = "us-east-1"

    # Create a Secrets Manager client
    session = boto3.session.Session()
    sm_client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )

    # In this sample we only handle the specific exceptions for the 'GetSecretValue' API.
    # See https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
    # We rethrow the exception by default.

    try:
        get_secret_value_response = sm_client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        if e.response['Error']['Code'] == 'DecryptionFailureException':
            # Secrets Manager can't decrypt the protected secret text using the provided KMS key.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InternalServiceErrorException':
            # An error occurred on the server side.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            # You provided an invalid value for a parameter.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            # You provided a parameter value that is not valid for the current state of the resource.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'ResourceNotFoundException':
            # We can't find the resource that you asked for.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
    else:
        # Decrypts secret using the associated KMS CMK.
        # Depending on whether the secret is a string or binary, one of these fields will be populated.
        if 'SecretString' in get_secret_value_response:
            secret = get_secret_value_response['SecretString']
        else:
            decoded_binary_secret = base64.b64decode(get_secret_value_response['SecretBinary'])
            
    return secret

#def update_secret

def update_user_password(pool_id, user, password):
    cognito_client = boto3.client('cognito-idp')
    
    try:
        set_password = cognito_client.admin_set_user_password(
            UserPoolId=pool_id,
            Username=user,
            Password=password,
            Permanent=True
        )
    except ClientError as e:
        raise e
    return set_password
