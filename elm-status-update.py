import json
import boto3
import logging
from datetime import datetime
import time
import os

dynamodb_client = boto3.client('dynamodb')

logger = logging.getLogger(name="LambdaLogger")
logger.setLevel(logging.INFO)


def get_desired_time(ttl_in_minutes): 
    current_time = time.time()
    ttl_in_seconds = int(ttl_in_minutes * 60)
    epoch = int(current_time) + ttl_in_seconds
    desired_time_format = datetime.utcfromtimestamp(epoch).replace(microsecond=0)
    return epoch, str(desired_time_format)


def check_simple_exception_format(resource):
    if resource['exceptionFormat'] == 'Resource ID':
        logger.info(f" Resource : {resource['resourceId']} has Exception_Format : {resource['exceptionFormat']}.")
        return resource['resourceId']

    if resource['exceptionFormat'] == "Resource ARN":
        logger.info(f" Resource : {resource['resourceName']} has Exception_Format : {resource['exceptionFormat']}.")
        region_accountid = resource['awsRegion'] + ":" + resource['awsAccountId']
        paginator = dynamodb_client.get_paginator('scan')
        response = paginator.paginate(
            TableName='Config-ResourceExceptions',
            Select='SPECIFIC_ATTRIBUTES',
            ExpressionAttributeNames = {"#R" : "RuleId", "#E" : "Exception", "#S" : "ExceptionStatus"},
            ExpressionAttributeValues={
                ":reg_id":{"S" : region_accountid},
                ":resource_name":{"S" : resource['resourceName']},
                ":rule_id":{"N" : resource['configRuleId']}
            },
            ProjectionExpression='AccountId_RuleId,#E,#R,#S',
            FilterExpression= 'contains (#E, :reg_id) AND contains (#E, :resource_name) AND #R = :rule_id'
        ).build_full_result()
        return response['Items'][0]['Exception']['S']


def check_composite_exception_format(resource):
    logger.info(f"Resource {resource['resourceId']} has Exception Type: Composite.")

    paginator = dynamodb_client.get_paginator('scan')
    response = paginator.paginate(
        TableName='Config-ResourceExceptions',
        Select='SPECIFIC_ATTRIBUTES',
        ExpressionAttributeNames = {"#R" : "RuleId", "#E" : "Exception", "#S" : "ExceptionStatus"},
        ExpressionAttributeValues={
            ":resource_name":{"S" : resource['resourceName']},
            ":rule_id":{"N" : resource['configRuleId']}
        },
        ProjectionExpression='AccountId_RuleId,#E,#R,#S',
        FilterExpression= 'begins_with (#E, :resource_name) AND #R = :rule_id'
    ).build_full_result()
    return response['Items']


def update_exception_table(deleted_resources, desired_time):
    try:
        now = datetime.today().strftime("%m/%d/%Y %H:%M:%S")
        logger.info("Updating Config-ResourceExceptions table.")
        for resource in deleted_resources:
            partition_key = resource['awsAccountId'] + '_' + resource['configRuleId']
            if resource['exceptionType'] == 'Simple':
                exception = check_simple_exception_format(resource)
                dynamodb_client.update_item(
                    TableName='Config-ResourceExceptions',
                    Key={
                    'AccountId_RuleId': {'S': partition_key},
                    'Exception' : {'S': exception},
                    },
                    UpdateExpression='SET #S = :val, #LM = :auto, #ttl = :ttl, #UT = :update_timestamp',
                    ConditionExpression='#Reg = :region',
                    ExpressionAttributeNames={'#S': 'ExceptionStatus', '#LM': 'LastModifiedBy', '#Reg': 'Region', '#ttl': 'TTL','#UT': 'UpdateTimeStamp'},
                    ExpressionAttributeValues={':val': {'S': 'RESOURCE_DELETED'}, ':auto': {'S': 'ELM_AUTOMATION'}, ':region': {'S': resource['awsRegion']},':ttl': {'N': str(desired_time[0])},':update_timestamp': {'S': str(now)}}, 
                    ReturnValues="UPDATED_NEW"
                )
                logger.info(f"Exception : {resource['resourceId']} updated successfully.")

            elif resource['exceptionType'] == 'Composite':
                exceptions = check_composite_exception_format(resource)
                for exception in exceptions:
                    dynamodb_client.update_item(
                        TableName='Config-ResourceExceptions',
                        Key={
                        'AccountId_RuleId': {'S': partition_key},
                        'Exception' : {'S': exception['Exception']['S']},
                        },
                        UpdateExpression='SET #S = :val, #LM = :auto, #ttl = :ttl, #UT = :update_timestamp',
                        ConditionExpression='#Reg = :region',
                        ExpressionAttributeNames={'#S': 'ExceptionStatus', '#LM': 'LastModifiedBy', '#Reg': 'Region', '#ttl': 'TTL','#UT': 'UpdateTimeStamp'},
                        ExpressionAttributeValues={':val': {'S': 'RESOURCE_DELETED'}, ':auto': {'S': 'ELM_AUTOMATION'} , ':region': {'S': resource['awsRegion']},':ttl': {'N': str(desired_time[0])}, ':update_timestamp': {'S': str(now)}},
                        ReturnValues="UPDATED_NEW"
                    )
                    logger.info(f"Exception : {exception['Exception']['S']} updated successfully.")

        logger.info(f"Expiration Time: {desired_time[1]}")

    except Exception as error:
        logging.error(f"Error while updating record! [{error}]")


def filter_deleted_resource_list(config_response):
    deleted_resources = []
    for resource in config_response['resourceIdentifiers']:
        if 'resourceDeletionTime' in resource.keys():
            deleted_resources.append(resource)
    return deleted_resources


def assume_role(aws_account_number, role_name):
    sts_client = boto3.client('sts')
    partition = sts_client.get_caller_identity()['Arn'].split(":")[1]

    response = sts_client.assume_role(
        RoleArn='arn:{}:iam::{}:role/{}'.format(
            partition,
            aws_account_number,
            role_name
        ),
        RoleSessionName='Session'
    )
    session = boto3.Session(
        aws_access_key_id=response['Credentials']['AccessKeyId'],
        aws_secret_access_key=response['Credentials']['SecretAccessKey'],
        aws_session_token=response['Credentials']['SessionToken']
    )

    logger.info(f"Assumed session for {aws_account_number}.")
    return session


def lambda_handler(event, context):
    try:
        for data in event['Records']:
            message_body = json.loads(data['body'])

            temp_dict = {
                'message_id' : data['messageId'],
                'resourceType' : message_body['detail']['resourceType'],
                'resourceId' : message_body['detail']['resourceId'],
                'awsAccountId' : message_body['detail']['awsAccountId'],
                'awsRegion' : message_body['detail']['awsRegion'],
                'configRuleName' : message_body['detail']['configRuleName']
            }

            # get config rule details
            paginator = dynamodb_client.get_paginator('scan')
            rule_details = paginator.paginate(
                TableName='Config-Master',
                Select='SPECIFIC_ATTRIBUTES',
                ExpressionAttributeNames = {"#R" : "RuleId", "#EF" : "ExceptionFormat", "#ET" : "ExceptionType", "#RN" : "RuleName"},
                ExpressionAttributeValues={
                    ":rule_name":{"S" : temp_dict['configRuleName']}
                },
                ProjectionExpression='#R,#EF,#ET,#RN',
                FilterExpression= '#RN = :rule_name'
            ).build_full_result()

            rule_id = rule_details['Items'][0]['RuleId']['N']
            exception_format = rule_details['Items'][0]['ExceptionFormat']['S']
            exception_type = rule_details['Items'][0]['ExceptionType']['S']

            logger.info(f"Config Rule details from Config-Master table: Rule ID = {rule_id} Exception_Format = {exception_format} Exception_Type = {exception_type}") 
          
            # run in target account
            session = assume_role(temp_dict['awsAccountId'], 'VA-Role-Config-Mgmt')
            config_client = session.client('config', region_name=temp_dict['awsRegion'])
            config_response = config_client.list_discovered_resources(
                resourceType=temp_dict['resourceType'],
                resourceIds=[
                    temp_dict['resourceId'],
                ],
                includeDeletedResources=True
            )
            config_response['resourceIdentifiers'][event['Records'].index(data)].update({'configRuleId' : rule_id, 'awsAccountId' : temp_dict['awsAccountId'], 'awsRegion' : temp_dict['awsRegion'], 'exceptionFormat' : exception_format, 'exceptionType' : exception_type})

            filtered_resources = filter_deleted_resource_list(config_response)

        ttl_in_minutes = int(os.environ['EXPIRATION_TIME'])
        desired_time = get_desired_time(ttl_in_minutes)
        update_exception_table(filtered_resources, desired_time)
        logger.info("UPDATE COMPLETED!")

    except Exception as error:
        logging.error(f"{error}")