import boto3
import simplejson as json
from botocore.exceptions import ClientError

table = boto3.resource('dynamodb').Table('Visits')


def lambda_handler(event, context):

    try:
        # Attempt to update the item
        table.update_item(
            Key={
                'Id': 'cv'
            },
            UpdateExpression='ADD VisitTotal :inc',
            ExpressionAttributeValues={
                ':inc': 1
            }
        )

        # Attempt to get the item
        response = table.get_item(
            Key={
                'Id': 'cv'
            }
        )

        # Return the response
        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'application/json'
            },
            'body': json.dumps(response['Item'])
        }

    except ClientError as e:
        # If an error occurs, return an error response
        error_message = f"An error occurred: {
            e.response['Error']['Message']
        }"
        return {
            'statusCode': 500,
            'headers': {
                'Content-Type': 'application/json'
            },
            'body': json.dumps({'error': error_message})
        }
