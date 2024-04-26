import boto3
import simplejson as json

table = boto3.resource('dynamodb').Table('Visits')

def lambda_handler(event, context):   
    response = table.update_item(
        Key={
            'Id': 'cv'
        },
        UpdateExpression='ADD VisitTotal :inc',
        ExpressionAttributeValues={
            ':inc': 1
        }
    )

    response = table.get_item(
        Key={
            'Id': 'cv'
        }
    )
    
    return {
        'statusCode': 200,
        'headers': {
            'Content-Type': 'application/json'
        },
        'body': json.dumps(response['Item'])
    }
