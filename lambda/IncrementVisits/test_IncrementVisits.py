
from moto import mock_aws
import boto3
import unittest
from IncrementVisits import lambda_handler


class Test_IncrementVisits(unittest.TestCase):

    @mock_aws
    def test_lambda_handler_success(self):
        boto3.client('dynamodb', region_name='eu-west-2').create_table(
            AttributeDefinitions=[
                {
                    'AttributeName': 'Id',
                    'AttributeType': 'S'
                },
            ],
            TableName='Visits',
            KeySchema=[
                {
                    'AttributeName': 'Id',
                    'KeyType': 'HASH'
                },
            ],
            BillingMode='PAY_PER_REQUEST'
        )

        event = {}
        context = {}

        # Invoke lambda_handler
        response = lambda_handler(event, context)

        # Check response 1
        self.assertEqual(response['statusCode'], 200)
        self.assertEqual(response['body'], '{"Id": "cv", "VisitTotal": 1}')

        # Invoke lambda_handler
        response = lambda_handler(event, context)

        # Check response 2
        self.assertEqual(response['statusCode'], 200)
        self.assertEqual(response['body'], '{"Id": "cv", "VisitTotal": 2}')

    @mock_aws
    def test_lambda_handler_error(self):
        event = {}
        context = {}

        # Invoke lambda_handler without DynamoDB Table
        response = lambda_handler(event, context)
        print(response)

        self.assertEqual(response['statusCode'], 500)
        self.assertIn('error', response['body'])
