# Create DynamoDB table Visits
resource "aws_dynamodb_table" "visits" {
  name         = "Visits"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "Id"

  attribute {
    name = "Id"
    type = "S"
  }
}

data "aws_iam_policy_document" "assume_role" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"]
  }
}

data "aws_iam_policy_document" "visits_policy" {
  statement {
    effect = "Allow"

    actions = [
      "dynamodb:UpdateItem",
      "dynamodb:GetItem"
    ]

    resources = [
      "${aws_dynamodb_table.visits.arn}"
    ]
  }
}

# Create IAM role for Lambda
resource "aws_iam_role" "LambdaAssumeRole" {
  name               = "LambdaAssumeRole"
  assume_role_policy = data.aws_iam_policy_document.assume_role.json

  inline_policy {
    name   = "policy-visits"
    policy = data.aws_iam_policy_document.visits_policy.json
  }
}

data "archive_file" "lambda_incrementvisits_payload" {
  type        = "zip"
  source_file = "${path.module}/lambda/IncrementVisits/IncrementVisits.py"
  output_path = "${path.module}/lambda/IncrementVisits/IncrementVisits_payload.zip"
}

# Create Lambda function from Python archive
resource "aws_lambda_function" "IncrementVisits" {
  filename      = "${path.module}/lambda/IncrementVisits/IncrementVisits_payload.zip"
  function_name = "IncrementVisits"
  role          = aws_iam_role.LambdaAssumeRole.arn
  handler       = "IncrementVisits.lambda_handler"

  source_code_hash = data.archive_file.lambda_incrementvisits_payload.output_base64sha256

  runtime = "python3.12"
}

# Request certificate from ACM to be used as Custom Domain with API Gateway
resource "aws_acm_certificate" "api_request" {
  domain_name       = "api.cv.benjamesdodwell.com"
  validation_method = "DNS"
}

data "aws_route53_zone" "cv_benjamesdodwell_com" {
  name         = "cv.benjamesdodwell.com."
  private_zone = false
}

# Create DNS records for validation of ACM request
resource "aws_route53_record" "api_validation" {
  for_each = {
    for dvo in aws_acm_certificate.api_request.domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  }

  allow_overwrite = true
  name            = each.value.name
  records         = [each.value.record]
  ttl             = 60
  type            = each.value.type
  zone_id         = data.aws_route53_zone.cv_benjamesdodwell_com.zone_id
}

# Validate ACM request from DNS records
resource "aws_acm_certificate_validation" "api_validated" {
  certificate_arn         = aws_acm_certificate.api_request.arn
  validation_record_fqdns = [for record in aws_route53_record.api_validation : record.fqdn]
}

# Create Custom Domain for API Gateway (HTTP)
resource "aws_apigatewayv2_domain_name" "api_cv_benjamesdodwell_com" {
  domain_name = "api.cv.benjamesdodwell.com"
  domain_name_configuration {
    certificate_arn = aws_acm_certificate_validation.api_validated.certificate_arn
    endpoint_type   = "REGIONAL"
    security_policy = "TLS_1_2"
  }
}

# Create DNS (A) record for API Gateway (HTTP) Custom Domain
resource "aws_route53_record" "api_cv_benjamesdodwell_com_alias" {
  name    = aws_apigatewayv2_domain_name.api_cv_benjamesdodwell_com.domain_name
  type    = "A"
  zone_id = data.aws_route53_zone.cv_benjamesdodwell_com.id

  alias {
    evaluate_target_health = true
    name                   = aws_apigatewayv2_domain_name.api_cv_benjamesdodwell_com.domain_name_configuration[0].target_domain_name
    zone_id                = aws_apigatewayv2_domain_name.api_cv_benjamesdodwell_com.domain_name_configuration[0].hosted_zone_id
  }
}

# Create API Gateway (HTTP) with CORS
resource "aws_apigatewayv2_api" "lambda_incrementvisits" {
  name                         = "Lambda-IncrementVisits"
  protocol_type                = "HTTP"
  disable_execute_api_endpoint = true

  #target = aws_lambda_function.IncrementVisits.arn

  cors_configuration {
    allow_origins = ["https://cv.benjamesdodwell.com"]
    allow_methods = ["GET"]
  }
}

# Create Lambda permissions for API Gateway
resource "aws_lambda_permission" "apigw" {
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.IncrementVisits.arn
  principal     = "apigateway.amazonaws.com"

  source_arn = "${aws_apigatewayv2_api.lambda_incrementvisits.execution_arn}/*/*"
}

# Create API Gateway (HTTP) Stage
resource "aws_apigatewayv2_stage" "prod" {
  api_id      = aws_apigatewayv2_api.lambda_incrementvisits.id
  name        = "prod"
  auto_deploy = true
}

# Create API Gateway (HTTP) mapping to Custom Domain
resource "aws_apigatewayv2_api_mapping" "lambda_incrementvisits_api_cv_benjamesdodwell_com_prod" {
  api_id      = aws_apigatewayv2_api.lambda_incrementvisits.id
  domain_name = aws_apigatewayv2_domain_name.api_cv_benjamesdodwell_com.id
  stage       = aws_apigatewayv2_stage.prod.id
}

# Create API Gateway (HTTP) integration with Lambda function
resource "aws_apigatewayv2_integration" "api_IncrementVisits" {
  api_id = aws_apigatewayv2_api.lambda_incrementvisits.id

  integration_uri    = aws_lambda_function.IncrementVisits.arn
  integration_type   = "AWS_PROXY"
  integration_method = "GET"
}

# Create API Gateway route
resource "aws_apigatewayv2_route" "api-route" {
  api_id = aws_apigatewayv2_api.lambda_incrementvisits.id

  route_key = "GET /IncrementVisits"
  target    = "integrations/${aws_apigatewayv2_integration.api_IncrementVisits.id}"
}