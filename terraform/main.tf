resource "aws_kms_key" "backend_cv" {
  description             = "backend_cv"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  policy = <<POLICY
  {
    "Version": "2012-10-17",
    "Id": "default",
    "Statement": [
      {
        "Effect": "Allow",
        "Principal": {
          "AWS": "arn:aws:iam::${var.aws_account}:root"
        },
        "Action": "kms:*",
        "Resource": "*"
      },
      {
        "Effect": "Allow",
        "Principal": {
          "AWS": "arn:aws:iam::${var.aws_account}:user/terraform"
        },
        "Action": "kms:*",
        "Resource": "*"
      },
      {
        "Effect": "Allow",
        "Principal": {
          "AWS": "arn:aws:iam::${var.aws_account}:role/GitHubActionsTerraformRole" 
        },
        "Action": "kms:*",
        "Resource": "*"
      },
      {
        "Effect": "Allow",
        "Principal": {
          "Service": "logs.${var.region}.amazonaws.com" 
        },
        "Action": [
            "kms:Encrypt*",
            "kms:Decrypt*",
            "kms:ReEncrypt*",
            "kms:GenerateDataKey*",
            "kms:Describe*"
        ],
        "Resource": "*"
      }     
    ]
  }
POLICY
}

# Create DynamoDB table Visits
resource "aws_dynamodb_table" "visits" {
  name         = "Visits"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "Id"

  attribute {
    name = "Id"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.backend_cv.arn
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

  statement {
    effect = "Allow"

    actions = [
      "kms:Decrypt"
    ]

    resources = [
      "${aws_kms_key.backend_cv.arn}"
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
  source_file = "${path.module}/../lambda/IncrementVisits/IncrementVisits.py"
  output_path = "${path.module}/../lambda/IncrementVisits/IncrementVisits_payload.zip"
}

resource "aws_s3_bucket" "code_signing" {
  #checkov:skip=CKV_AWS_144:Cross-region replication not required for code-signing bucket.
  #checkov:skip=CKV_AWS_18:Access logging not required for code-signing bucket.
  #checkov:skip=CKV2_AWS_62:Event notifications not required for code-signing bucket.
  #checkov:skip=CKV2_AWS_61:Lifecycle configuration not required for code-signing bucket.
  bucket = var.code_signing_bucket

  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "code_signing" {
  bucket                  = aws_s3_bucket.code_signing.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "code_signing_versioning" {
  bucket = aws_s3_bucket.code_signing.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_object_lock_configuration" "code_signing_object_lock" {
  bucket = aws_s3_bucket.code_signing.id

  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = 5
    }
  }

  depends_on = [
    aws_s3_bucket_versioning.code_signing_versioning
  ]
}

resource "aws_s3_bucket_server_side_encryption_configuration" "code_signing_encryption" {
  bucket = aws_s3_bucket.code_signing.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.backend_cv.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_object" "lambda_incrementvisits_payload" {
  bucket = aws_s3_bucket.code_signing.id
  key    = "unsigned/IncrementVisits_payload.zip"
  source = data.archive_file.lambda_incrementvisits_payload.output_path
}

resource "aws_signer_signing_profile" "code_signing" {
  platform_id = "AWSLambda-SHA384-ECDSA"
}

resource "aws_signer_signing_job" "code_signing" {
  profile_name = aws_signer_signing_profile.code_signing.name

  source {
    s3 {
      bucket  = aws_s3_bucket.code_signing.id
      key     = aws_s3_object.lambda_incrementvisits_payload.id
      version = aws_s3_object.lambda_incrementvisits_payload.version_id
    }
  }

  destination {
    s3 {
      bucket = aws_s3_bucket.code_signing.id
      prefix = "signed/"
    }
  }

  ignore_signing_job_failure = true
}

locals {
  signed_bucket = aws_signer_signing_job.code_signing.signed_object[0]["s3"][0]["bucket"]
  signed_key    = aws_signer_signing_job.code_signing.signed_object[0]["s3"][0]["key"]
}

data "aws_s3_object" "signed_object" {
  bucket = local.signed_bucket
  key    = local.signed_key
}

resource "aws_lambda_code_signing_config" "code_signing" {
  allowed_publishers {
    signing_profile_version_arns = [aws_signer_signing_profile.code_signing.version_arn]
  }

  policies {
    untrusted_artifact_on_deployment = "Enforce"
  }
}

# Create Lambda function from Python archive
resource "aws_lambda_function" "IncrementVisits" {
  #checkov:skip=CKV_AWS_117:Lambda requires no access to VPC resources.
  #checkov:skip=CKV_AWS_116:Dead Letter Queue (DLQ) not required for this Lambda function.
  s3_bucket         = local.signed_bucket
  s3_key            = local.signed_key
  s3_object_version = data.aws_s3_object.signed_object.version_id

  function_name = "IncrementVisits"
  role          = aws_iam_role.LambdaAssumeRole.arn
  handler       = "IncrementVisits.lambda_handler"

  reserved_concurrent_executions = -1

  runtime = "python3.12"

  code_signing_config_arn = aws_lambda_code_signing_config.code_signing.arn

  tracing_config {
    mode = "Active"
  }
}

# Request certificate from ACM to be used as Custom Domain with API Gateway
resource "aws_acm_certificate" "api_request" {
  domain_name       = "api.cv.benjamesdodwell.com"
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }
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

resource "aws_cloudwatch_log_group" "api_cv_benjamesdodwell_com" {
  name              = "api_cv_benjamesdodwell_com"
  kms_key_id        = aws_kms_key.backend_cv.arn
  retention_in_days = 365
}

# Create API Gateway (HTTP) Stage
resource "aws_apigatewayv2_stage" "prod" {
  api_id      = aws_apigatewayv2_api.lambda_incrementvisits.id
  name        = "prod"
  auto_deploy = true

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.api_cv_benjamesdodwell_com.arn
    format          = "$context.identity.sourceIp,$context.identity.caller,$context.identity.user,$context.requestTime,$context.httpMethod,$context.resourcePath,$context.protocol,$context.status,$context.responseLength,$context.requestId,$context.extendedRequestId"
  }
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
  #checkov:skip=CKV_AWS_309:Authorisation not required for route.
  api_id = aws_apigatewayv2_api.lambda_incrementvisits.id

  route_key = "GET /IncrementVisits"
  target    = "integrations/${aws_apigatewayv2_integration.api_IncrementVisits.id}"
}
