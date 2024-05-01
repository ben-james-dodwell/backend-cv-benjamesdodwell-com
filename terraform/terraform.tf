terraform {
  backend "s3" {
    bucket          = "cv-benjamesdodwell-com-terraform"
    key             = "backend/terraform.tfstate"
    region          = "eu-west-2"
    dynamodb_table  = "cv-benjamesdodwell-com-terraform"
  }

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "= 5.46.0"
    }
  }

  required_version = ">= 1.8.2"
}