# Backend Infrastructure as Code (IaC)

Provision and configure backend infrastructure used by https://cv.benjamesdodwell.com

## Requirements

- [Terraform](https://developer.hashicorp.com/terraform/install)
- [AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html)

## Usage

Configure an AWS IAM account with appropriate permissions and an access key to be used by Terraform:

https://registry.terraform.io/providers/hashicorp/aws/latest/docs#authentication-and-configuration

Configure AWS CLI with the access key:
```sh
aws cli configure
```

Run the Terraform module:
```sh
terraform init -backend-config="backend.tfvars"
terraform apply
```