variable "bucket" {
  type    = string
  default = "terraform-state"
}

variable "key" {
  type    = string
  default = "terraform.tfstate"
}

variable "dynamodb_table" {
  type    = string
  default = "terraform-state"
}

variable "region" {
  type    = string
  default = "eu-west-2"
}