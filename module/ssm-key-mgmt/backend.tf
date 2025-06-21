terraform {
  backend "s3" {
    bucket         = ""
    key            = "ssh-key-mgmt/terraform.tfstate"
    region         = "eu-north-1"
    dynamodb_table = "terraform-locks"
    
  }
}