terraform {
  backend "s3" {
    bucket         = "my-terraform-state-bucket"
    key            = "ssh-key-mgmt/terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "terraform-locks"
    
  }
}