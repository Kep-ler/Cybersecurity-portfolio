terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

resource "aws_security_group" "test_sg" {
  name        = "aegis-ci-test"
  description = "Aegis CI/CD compliant test security group"
}

resource "aws_security_group_rule" "ssh_internal" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = ["10.0.0.0/8"]
  security_group_id = aws_security_group.test_sg.id
}
