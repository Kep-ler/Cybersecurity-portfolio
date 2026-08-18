terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "6.60.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

resource "aws_security_group" "test_sg" {
  name        = "aegis-negative-test"
  description = "Intentionally insecure configuration for Aegis testing"
}

resource "aws_security_group_rule" "bad_ssh" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.test_sg.id
}
