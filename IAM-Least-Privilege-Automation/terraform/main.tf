data "aws_iam_role" "overprivileged" {
  name = "your-role-name"
}

resource "aws_iam_policy" "least_privilege" {
  name        = "least-privilege-policy"
  description = "Narrow policy generated from CloudTrail analysis."

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowS3ReadOnly"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListBucket",
          "s3:GetBucketLocation"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "attach_least_privilege" {
  role       = data.aws_iam_role.overprivileged.name
  policy_arn = aws_iam_policy.least_privilege.arn
}
