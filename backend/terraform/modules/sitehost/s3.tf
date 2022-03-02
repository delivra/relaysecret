locals {
  bucketname    = "relaysecret-${var.deploymentname}-frontend"
  frontend_path = abspath("${path.module}/../../../../frontend/")

  mime_types = {
    ".htm" = "text/html"
    ".html" = "text/html"
    ".js" = "text/javascript"
    ".css" = "text/css"
    ".woff" = "font/woff"
    ".woff2" = "font/woff2"
    ".png" = "image/png"
    ".gif" = "image/gif"
    ".svg" = "image/svg+xml"
    ".ico" = "image/x-icon"
  }
}

resource "aws_s3_bucket" "frontend" {
  bucket = local.bucketname
  acl    = "private"
}

// Using cloudfront origin access identity, we can lock down our bucket and allow
// users access objects via Cloudfront but not directly.
data "aws_iam_policy_document" "frontend" {
  statement {
    sid = "AllowCloudFront"
    actions = [
      "s3:GetObject",
      "s3:ListBucket"
    ]
    resources = [
      aws_s3_bucket.frontend.arn,
      "${aws_s3_bucket.frontend.arn}/*"
    ]
    principals {
      type = "AWS"
      identifiers = [
        aws_cloudfront_origin_access_identity.frontend.iam_arn,
      ]
    }
  }
}

resource "aws_s3_bucket_policy" "frontend" {
  bucket = aws_s3_bucket.frontend.id
  policy = data.aws_iam_policy_document.frontend.json
}

resource "aws_s3_bucket_object" "resources" {
  for_each = fileset(local.frontend_path, "/**/*.*")

  bucket                 = aws_s3_bucket.frontend.bucket
  key                    = each.value
  source                 = "${local.frontend_path}/${each.value}"
  content_type           = lookup(local.mime_types, regex("\\.[^.]+$", each.value), null)
  etag                   = filemd5("${local.frontend_path}/${each.value}")
  server_side_encryption = "AES256"
}

#Generate config dynamically to point to API gateway in backend
resource "aws_s3_bucket_object" "config" {
  bucket       = aws_s3_bucket.frontend.bucket
  key          = "assets/config.js"
  content_type = lookup(local.mime_types, ".js", null)

  content = <<EOF
// Change to your lambda endpoint here
var lambdaurl = '${var.lambdaurl}/';
EOF

  server_side_encryption = "AES256"
}