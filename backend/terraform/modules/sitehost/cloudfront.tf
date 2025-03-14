// Cloudfront distribution using s3 bucket as its origin
resource "aws_cloudfront_distribution" "s3_distribution" {
  origin {
    s3_origin_config {
      origin_access_identity = aws_cloudfront_origin_access_identity.frontend.cloudfront_access_identity_path
    }
    domain_name = aws_s3_bucket.frontend.bucket_regional_domain_name
    origin_id   = "${local.bucketname}-origin"
  }

  enabled             = true
  is_ipv6_enabled     = true
  comment             = "Relaysecret frontend cloudfront distribution"
  default_root_object = "index.html"

  aliases = [var.domain]

  default_cache_behavior {
    allowed_methods  = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods   = ["GET","HEAD"]
    target_origin_id =  "${local.bucketname}-origin"
    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
    }

    viewer_protocol_policy = "redirect-to-https"
    min_ttl                = 0
    default_ttl            = 0
    max_ttl                = 0
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    acm_certificate_arn = aws_acm_certificate.cert.arn
    ssl_support_method = "sni-only"
    minimum_protocol_version = "TLSv1.2_2019"
  }
}

// To lock down an S3 bucket and only allow users to access its object via cloudfront distribution, we need
// a cloudfront origin access identity for S3 bucket policy.
resource "aws_cloudfront_origin_access_identity" "frontend" {
  comment = "RelaySecret component"
}

provider "aws" {
  # us-east-1 instance
  region = "us-east-1"
  alias = "east1"
}

// If we are using ACM certificate for Cloudfront, only certificates generate & store in us-east-1 can be loaded into cloudfront.
resource "aws_acm_certificate" "cert" {
  domain_name       = var.domain
  validation_method = "DNS"
  lifecycle {
    create_before_destroy = true
  }
  provider = aws.east1
}