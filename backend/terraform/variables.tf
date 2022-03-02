
variable "accountids" {
  type = list(string)
}

variable "deploymentname" {
  type        = string
  description = "Unique name for the given deployment."
}

variable "APPURL" {
  type        = string
  default     = "devmode"
  description = "Expected referer or 'devmode' to skip referer check."
}

variable "VTAPIKEY" {
  type        = string
  default     = "none"
  description = "VirusTotal API key or 'none' to skip virus checks."
}

variable "SLACK_SIGNING_SECRET" {
  type        = string
  default     = "none"
  description = "Slack app signing secret for verifying sharing requests."
}

variable "HMACSECRET"{
  type        = string
  default     = "none"
  description = "HMAC secret key for validating timestamps or 'none' to skip expiration checks."
}

variable "domain" {
  type        = string
  description = "Domain to host the frontend via Cloudfront."
}