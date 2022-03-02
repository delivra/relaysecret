variable "deploymentname" {
  type = string
}

variable "domain" {
  type = string
}

variable "lambdaurl" {
  type        = string
  description = "Backend invoke_url for API gateway"
}