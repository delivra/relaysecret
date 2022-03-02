variable "deploymentname" {
  type = string
}

variable "envvar" {
  type    = map(string)
  default = {}
}