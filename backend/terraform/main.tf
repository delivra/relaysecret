provider "aws" {
  region              = "us-west-1"
  allowed_account_ids = var.accountids
}

module "relaysecret" {
  source             = "./modules/relaysecret"
  deploymentname     = var.deploymentname

  envvar = {
    "APP_DOMAIN"           = var.domain
    "APPURL"               = var.APPURL
    "VTAPIKEY"             = var.VTAPIKEY
    "SLACK_SIGNING_SECRET" = var.SLACK_SIGNING_SECRET
    "HMACSECRET"           = var.HMACSECRET
  }
}

module "frontend" {
  source             = "./modules/sitehost"
  deploymentname     = var.deploymentname
  domain             = var.domain
  lambdaurl          = module.relaysecret.base_url
}

output "base_url" {
  value = module.relaysecret.base_url
}
