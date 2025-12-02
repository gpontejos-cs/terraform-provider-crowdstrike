terraform {
  required_providers {
    crowdstrike = {
      source = "registry.terraform.io/crowdstrike/crowdstrike"
    }
  }
}

provider "crowdstrike" {
  cloud = "us-2"
}


resource "crowdstrike_cloud_security_suppression_rule" "example" {
  name                = "Suppression Rule"
  domain              = "CSPM"
  subdomain           = "IOM"
  rule_selection_type = "rule_selection_filter"
  scope_type          = "asset_filter"
  suppression_reason  = "Temporary Suppression"
  rule_selection_filter {
    rule_names = ["IAM root user has an active access key"]
  }
  scope_asset_filter {
    regions = ["us-east-2"]
  }
}

output "suppression_rule" {
  value = crowdstrike_cloud_security_suppression_rule.example
}
