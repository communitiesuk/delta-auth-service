variable "default_tags" {
  type = map(string)
  default = {
    project           = "Data Collection Service"
    business-unit     = "Digital Delivery"
    technical-contact = "delta-notifications@communities.gov.uk"
    environment       = "staging"
    repository        = "https://github.com/communitiesuk/delta-auth-service"
  }
}

variable "image_tag" {
  description = "Tag of docker image to deploy to ECS, usually release-x.y"
  type        = string
}
