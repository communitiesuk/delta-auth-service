variable "default_tags" {
  type = map(string)
  default = {
    project           = "Data Collection Service"
    business-unit     = "Digital Delivery"
    technical-contact = "Team-DLUHC@softwire.com"
    environment       = "test"
    repository        = "https://github.com/communitiesuk/delta-auth-service"
  }
}

variable "image_tag" {
  type = string
}
