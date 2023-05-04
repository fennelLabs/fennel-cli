terraform {
  backend "gcs" {
    bucket      = "whiteflag-0-tfstate"
    prefix      = "terraform/state"
  }
}