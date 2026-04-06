terraform {
  required_version = ">= 1.0.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.0"
    }
  }

  backend "gcs" {
    # Configure via -backend-config flags:
    #   terraform init -backend-config="bucket=my-tf-state" -backend-config="prefix=access-plane"
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

data "google_client_config" "default" {}

data "google_container_cluster" "cluster" {
  name     = var.gke_cluster_name
  location = var.gke_location
  project  = var.project_id
}

provider "kubernetes" {
  host                   = "https://${data.google_container_cluster.cluster.endpoint}"
  token                  = data.google_client_config.default.access_token
  cluster_ca_certificate = base64decode(data.google_container_cluster.cluster.master_auth[0].cluster_ca_certificate)
}

locals {
  labels = {
    "app.kubernetes.io/name"       = "access-plane"
    "app.kubernetes.io/managed-by" = "terraform"
  }
}
