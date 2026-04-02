# GCP service account for the access plane.
# Uses Workload Identity to bind the K8s SA to the GCP SA.
resource "google_service_account" "access_plane" {
  count        = var.create_gcp_service_account ? 1 : 0
  account_id   = var.gcp_service_account_id
  display_name = "Access Plane"
  description  = "Service account for the Capsule access plane (credential injection, GCP token minting)"
  project      = var.project_id
}

# Allow the K8s SA (via Workload Identity) to impersonate the GCP SA.
resource "google_service_account_iam_member" "workload_identity" {
  count              = var.create_gcp_service_account ? 1 : 0
  service_account_id = google_service_account.access_plane[0].name
  role               = "roles/iam.workloadIdentityUser"
  member             = "serviceAccount:${var.project_id}.svc.id.goog[${var.namespace}/access-plane]"
}

# Allow the access plane SA to mint tokens for itself (gcp-sa provider needs
# generateAccessToken on the SA it impersonates — for simple setups the access
# plane impersonates itself).
resource "google_service_account_iam_member" "token_creator_self" {
  count              = var.create_gcp_service_account && var.token_creator_on_self ? 1 : 0
  service_account_id = google_service_account.access_plane[0].name
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = "serviceAccount:${google_service_account.access_plane[0].email}"
}

# K8s service account with Workload Identity annotation.
resource "kubernetes_service_account" "access_plane" {
  metadata {
    name      = "access-plane"
    namespace = kubernetes_namespace.access_plane.metadata[0].name

    annotations = var.create_gcp_service_account ? {
      "iam.gke.io/gcp-service-account" = google_service_account.access_plane[0].email
    } : {}

    labels = local.labels
  }
}
