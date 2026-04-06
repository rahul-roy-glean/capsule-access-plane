# ── GCP / Cluster ─────────────────────────────────────────────────────────────

variable "project_id" {
  description = "GCP project ID"
  type        = string
}

variable "region" {
  description = "GCP region"
  type        = string
}

variable "gke_cluster_name" {
  description = "Name of the existing GKE cluster"
  type        = string
}

variable "gke_location" {
  description = "Zone or region of the GKE cluster"
  type        = string
}

# ── Image ─────────────────────────────────────────────────────────────────────

variable "image_repository" {
  description = "Container image repository (e.g. us-docker.pkg.dev/my-project/capsule/access-plane)"
  type        = string
}

variable "image_tag" {
  description = "Container image tag"
  type        = string
  default     = "latest"
}

# ── Namespace ─────────────────────────────────────────────────────────────────

variable "namespace" {
  description = "Kubernetes namespace for the access plane"
  type        = string
  default     = "access-plane"
}

# ── Secrets ───────────────────────────────────────────────────────────────────

variable "attestation_secret" {
  description = "Shared HMAC secret for runner attestation token verification"
  type        = string
  sensitive   = true
}

# ── Application config ────────────────────────────────────────────────────────

variable "providers_config" {
  description = "JSON string of provider configurations (optional). Mounted as /etc/access-plane/providers.json"
  type        = string
  default     = ""
}

variable "credential_ref" {
  description = "Default credential reference (e.g. env:GITHUB_TOKEN)"
  type        = string
  default     = ""
}

variable "tenant_id" {
  description = "Optional tenant ID for multi-tenant scoping"
  type        = string
  default     = ""
}

variable "extra_env" {
  description = "Extra environment variables to set on the container (map of name → value)"
  type        = map(string)
  default     = {}
}

# ── Networking ────────────────────────────────────────────────────────────────

variable "enable_connect_proxy" {
  description = "Enable the CONNECT proxy on port 3128"
  type        = bool
  default     = false
}

# ── Scaling & resources ───────────────────────────────────────────────────────

variable "replicas" {
  description = "Number of deployment replicas"
  type        = number
  default     = 1
}

variable "resources_requests_cpu" {
  description = "CPU request"
  type        = string
  default     = "100m"
}

variable "resources_requests_memory" {
  description = "Memory request"
  type        = string
  default     = "128Mi"
}

variable "resources_limits_cpu" {
  description = "CPU limit"
  type        = string
  default     = "500m"
}

variable "resources_limits_memory" {
  description = "Memory limit"
  type        = string
  default     = "512Mi"
}

# ── Storage ───────────────────────────────────────────────────────────────────

variable "disk_size" {
  description = "PVC size for SQLite database"
  type        = string
  default     = "10Gi"
}

variable "create_gcp_service_account" {
  description = "Create a dedicated GCP service account for the access plane with Workload Identity"
  type        = bool
  default     = true
}

variable "gcp_service_account_id" {
  description = "GCP service account ID (e.g. capsule-dev-access-plane). Only used when create_gcp_service_account=true."
  type        = string
  default     = "capsule-access-plane"
}

variable "token_creator_on_self" {
  description = "Grant the access plane SA roles/iam.serviceAccountTokenCreator on itself (required for gcp-sa provider)"
  type        = bool
  default     = true
}
