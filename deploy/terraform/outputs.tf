output "internal_lb_ip" {
  description = "Internal load balancer IP address"
  value       = kubernetes_service.access_plane.status[0].load_balancer[0].ingress[0].ip
}

output "service_endpoint" {
  description = "Access plane API endpoint (IP:port)"
  value       = "${kubernetes_service.access_plane.status[0].load_balancer[0].ingress[0].ip}:8080"
}

output "proxy_endpoint" {
  description = "CONNECT proxy endpoint (empty if disabled)"
  value       = var.enable_connect_proxy ? "${kubernetes_service.access_plane.status[0].load_balancer[0].ingress[0].ip}:3128" : ""
}

output "namespace" {
  description = "Kubernetes namespace"
  value       = kubernetes_namespace.access_plane.metadata[0].name
}

output "gcp_service_account_email" {
  description = "GCP service account email for the access plane (empty if not created)"
  value       = var.create_gcp_service_account ? google_service_account.access_plane[0].email : ""
}
