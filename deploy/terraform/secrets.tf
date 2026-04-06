resource "kubernetes_secret" "access_plane" {
  metadata {
    name      = "access-plane-secrets"
    namespace = kubernetes_namespace.access_plane.metadata[0].name
  }

  data = {
    ATTESTATION_SECRET = var.attestation_secret
  }
}
