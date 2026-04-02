resource "kubernetes_namespace" "access_plane" {
  metadata {
    name = var.namespace

    labels = local.labels
  }
}
