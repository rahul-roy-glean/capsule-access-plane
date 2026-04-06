resource "kubernetes_config_map" "access_plane" {
  count = var.providers_config != "" ? 1 : 0

  metadata {
    name      = "access-plane-config"
    namespace = kubernetes_namespace.access_plane.metadata[0].name
  }

  data = {
    "providers.json" = var.providers_config
  }
}
