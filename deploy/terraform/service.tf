resource "kubernetes_service" "access_plane" {
  metadata {
    name      = "access-plane"
    namespace = kubernetes_namespace.access_plane.metadata[0].name
    labels    = local.labels

    annotations = {
      "networking.gke.io/load-balancer-type" = "Internal"
    }
  }

  spec {
    type = "LoadBalancer"

    selector = {
      "app.kubernetes.io/name" = "access-plane"
    }

    port {
      name        = "http"
      port        = 8080
      target_port = "http"
      protocol    = "TCP"
    }

    dynamic "port" {
      for_each = var.enable_connect_proxy ? [1] : []
      content {
        name        = "proxy"
        port        = 3128
        target_port = "proxy"
        protocol    = "TCP"
      }
    }
  }
}
