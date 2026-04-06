resource "kubernetes_persistent_volume_claim" "access_plane_data" {
  wait_until_bound = false

  metadata {
    name      = "access-plane-data"
    namespace = kubernetes_namespace.access_plane.metadata[0].name
  }

  spec {
    access_modes = ["ReadWriteOnce"]

    resources {
      requests = {
        storage = var.disk_size
      }
    }
  }
}

resource "kubernetes_deployment" "access_plane" {
  metadata {
    name      = "access-plane"
    namespace = kubernetes_namespace.access_plane.metadata[0].name
    labels    = local.labels
  }

  spec {
    replicas = var.replicas

    selector {
      match_labels = {
        "app.kubernetes.io/name" = "access-plane"
      }
    }

    strategy {
      type = "Recreate"
    }

    template {
      metadata {
        labels = local.labels
      }

      spec {
        service_account_name = kubernetes_service_account.access_plane.metadata[0].name

        container {
          name  = "access-plane"
          image = "${var.image_repository}:${var.image_tag}"

          port {
            name           = "http"
            container_port = 8080
          }

          dynamic "port" {
            for_each = var.enable_connect_proxy ? [1] : []
            content {
              name           = "proxy"
              container_port = 3128
            }
          }

          env {
            name  = "LISTEN_ADDR"
            value = ":8080"
          }

          env {
            name  = "DATABASE_URL"
            value = "/data/capsule-access.db"
          }

          env {
            name = "ATTESTATION_SECRET"
            value_from {
              secret_key_ref {
                name = kubernetes_secret.access_plane.metadata[0].name
                key  = "ATTESTATION_SECRET"
              }
            }
          }

          dynamic "env" {
            for_each = var.enable_connect_proxy ? [":3128"] : []
            content {
              name  = "PROXY_ADDR"
              value = env.value
            }
          }

          dynamic "env" {
            for_each = var.credential_ref != "" ? [var.credential_ref] : []
            content {
              name  = "CREDENTIAL_REF"
              value = env.value
            }
          }

          dynamic "env" {
            for_each = var.tenant_id != "" ? [var.tenant_id] : []
            content {
              name  = "TENANT_ID"
              value = env.value
            }
          }

          dynamic "env" {
            for_each = var.providers_config != "" ? ["/etc/access-plane/providers.json"] : []
            content {
              name  = "PROVIDERS_CONFIG"
              value = env.value
            }
          }

          dynamic "env" {
            for_each = var.extra_env
            content {
              name  = env.key
              value = env.value
            }
          }

          resources {
            requests = {
              cpu    = var.resources_requests_cpu
              memory = var.resources_requests_memory
            }
            limits = {
              cpu    = var.resources_limits_cpu
              memory = var.resources_limits_memory
            }
          }

          volume_mount {
            name       = "data"
            mount_path = "/data"
          }

          dynamic "volume_mount" {
            for_each = var.providers_config != "" ? [1] : []
            content {
              name       = "config"
              mount_path = "/etc/access-plane"
              read_only  = true
            }
          }

          liveness_probe {
            http_get {
              path = "/healthz"
              port = 8080
            }
            initial_delay_seconds = 5
            period_seconds        = 10
          }

          readiness_probe {
            http_get {
              path = "/healthz"
              port = 8080
            }
            initial_delay_seconds = 3
            period_seconds        = 5
          }
        }

        volume {
          name = "data"
          persistent_volume_claim {
            claim_name = kubernetes_persistent_volume_claim.access_plane_data.metadata[0].name
          }
        }

        dynamic "volume" {
          for_each = var.providers_config != "" ? [1] : []
          content {
            name = "config"
            config_map {
              name = kubernetes_config_map.access_plane[0].metadata[0].name
            }
          }
        }
      }
    }
  }
}
