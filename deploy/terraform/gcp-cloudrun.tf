resource "google_cloud_run_v2_service" "aegis" {
  name     = "aegis-kernel"
  location = "us-central1"

  template {
    containers {
      image = "gcr.io/my-project/aegis-kernel:latest"
      ports {
        container_port = 8080
      }
      env {
        name  = "ENV"
        value = "production"
      }
    }
    vpc_access {
      connector = var.vpc_connector
      egress    = "ALL_TRAFFIC"
    }
  }
}
