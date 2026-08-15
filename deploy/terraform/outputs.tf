output "ecs_cluster_name" {
  value = aws_ecs_cluster.aegis.name
}

output "cloud_run_url" {
  value = google_cloud_run_v2_service.aegis.uri
}
