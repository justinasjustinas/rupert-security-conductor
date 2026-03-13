output "cloud_run_service_url" {
  description = "URL of the Cloud Run service"
  value       = google_cloud_run_service.security_conductor.status[0].url
}

output "artifact_registry_repository" {
  description = "Artifact Registry repository for Docker images"
  value       = "${var.gcp_region}-docker.pkg.dev/${var.gcp_project_id}/${data.google_artifact_registry_repository.docker_repo.repository_id}"
}

output "service_account_email" {
  description = "Email of the Cloud Run service account"
  value       = data.google_service_account.cloud_run.email
}

output "gemini_secret_id" {
  description = "Secret Manager secret ID for Gemini API key"
  value       = data.google_secret_manager_secret.gemini_api_key.secret_id
}
