output "cloud_run_service_url" {
  description = "URL of the Cloud Run service"
  value       = google_cloud_run_service.security_conductor.status[0].url
}

output "artifact_registry_repository" {
  description = "Artifact Registry repository for Docker images"
  value       = "${var.gcp_region}-docker.pkg.dev/${var.gcp_project_id}/${google_artifact_registry_repository.docker_repo.repository_id}"
}

output "service_account_email" {
  description = "Email of the Cloud Run service account"
  value       = google_service_account.cloud_run.email
}

output "gemini_secret_id" {
  description = "Secret Manager secret ID for Gemini API key"
  value       = google_secret_manager_secret.gemini_api_key.secret_id
}

output "github_actions_service_account_email" {
  description = "Email of the GitHub Actions deployer service account"
  value       = local.github_actions_enabled ? google_service_account.github_actions[0].email : null
}

output "github_workload_identity_provider" {
  description = "Full resource name for the GitHub Actions Workload Identity Provider"
  value       = local.github_actions_enabled ? google_iam_workload_identity_pool_provider.github_actions[0].name : null
}

output "github_repository_subject" {
  description = "GitHub repository allowed to federate into Google Cloud"
  value       = local.github_actions_enabled ? local.github_repository : null
}
