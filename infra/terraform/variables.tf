variable "gcp_project_id" {
  description = "GCP Project ID"
  type        = string
}

variable "gcp_region" {
  description = "GCP region for Cloud Run deployment (use full region names like europe-west1, us-central1, etc.)"
  type        = string
  default     = "europe-west1"
}

variable "cloud_run_service_name" {
  description = "Name of the Cloud Run service"
  type        = string
  default     = "rupert-security-conductor"
}

variable "cloud_run_service_account_id" {
  description = "Account ID for the Cloud Run runtime service account"
  type        = string
  default     = "rupert-security-conductor"
}

variable "github_actions_service_account_id" {
  description = "Account ID for the GitHub Actions deployer service account"
  type        = string
  default     = "rupert-github-actions"
}

variable "github_workload_identity_pool_id" {
  description = "Workload Identity Pool ID for GitHub Actions"
  type        = string
  default     = "github-actions"
}

variable "github_workload_identity_provider_id" {
  description = "Workload Identity Provider ID for GitHub Actions"
  type        = string
  default     = "github-provider"
}

variable "github_repository_owner" {
  description = "GitHub repository owner or organization for CI/CD federation"
  type        = string
  default     = ""
}

variable "github_repository_name" {
  description = "GitHub repository name for CI/CD federation"
  type        = string
  default     = ""
}

variable "artifact_registry_repo" {
  description = "Artifact Registry repository name"
  type        = string
  default     = "security-conductor"
}

variable "docker_image_name" {
  description = "Docker image name"
  type        = string
  default     = "security-conductor"
}

variable "docker_image_tag" {
  description = "Docker image tag"
  type        = string
  default     = "latest"
}

variable "cloud_run_memory" {
  description = "Memory allocation for Cloud Run (hobby tier: 512Mi is free)"
  type        = string
  default     = "512Mi"
}

variable "cloud_run_cpu" {
  description = "CPU allocation for Cloud Run"
  type        = string
  default     = "0.5"
}

variable "cloud_run_timeout" {
  description = "Request timeout for Cloud Run in seconds"
  type        = number
  default     = 300
}

variable "cloud_run_max_instances" {
  description = "Maximum number of Cloud Run instances"
  type        = number
  default     = 10
}

# ============================================================================
# OPTIONAL FEATURE FLAGS
# ============================================================================

variable "enable_github_webhook" {
  description = "Create the GitHub webhook HMAC secret in Secret Manager and wire it to Cloud Run. Set to true when GITHUB_WEBHOOK_SECRET is provided to deploy.sh."
  type        = bool
  default     = false
}

variable "enable_bitbucket_webhook" {
  description = "Create the Bitbucket webhook HMAC secret in Secret Manager and wire it to Cloud Run. Set to true when BITBUCKET_WEBHOOK_SECRET is provided to deploy.sh."
  type        = bool
  default     = false
}

variable "enable_github_token" {
  description = "Create a GitHub API token secret in Secret Manager and wire it to Cloud Run. Required for automatic diff fetching on private repositories."
  type        = bool
  default     = false
}

variable "gcs_bucket_name" {
  description = "GCS bucket name for scan result persistence. If non-empty, the Cloud Run service account is granted objectCreator on the bucket and GCS_BUCKET_NAME is set as an env var."
  type        = string
  default     = ""
}
