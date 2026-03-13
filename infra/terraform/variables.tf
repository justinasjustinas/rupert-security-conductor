variable "gcp_project_id" {
  description = "GCP Project ID"
  type        = string
}

variable "gcp_region" {
  description = "GCP region for Cloud Run deployment"
  type        = string
  default     = "eu-west1"
}

variable "cloud_run_service_name" {
  description = "Name of the Cloud Run service"
  type        = string
  default     = "rupert-security-conductor"
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
