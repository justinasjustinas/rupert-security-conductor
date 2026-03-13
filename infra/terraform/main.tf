# Terraform configuration for GCP Cloud Run deployment
# Hobby-tier setup using:
# - Cloud Run (free tier: 180k vCPU-seconds/month)
# - Gemini 1.5 Flash (free tier available)
# - Artifact Registry (free tier)
# - Cloud Logging (free tier: 50GB/month ingestion)

terraform {
  required_version = ">= 1.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }

  # Uncomment to use remote state (requires gs:// bucket)
  # backend "gcs" {
  #   bucket  = "your-terraform-state-bucket"
  #   prefix  = "rupert-security-conductor"
  # }
}

provider "google" {
  project = var.gcp_project_id
  region  = var.gcp_region
}

# ============================================================================
# ARTIFACT REGISTRY: Docker image repository
# ============================================================================

resource "google_artifact_registry_repository" "docker_repo" {
  location      = var.gcp_region
  repository_id = var.artifact_registry_repo
  description   = "Docker repository for Rupert Security Conductor"
  format        = "DOCKER"

  cleanup_policy_if_inactive {
    condition_duration_days = 30
  }
}

# ============================================================================
# SERVICE ACCOUNT: Minimal IAM permissions
# ============================================================================

resource "google_service_account" "cloud_run" {
  account_id   = "rupert-security-conductor"
  display_name = "Rupert Security Conductor Cloud Run Service Account"
  description  = "Service account for Rupert Security Conductor with minimal permissions"
}

# Allow Cloud Run to read from Artifact Registry
resource "google_artifact_registry_repository_iam_member" "cloud_run_reader" {
  location   = google_artifact_registry_repository.docker_repo.location
  repository = google_artifact_registry_repository.docker_repo.repository_id
  role       = "roles/artifactregistry.reader"
  member     = "serviceAccount:${google_service_account.cloud_run.email}"
}

# Allow Cloud Run to access Secret Manager for API keys
resource "google_secret_manager_secret_iam_member" "gemini_api_key" {
  secret_id = google_secret_manager_secret.gemini_api_key.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.cloud_run.email}"
}

# Allow Cloud Run to write logs
resource "google_project_iam_member" "cloud_run_logging" {
  project = var.gcp_project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.cloud_run.email}"
}

# ============================================================================
# SECRETS MANAGER: Gemini API Key
# ============================================================================

resource "google_secret_manager_secret" "gemini_api_key" {
  secret_id = "rupert-gemini-api-key"

  replication {
    automatic = true
  }
}

# NOTE: The secret value must be set manually or via separate process
# terraform apply will NOT set the actual secret value
# Use: gcloud secrets versions add rupert-gemini-api-key --data-file=- <<< "$GEMINI_API_KEY"

# ============================================================================
# CLOUD RUN: Serverless deployment
# ============================================================================

resource "google_cloud_run_service" "security_conductor" {
  name     = var.cloud_run_service_name
  location = var.gcp_region

  template {
    spec {
      service_account_name = google_service_account.cloud_run.email

      containers {
        image   = "${var.gcp_region}-docker.pkg.dev/${var.gcp_project_id}/${google_artifact_registry_repository.docker_repo.repository_id}/${var.docker_image_name}:${var.docker_image_tag}"
        command = []
        args    = []

        # Resource allocation (hobby tier: minimal)
        # Free tier: 180k vCPU-seconds/month
        resources {
          limits = {
            cpu    = "0.5"
            memory = "512Mi"
          }
        }

        # Environment variables
        env {
          name  = "LOG_LEVEL"
          value = "INFO"
        }

        env {
          name = "GEMINI_API_KEY"
          value_from {
            secret_key_ref {
              name = google_secret_manager_secret.gemini_api_key.secret_id
              key  = "latest"
            }
          }
        }

        # Liveness probe for Cloud Run health checks
        liveness_probe {
          http_get {
            path = "/health"
            port = 8080
          }
          initial_delay_seconds = 10
          timeout_seconds       = 3
          period_seconds        = 30
        }
      }

      timeout_seconds = 300
      max_instances   = 10
    }

    metadata {
      annotations = {
        "autoscaling.knative.dev/minScale" = "0"
        "autoscaling.knative.dev/maxScale" = "10"
      }
    }
  }

  traffic {
    percent         = 100
    latest_revision = true
  }

  depends_on = [
    google_artifact_registry_repository.docker_repo,
    google_service_account.cloud_run,
  ]
}

# ============================================================================
# IAM: Allow public HTTPS access
# ============================================================================

resource "google_cloud_run_service_iam_member" "public_access" {
  service  = google_cloud_run_service.security_conductor.name
  location = google_cloud_run_service.security_conductor.location
  role     = "roles/run.invoker"
  member   = "allUsers"
}

# ============================================================================
# CLOUD LOGGING: JSON structured logging
# ============================================================================

resource "google_logging_project_sink" "security_conductor_logs" {
  name                   = "rupert-security-conductor-sink"
  destination            = "logging.googleapis.com/projects/${var.gcp_project_id}/logs/security-conductor"
  filter                 = "resource.type=\"cloud_run_managed_environment\" OR resource.type=\"cloud_run_managed\" OR resource.labels.service_name=\"${var.cloud_run_service_name}\""
  unique_writer_identity = true
}
