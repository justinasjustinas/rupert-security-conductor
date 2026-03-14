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

locals {
  github_actions_enabled = var.github_repository_owner != "" && var.github_repository_name != ""
  github_repository      = "${var.github_repository_owner}/${var.github_repository_name}"
}

# ============================================================================
# ARTIFACT REGISTRY: Docker image repository
# ============================================================================

# Managed by Terraform so a fresh project can be bootstrapped end-to-end.
resource "google_artifact_registry_repository" "docker_repo" {
  location      = var.gcp_region
  repository_id = var.artifact_registry_repo
  description   = "Docker images for Rupert Security Conductor"
  format        = "DOCKER"
}

# ============================================================================
# SERVICE ACCOUNTS: Runtime identity and GitHub Actions deployer
# ============================================================================

resource "google_service_account" "cloud_run" {
  account_id   = var.cloud_run_service_account_id
  display_name = "Rupert Security Conductor runtime"
}

resource "google_service_account" "github_actions" {
  count        = local.github_actions_enabled ? 1 : 0
  account_id   = var.github_actions_service_account_id
  display_name = "Rupert GitHub Actions deployer"
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

# Allow GitHub Actions to push images to Artifact Registry
resource "google_artifact_registry_repository_iam_member" "github_actions_writer" {
  count      = local.github_actions_enabled ? 1 : 0
  location   = google_artifact_registry_repository.docker_repo.location
  repository = google_artifact_registry_repository.docker_repo.repository_id
  role       = "roles/artifactregistry.writer"
  member     = "serviceAccount:${google_service_account.github_actions[0].email}"
}

# Allow GitHub Actions to deploy Cloud Run revisions
resource "google_project_iam_member" "github_actions_run_admin" {
  count   = local.github_actions_enabled ? 1 : 0
  project = var.gcp_project_id
  role    = "roles/run.admin"
  member  = "serviceAccount:${google_service_account.github_actions[0].email}"
}

# Allow GitHub Actions to attach the runtime service account during deploys
resource "google_service_account_iam_member" "github_actions_service_account_user" {
  count              = local.github_actions_enabled ? 1 : 0
  service_account_id = google_service_account.cloud_run.name
  role               = "roles/iam.serviceAccountUser"
  member             = "serviceAccount:${google_service_account.github_actions[0].email}"
}

# ============================================================================
# WORKLOAD IDENTITY FEDERATION: GitHub Actions -> Google Cloud
# ============================================================================

resource "google_iam_workload_identity_pool" "github_actions" {
  count                     = local.github_actions_enabled ? 1 : 0
  workload_identity_pool_id = var.github_workload_identity_pool_id
  display_name              = "GitHub Actions"
  description               = "OIDC federation pool for GitHub Actions deployments"
}

resource "google_iam_workload_identity_pool_provider" "github_actions" {
  count                              = local.github_actions_enabled ? 1 : 0
  workload_identity_pool_id          = google_iam_workload_identity_pool.github_actions[0].workload_identity_pool_id
  workload_identity_pool_provider_id = var.github_workload_identity_provider_id
  display_name                       = "GitHub provider"
  description                        = "Accept GitHub OIDC tokens for CI/CD"
  attribute_mapping = {
    "google.subject"           = "assertion.sub"
    "attribute.actor"          = "assertion.actor"
    "attribute.aud"            = "assertion.aud"
    "attribute.ref"            = "assertion.ref"
    "attribute.repository"     = "assertion.repository"
    "attribute.repository_owner" = "assertion.repository_owner"
  }
  attribute_condition = "assertion.repository_owner == '${var.github_repository_owner}' && assertion.repository == '${local.github_repository}'"
  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }
}

resource "google_service_account_iam_member" "github_actions_workload_identity_user" {
  count              = local.github_actions_enabled ? 1 : 0
  service_account_id = google_service_account.github_actions[0].name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.github_actions[0].name}/attribute.repository/${local.github_repository}"
}

# ============================================================================
# SECRETS MANAGER: Gemini API Key
# ============================================================================

# Secret metadata is managed by Terraform. Secret versions are added separately
# so the API key is not written into Terraform state.
resource "google_secret_manager_secret" "gemini_api_key" {
  secret_id = "rupert-gemini-api-key"
  replication {
    auto {}
  }
}

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
# (Cloud Run automatically sends logs to Cloud Logging)
# ============================================================================
# Logging sink configuration removed - Cloud Run handles this automatically
