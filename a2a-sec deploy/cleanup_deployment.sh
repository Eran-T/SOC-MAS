#!/bin/bash

# ==============================================================================
# Multi-Agent SOC System - FULL CLEANUP SCRIPT
#
# This script deletes ALL resources created by the deployment scripts.
# It is destructive and irreversible.
#
# It MUST be run from the same directory as your populated .env file.
# ==============================================================================

echo "--- Loading configuration from .env file ---"

CONFIG_FILE=".env"
if [ ! -f "$CONFIG_FILE" ]; then
    echo "❌ Error: .env file not found."
    echo "This script needs .env to know which resources to delete."
    exit 1
fi

# Load all variables from the .env file
source "$CONFIG_FILE"

# --- 1. Set Core Variables ---
echo "--- Setting up project and resource variables ---"

# Set project from env, or fall back to gcloud config
if [[ -z "${GOOGLE_CLOUD_PROJECT}" || "${GOOGLE_CLOUD_PROJECT}" == "YOUR_PROJECT_ID" ]]; then
  export GOOGLE_CLOUD_PROJECT=$(gcloud config get-value project)
fi

if [ -z "$REGION" ]; then
    echo "❌ Error: REGION is not set in .env. Please set it."
    exit 1
fi

# Re-build resource names just as the deploy scripts did
export PROJECT_NUMBER=$(gcloud projects describe ${GOOGLE_CLOUD_PROJECT} --format="value(projectNumber)")
export IMAGE_URI="${REGION}-docker.pkg.dev/${GOOGLE_CLOUD_PROJECT}/${REPOSITORY}/${SERVICE_NAME}:latest"
export BUCKET_UPLOAD_NAME="${PROJECT_NUMBER}-${UPLOAD_BUCKET}"
export BUCKET_DOWNLOAD_NAME="${PROJECT_NUMBER}-${DOWNLOAD_BUCKET}"
export SA_EMAIL="${FILE_HANDLER_SERVICE_ACCOUNT_NAME}@${GOOGLE_CLOUD_PROJECT}.iam.gserviceaccount.com"
export TRIGGER_SA_EMAIL="${TRIGGER_SA_NAME}@${GOOGLE_CLOUD_PROJECT}.iam.gserviceaccount.com"
export GCS_SA_EMAIL="$(gcloud storage service-agent --project=${GOOGLE_CLOUD_PROJECT})"

echo "✅ Configuration loaded for Project: ${GOOGLE_CLOUD_PROJECT} in Region: ${REGION}"


# --- 2. SAFETY PROMPT ---
echo ""
echo "🔴 WARNING! This script will permanently delete the following resources:"
echo "------------------------------------------------------------------"
echo "  Cloud Run Service:     ${SERVICE_NAME}"
echo "  Cloud Function:        soc-file-processor"
echo "  Artifact Registry:   ${REPOSITORY}"
echo "  Container Image:       ${IMAGE_URI}"
echo "  GCS Bucket:            ${BUCKET_UPLOAD_NAME}"
echo "  GCS Bucket:            ${BUCKET_DOWNLOAD_NAME}"
echo "  Service Account:       ${SA_EMAIL}"
echo "  Service Account:       ${TRIGGER_SA_EMAIL}"
echo "  Agent (Chat):          ${CHAT_AGENT_RESOURCE_NAME}"
echo "  Agent (GTI):           ${GTI_AGENT_RESOURCE_NAME}"
echo "  Agent (Malware):       ${MALWARE_ANALYSIS_AGENT_RESOURCE_NAME}"
echo "  Agent (Post Mortem):   ${POST_MORTEM_AGENT_RESOURCE_NAME}"
echo "  Agent (Incident):      ${INCIDENT_RESPONSE_AGENT_RESOURCE_NAME}"
echo "  IAM Binding:           GCS Service Agent -> Pub/Sub Publisher"
echo "------------------------------------------------------------------"
echo ""
read -p "Are you sure you want to delete all these resources? (y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]
then
    echo "Cleanup aborted by user."
    exit 1
fi


# --- 3. Execute Deletion ---
# We use '|| true' on each command to ensure the script continues
# even if a resource was already deleted or never existed.

echo -e "\n[Step 1/8] Deleting Cloud Run service..."
gcloud run services delete ${SERVICE_NAME} \
  --region=${REGION} \
  --project=${GOOGLE_CLOUD_PROJECT} \
  --quiet || true

echo -e "\n[Step 2/8] Deleting Vertex AI Reasoning Engines (Agents)..."
if [ -n "$CHAT_AGENT_RESOURCE_NAME" ]; then
    gcloud ai reasoning-engines delete ${CHAT_AGENT_RESOURCE_NAME} --region=${REGION} --project=${GOOGLE_CLOUD_PROJECT} --quiet || true
fi
if [ -n "$GTI_AGENT_RESOURCE_NAME" ]; then
    gcloud ai reasoning-engines delete ${GTI_AGENT_RESOURCE_NAME} --region=${REGION} --project=${GOOGLE_CLOUD_PROJECT} --quiet || true
fi
if [ -n "$MALWARE_ANALYSIS_AGENT_RESOURCE_NAME" ]; then
    gcloud ai reasoning-engines delete ${MALWARE_ANALYSIS_AGENT_RESOURCE_NAME} --region=${REGION} --project=${GOOGLE_CLOUD_PROJECT} --quiet || true
fi
if [ -n "$POST_MORTEM_AGENT_RESOURCE_NAME" ]; then
    gcloud ai reasoning-engines delete ${POST_MORTEM_AGENT_RESOURCE_NAME} --region=${REGION} --project=${GOOGLE_CLOUD_PROJECT} --quiet || true
fi
if [ -n "$INCIDENT_RESPONSE_AGENT_RESOURCE_NAME" ]; then
    gcloud ai reasoning-engines delete ${INCIDENT_RESPONSE_AGENT_RESOURCE_NAME} --region=${REGION} --project=${GOOGLE_CLOUD_PROJECT} --quiet || true
fi

echo -e "\n[Step 3/8] Deleting Cloud Function..."
gcloud functions delete soc-file-processor \
  --region=${REGION} \
  --project=${GOOGLE_CLOUD_PROJECT} \
  --quiet || true

echo -e "\n[Step 4/8] Deleting Container Image from Artifact Registry..."
# We must delete the image before the repository
gcloud artifacts docker images delete ${IMAGE_URI} \
  --project=${GOOGLE_CLOUD_PROJECT} \
  --quiet \
  --delete-tags || true

echo -e "\n[Step 5/8] Deleting Artifact Registry repository..."
gcloud artifacts repositories delete ${REPOSITORY} \
  --location=${REGION} \
  --project=${GOOGLE_CLOUD_PROJECT} \
  --quiet || true

echo -e "\n[Step 6/8] Deleting GCS Buckets..."
# The -r flag recursively deletes all contents
gsutil rm -r gs://${BUCKET_UPLOAD_NAME} || true
gsutil rm -r gs://${BUCKET_DOWNLOAD_NAME} || true

echo -e "\n[Step 7/8] Deleting Service Accounts..."
gcloud iam service-accounts delete ${SA_EMAIL} \
  --project=${GOOGLE_CLOUD_PROJECT} \
  --quiet || true
gcloud iam service-accounts delete ${TRIGGER_SA_EMAIL} \
  --project=${GOOGLE_CLOUD_PROJECT} \
  --quiet || true

echo -e "\n[Step 8/8] Removing project-level IAM binding..."
# This removes the pubsub.publisher role from the GCS service agent
gcloud projects remove-iam-policy-binding ${GOOGLE_CLOUD_PROJECT} \
    --member="serviceAccount:${GCS_SA_EMAIL}" \
    --role="roles/pubsub.publisher" \
    --condition=None \
    --quiet || true


echo -e "\n--- ✅ Cleanup Complete ---"