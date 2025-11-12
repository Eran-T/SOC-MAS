#!/bin/bash

# ==============================================================================
# GCP Serverless File Processing Pipeline Deployment Script
#
# This script automates the deployment of a serverless file processing pipeline
# using Cloud Storage, Eventarc, and a 2nd Gen Cloud Function.
#
# Usage:
#   ./deploy_pipeline.sh <PATH_TO_FUNCTION_SOURCE_DIRECTORY>
#
# Prerequisites:
#   - gcloud CLI is installed and authenticated.
#   - GOOGLE_CLOUD_PROJECT environment variable is set.
#   - The necessary APIs are enabled in your project.
# ==============================================================================

# --- Script Configuration ---
# Exit immediately if a command exits with a non-zero status.
set -e


# Check if GOOGLE_CLOUD_PROJECT is set
if [ -z "$GOOGLE_CLOUD_PROJECT" ]; then
  echo "Error: GOOGLE_CLOUD_PROJECT environment variable is not set."
  echo "Please set it using: export GOOGLE_CLOUD_PROJECT=\`gcloud config get-value project\`"
  exit 1
fi

echo "--- Starting Deployment for project: ${GOOGLE_CLOUD_PROJECT} ---"


# --- Step 1: Create Cloud Storage Buckets ---
echo -e "\n[Step 1/5] Creating Cloud Storage buckets..."
export BUCKET_UPLOAD_NAME="${PROJECT_NUMBER}-${UPLOAD_BUCKET}"
export BUCKET_DOWNLOAD_NAME="${PROJECT_NUMBER}-${DOWNLOAD_BUCKET}"

gsutil mb -p ${GOOGLE_CLOUD_PROJECT} -l ${REGION} gs://${BUCKET_UPLOAD_NAME}
gsutil mb -p ${GOOGLE_CLOUD_PROJECT} -l ${REGION} gs://${BUCKET_DOWNLOAD_NAME}

echo "Buckets created: ${BUCKET_UPLOAD_NAME} and ${BUCKET_DOWNLOAD_NAME}"

# --- Step 2: Create and Configure Service Accounts ---
echo -e "\n[Step 2/5] Creating and configuring service accounts..."

# 1. Function Identity Service Account
export SA_NAME="${FILE_HANDLER_SERVICE_ACCOUNT_NAME}"
export SA_EMAIL="${SA_NAME}@${GOOGLE_CLOUD_PROJECT}.iam.gserviceaccount.com"
export DISPLAY_NAME="File Processor Service Account"

gcloud iam service-accounts create ${SA_NAME} \
    --display-name="${DISPLAY_NAME}" \
    --description="Service account for the Eventarc file processing function" \
    --project=${GOOGLE_CLOUD_PROJECT} || echo "Service account '${SA_NAME}' already exists."

# 2. Grant Storage permissions to the Function SA
gcloud storage buckets add-iam-policy-binding gs://${BUCKET_UPLOAD_NAME} --member="serviceAccount:${SA_EMAIL}" --role="roles/storage.objectViewer" --project=${GOOGLE_CLOUD_PROJECT}
gcloud storage buckets add-iam-policy-binding gs://${BUCKET_UPLOAD_NAME} --member="serviceAccount:${SA_EMAIL}" --role="roles/storage.legacyBucketWriter" --project=${GOOGLE_CLOUD_PROJECT}
# Creator for the cloud run service
gcloud storage buckets add-iam-policy-binding gs://${BUCKET_DOWNLOAD_NAME} --member="serviceAccount:${SA_EMAIL}" --role="roles/storage.objectCreator" --project=${GOOGLE_CLOUD_PROJECT}
# Get for generating dwonload url
gcloud storage buckets add-iam-policy-binding gs://${BUCKET_DOWNLOAD_NAME} --member="serviceAccount:${SA_EMAIL}" --role="roles/storage.objectViewer" --project=${GOOGLE_CLOUD_PROJECT}

# 3. Grant Eventarc Event Receiver role to the Function SA
gcloud projects add-iam-policy-binding ${GOOGLE_CLOUD_PROJECT} --member="serviceAccount:${SA_EMAIL}" --role="roles/eventarc.eventReceiver" --project=${GOOGLE_CLOUD_PROJECT} --condition=None

# 4. Grant the deploying user permission to act as the Function SA
export DEPLOYING_USER=$(gcloud config get-value account)
gcloud iam service-accounts add-iam-policy-binding ${SA_EMAIL} --member="user:${DEPLOYING_USER}" --role="roles/iam.serviceAccountUser" --project=${GOOGLE_CLOUD_PROJECT} --condition=None
gcloud projects add-iam-policy-binding ${GOOGLE_CLOUD_PROJECT} --member="serviceAccount:${SA_EMAIL}" --role="roles/aiplatform.user" --condition=None
gcloud iam service-accounts add-iam-policy-binding ${SA_EMAIL} --member="serviceAccount:${SA_EMAIL}" --role="roles/iam.serviceAccountTokenCreator" --condition=None

# 5. Trigger Identity Service Account
export TRIGGER_SA_NAME="processor-trigger-sa"
export TRIGGER_SA_EMAIL="${TRIGGER_SA_NAME}@${GOOGLE_CLOUD_PROJECT}.iam.gserviceaccount.com"
export TRIGGER_DISPLAY_NAME="Processor Trigger Service Account"

gcloud iam service-accounts create ${TRIGGER_SA_NAME} \
    --display-name="${TRIGGER_DISPLAY_NAME}" \
    --description="Service account for the Eventarc trigger to invoke the function" \
    --project=${GOOGLE_CLOUD_PROJECT} || echo "Service account '${TRIGGER_SA_NAME}' already exists."

# 6. Grant Eventarc Event Receiver role to the Trigger SA
gcloud projects add-iam-policy-binding ${GOOGLE_CLOUD_PROJECT} --member="serviceAccount:${TRIGGER_SA_EMAIL}" --role="roles/eventarc.eventReceiver" --project=${GOOGLE_CLOUD_PROJECT} --condition=None

echo "Service accounts created and configured."

# --- Step 3: Grant GCS Service Agent Pub/Sub Publisher Role ---
echo -e "\n[Step 3/5] Granting GCS Service Agent Pub/Sub Publisher Role..."
export GCS_SA_EMAIL="$(gcloud storage service-agent --project=${GOOGLE_CLOUD_PROJECT})"
gcloud projects add-iam-policy-binding ${GOOGLE_CLOUD_PROJECT} \
    --member="serviceAccount:${GCS_SA_EMAIL}" \
    --role="roles/pubsub.publisher" \
    --project=${GOOGLE_CLOUD_PROJECT} \
    --condition=None

echo "Granted Pub/Sub Publisher role to the GCS service agent."

# --- Step 4: Deploy the Cloud Function with an Eventarc Trigger ---
echo -e "\n[Step 4/5] Deploying Cloud Function 'soc-file-processor'..."
gcloud functions deploy soc-file-processor \
  --gen2 \
  --runtime python311 \
  --entry-point process_file_upload \
  --region ${REGION} \
  --source "./deployment/file-processor" \
  --service-account ${SA_EMAIL} \
  --trigger-service-account ${TRIGGER_SA_EMAIL} \
  --trigger-event-filters="type=google.cloud.storage.object.v1.finalized,bucket=${BUCKET_UPLOAD_NAME}" \
  --set-env-vars BUCKET_UPLOAD_NAME=${BUCKET_UPLOAD_NAME},BUCKET_DOWNLOAD_NAME=${BUCKET_DOWNLOAD_NAME} \
  --project=${GOOGLE_CLOUD_PROJECT}

echo "Granting invoker permission to the trigger service account..."
gcloud functions add-invoker-policy-binding soc-file-processor \
  --member="serviceAccount:${TRIGGER_SA_EMAIL}" \
  --project=${GOOGLE_CLOUD_PROJECT}

echo "Cloud Function 'soc-file-processor' deployed."


# --- Step 5: Update CORS Policy ---
cat <<EOF > cors_upload.json
[
  {
    "origin": ["${SERVICE_URL}"],
    "method": ["PUT"],
    "responseHeader": ["Content-Type"],
    "maxAgeSeconds": 3600
  }
]
EOF
gcloud storage buckets update gs://${BUCKET_UPLOAD_NAME} --cors-file=cors_upload.json
cat <<EOF > cors_download.json
[
  {
    "origin": ["${SERVICE_URL}"],
    "method": ["GET"],
    "responseHeader": ["Content-Type"],
    "maxAgeSeconds": 3600
  }
]
EOF
gcloud storage buckets update gs://${BUCKET_DOWNLOAD_NAME} --cors-file=cors_download.json



echo -e "\n--- DEPLOYMENT COMPLETE ---"
echo "A test file 'sample.txt' has been uploaded to 'gs://${BUCKET_UPLOAD_NAME}'."
echo "Check the function logs and the download bucket 'gs://${BUCKET_DOWNLOAD_NAME}' to verify the pipeline."
