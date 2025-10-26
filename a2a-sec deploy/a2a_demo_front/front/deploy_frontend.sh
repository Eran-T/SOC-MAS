#!/bin/bash
# Exit immediately if a command exits with a non-zero status.
set -e


# --- Derived Variables ---
# The name of the Artifact Registry repository
export REPOSITORY="soc-agent-images"
# The full URI for the container image
export IMAGE_URI="${REGION}-docker.pkg.dev/${GOOGLE_CLOUD_PROJECT}/${REPOSITORY}/${SERVICE_NAME}:latest"

# --- Script ---

echo "--- 1. Enabling Google Cloud services ---"
gcloud services enable \
  run.googleapis.com \
  artifactregistry.googleapis.com \
  cloudbuild.googleapis.com \
  --project=${GOOGLE_CLOUD_PROJECT}

echo "--- 2. Creating Artifact Registry repository (if it doesn't exist) ---"
# Check if the repository exists and create it if it doesn't.
gcloud artifacts repositories describe ${REPOSITORY} --location=${REGION} --project=${GOOGLE_CLOUD_PROJECT} > /dev/null 2>&1 || \
gcloud artifacts repositories create ${REPOSITORY} \
    --repository-format=docker \
    --location=${REGION} \
    --description="Docker repository for Cloud Run services" \
    --project=${GOOGLE_CLOUD_PROJECT}

echo "--- 3. Building and pushing the container image using Cloud Build ---"
gcloud builds submit --tag ${IMAGE_URI} --project=${GOOGLE_CLOUD_PROJECT}

echo "--- 4. Deploying to Cloud Run (initial deployment without waiting) ---"
# Deploy the service for the first time.
# The --no-wait flag allows the script to continue without waiting for the revision to be healthy.
gcloud run deploy ${SERVICE_NAME} \
  --image=${IMAGE_URI} \
  --platform=managed \
  --region=${REGION} \
  --allow-unauthenticated \
  --set-env-vars="CHAT_AGENT_SERVER_URL=TO_BE_UPDATED" \
  --project=${GOOGLE_CLOUD_PROJECT} \
  --allow-unauthenticated \
  --quiet

echo "--- 5. Retrieving the Cloud Run service URL ---"
# Add a small delay to ensure the service object is created and has a URL.
sleep 5 
SERVICE_URL=$(gcloud run services describe ${SERVICE_NAME} \
  --platform=managed \
  --region=${REGION} \
  --project=${GOOGLE_CLOUD_PROJECT} \
  --format="value(status.url)")

export SERVICE_URL=${SERVICE_URL}


if [ -z "$SERVICE_URL" ]; then
    echo "Error: Could not retrieve service URL. Aborting."
    exit 1
fi

# echo "--- 6. Updating the service to set its own URL as FRONT_END_URL ---"
# # Update the service with the new environment variable.
# # This time we wait for the deployment to complete successfully.
# gcloud run services update ${SERVICE_NAME} \
#   --region=${REGION} \
#   --platform=managed \
#   --update-env-vars="FRONT_END_URL=${SERVICE_URL}" \
#   --project=${GOOGLE_CLOUD_PROJECT} \
#   --quiet

# echo "✅ Deployment complete!"
# echo ""
# echo "Your service is available at: ${SERVICE_URL}"
# echo ""
# echo "The FRONT_END_URL environment variable has been set on the Cloud Run service."
# echo "The CHAT_AGENT_SERVER_URL is set to a placeholder and can be updated in the Google Cloud Console."