#!/bin/bash
# Exit immediately if a command exits with a non-zero status.
set -e


# --- Derived Variables ---
# The name of the Artifact Registry repository
export REPOSITORY="soc-agent-images"
# The full URI for the container image
export IMAGE_URI="${REGION}-docker.pkg.dev/${GOOGLE_CLOUD_PROJECT}/${REPOSITORY}/${SERVICE_NAME}:latest"
export DEFAULT_SA_EMAIL="${PROJECT_NUMBER}-compute@developer.gserviceaccount.com"
# --- Script ---

echo "--- 1. Enabling Google Cloud services ---"
gcloud services enable \
  run.googleapis.com \
  artifactregistry.googleapis.com \
  cloudbuild.googleapis.com \
  run.googleapis.com \
  eventarc.googleapis.com \
  aiplatform.googleapis.com \
  cloudfunctions.googleapis.com \
  storage.googleapis.com \
  eventarc.googleapis.com \
  --project=${GOOGLE_CLOUD_PROJECT}

  
sleep 5

echo "--- 2. Creating and configuring service account... ---"
export SA_NAME="${FILE_HANDLER_SERVICE_ACCOUNT_NAME}"
export SA_EMAIL="${SA_NAME}@${GOOGLE_CLOUD_PROJECT}.iam.gserviceaccount.com"
export DISPLAY_NAME="File Processor Service Account"

gcloud iam service-accounts create ${SA_NAME} \
    --display-name="${DISPLAY_NAME}" \
    --description="Service account for the Eventarc file processing function" \
    --project=${GOOGLE_CLOUD_PROJECT} || echo "Service account '${SA_NAME}' already exists."

sleep 5


echo "--- 3. Grant the deploying user permission to act as the service accounts ${GOOGLE_CLOUD_PROJECT}---"
export DEPLOYING_USER=$(gcloud config get-value account)
gcloud iam service-accounts add-iam-policy-binding ${SA_EMAIL} --member="user:${DEPLOYING_USER}" --role="roles/iam.serviceAccountUser" --project=${GOOGLE_CLOUD_PROJECT} --condition=None
gcloud projects add-iam-policy-binding ${GOOGLE_CLOUD_PROJECT} --member="serviceAccount:${SA_EMAIL}" --role="roles/aiplatform.user" --condition=None
gcloud iam service-accounts add-iam-policy-binding ${SA_EMAIL} --member="serviceAccount:${SA_EMAIL}" --role="roles/iam.serviceAccountTokenCreator" --project=${GOOGLE_CLOUD_PROJECT} --condition=None
gcloud projects add-iam-policy-binding ${GOOGLE_CLOUD_PROJECT} --member="serviceAccount:${DEFAULT_SA_EMAIL}" --role="roles/logging.logWriter" --project=${GOOGLE_CLOUD_PROJECT} --condition=None
gcloud projects add-iam-policy-binding ${GOOGLE_CLOUD_PROJECT} --member="serviceAccount:${DEFAULT_SA_EMAIL}" --role="roles/storage.objectUser" --project=${GOOGLE_CLOUD_PROJECT} --condition=None 
gcloud projects add-iam-policy-binding ${GOOGLE_CLOUD_PROJECT} --member="serviceAccount:${DEFAULT_SA_EMAIL}" --role="roles/artifactregistry.writer" --project=${GOOGLE_CLOUD_PROJECT} --condition=None 
gcloud projects add-iam-policy-binding ${GOOGLE_CLOUD_PROJECT} --member="serviceAccount:${DEFAULT_SA_EMAIL}" --role="roles/cloudbuild.builds.builder" --project=${GOOGLE_CLOUD_PROJECT} --condition=None 
gcloud projects add-iam-policy-binding ${GOOGLE_CLOUD_PROJECT} --member="serviceAccount:${DEFAULT_SA_EMAIL}" --role="roles/cloudbuild.builds.builder" --project=${GOOGLE_CLOUD_PROJECT} --condition=None 


echo "--- 4. Creating Artifact Registry repository (if it doesn't exist) ---"
# Check if the repository exists and create it if it doesn't.
gcloud artifacts repositories describe ${REPOSITORY} --location=${REGION} --project=${GOOGLE_CLOUD_PROJECT} > /dev/null 2>&1 || \
gcloud artifacts repositories create ${REPOSITORY} \
    --repository-format=docker \
    --location=${REGION} \
    --description="Docker repository for Cloud Run services" \
    --project=${GOOGLE_CLOUD_PROJECT}

echo "--- 5. Building and pushing the container image using Cloud Build ---"
echo "${IMAGE_URI}"
FRONTEND_SOURCE_DIR="a2a_demo_front/front"
pushd "${FRONTEND_SOURCE_DIR}" > /dev/null
gcloud builds submit --tag ${IMAGE_URI} --project=${GOOGLE_CLOUD_PROJECT}
popd > /dev/null

echo "--- 6. Deploying to Cloud Run ---"
# Deploy the service for the first time.
# The --no-wait flag allows the script to continue without waiting for the revision to be healthy.
gcloud run deploy ${SERVICE_NAME} \
  --image=${IMAGE_URI} \
  --platform=managed \
  --region=${REGION} \
  --allow-unauthenticated \
  --set-env-vars="CHAT_AGENT_SERVER_URL=TO_BE_UPDATED" \
  --project=${GOOGLE_CLOUD_PROJECT} \
  --no-invoker-iam-check \
  --service-account=${SA_EMAIL} 


echo "--- 7. Retrieving the Cloud Run service URL ---"
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


echo "The FRONT_END_URL environment variable has been set on the Cloud Run service."
echo "The CHAT_AGENT_SERVER_URL is set to a placeholder and can be updated in the Google Cloud Console."
