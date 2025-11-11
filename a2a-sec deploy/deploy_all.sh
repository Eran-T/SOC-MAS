#!/bin/bash

# This script orchestrates the full deployment of the frontend and all backend agents.
# It uses a configuration file (.env) to manage state, allowing it to be resumed.
#
# Usage: source ./deploy_all_agents.sh [--start-from N]
#
#   --start-from N: Optional. A number from 1 to 7 indicating which part to start from.

set -e

# --- Config File Setup ---
CONFIG_FILE=".env"

# Check if the config file exists before proceeding.
if [ ! -f "$CONFIG_FILE" ]; then
    echo "❌ Error: Configuration file '${CONFIG_FILE}' not found."
    echo "Please create it from the template before running this script."
    return 1
fi

# Function to update a variable in the .env file using the Python helper.
# This is more reliable than using sed.
update_config() {
    local key="$1"
    local value="$2"
    python3 update_env.py "$key" "$value"
}


# Source the configuration file
source "$CONFIG_FILE"
# --- Argument Parsing for Start Step ---
START_STEP=1
if [[ "$1" == "--start-from" || "$1" == "-s" ]]; then
    # if ! [[ "$2" =~ ^[1-7]$ ]]; then
    #     echo "❌ Error: Invalid step number. Please provide a number between 1 and 7."
    #     return 1
    # fi
    START_STEP="$2"
    echo "▶️  Starting execution from PART ${START_STEP}."

    # Check if the script is being sourced, which is required for variables to persist
    if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
        echo "⚠️  Warning: For variables to be correctly inherited, please run with 'source ./deploy_all_agents.sh --start-from ${START_STEP}'"
    fi
fi


# --- Configuration ---
# Use GOOGLE_CLOUD_PROJECT from config file, otherwise try gcloud config
if [[ -z "${GOOGLE_CLOUD_PROJECT}" || "${GOOGLE_CLOUD_PROJECT}" == "YOUR_PROJECT_ID" ]]; then
  export GOOGLE_CLOUD_PROJECT=$(gcloud config get-value project)
fi

# --- PART 1: DEPLOY FRONTEND APPLICATION ---
if (( START_STEP <= 1 )); then
    echo "============================================================"
    echo "🎬 PART 1: Starting Frontend Deployment"
    echo "============================================================"
    
    echo "--- Fetching Google Cloud Project Number ---"
    PROJECT_NUMBER_VAL=$(gcloud projects describe ${GOOGLE_CLOUD_PROJECT} --format="value(projectNumber)")
    if [ -z "$PROJECT_NUMBER_VAL" ]; then echo "❌ Error: Could not retrieve Project Number. Aborting."; return 1; fi
    export PROJECT_NUMBER=${PROJECT_NUMBER_VAL}
    update_config "PROJECT_NUMBER" "${PROJECT_NUMBER}"
    echo "✅ Project Number found and saved: ${PROJECT_NUMBER}"

    export IMAGE_URI="${REGION}-docker.pkg.dev/${GOOGLE_CLOUD_PROJECT}/${REPOSITORY}/${SERVICE_NAME}:latest"
    FRONTEND_SOURCE_DIR="a2a_demo_front/front"
    echo "--- Enabling Google Cloud services ---"
    gcloud services enable run.googleapis.com artifactregistry.googleapis.com cloudbuild.googleapis.com --project=${GOOGLE_CLOUD_PROJECT}
    echo "--- Creating Artifact Registry repository (if it doesn't exist) ---"
    gcloud artifacts repositories describe ${REPOSITORY} --location=${REGION} --project=${GOOGLE_CLOUD_PROJECT} > /dev/null 2>&1 || \
    gcloud artifacts repositories create ${REPOSITORY} --repository-format=docker --location=${REGION} --description="Docker repository for Cloud Run services" --project=${GOOGLE_CLOUD_PROJECT}
    echo "--- Building and pushing the container image using Cloud Build ---"
    pushd "${FRONTEND_SOURCE_DIR}" > /dev/null
    gcloud builds submit --tag ${IMAGE_URI} --project=${GOOGLE_CLOUD_PROJECT}
    popd > /dev/null
    echo "--- Deploying to Cloud Run ---"
    gcloud run deploy ${SERVICE_NAME} --image=${IMAGE_URI} --platform=managed --region=${REGION} --allow-unauthenticated --set-env-vars="CHAT_AGENT_SERVER_URL=TO_BE_UPDATED" --project=${GOOGLE_CLOUD_PROJECT} --quiet
    echo "--- Retrieving the Cloud Run service URL ---"
    sleep 5
    # SERVICE_URL_VAL="https://${SERVICE_NAME}-${PROJECT_NUMBER}.${REGION}.run.app"
    SERVICE_URL_VAL=$(gcloud run services describe ${SERVICE_NAME} --region=${REGION} --project=${GOOGLE_CLOUD_PROJECT} --format="value(status.url)")
    if [ -z "$SERVICE_URL_VAL" ]; then echo "❌ Error: Could not retrieve service URL. Aborting."; return 1; fi
    export SERVICE_URL=${SERVICE_URL_VAL}
    update_config "SERVICE_URL" "${SERVICE_URL}"
    echo "✅ Frontend deployment complete. Service URL saved: ${SERVICE_URL}"
fi

# --- PART 2: DEPLOY GTI AGENT (CUSTOM PYTHON SCRIPT) ---
if (( START_STEP <= 2 )); then
    echo -e "\n============================================================"
    echo "🎬 PART 2: Starting GTI Agent Deployment (Custom)"
    echo "============================================================"
    if [ -z "$PROJECT_NUMBER" ]; then echo "❌ Error: PROJECT_NUMBER not set. Please run PART 1 first."; return 1; fi
    GTI_AGENT_DIR="agents/remote_agents/gti_agent"
    CUSTOM_GTI_DEPLOY_SCRIPT="setup_alt.py" 

    if [ -f "${GTI_AGENT_DIR}/${CUSTOM_GTI_DEPLOY_SCRIPT}" ]; then
        echo "▶️  Found custom Python deploy script. Executing..."
        echo "--- Preparing staging bucket for GTI Agent ---"
        export GTI_AGENT_STAGING_BUCKET="${PROJECT_NUMBER}-gti_agent"
        pushd "${GTI_AGENT_DIR}" > /dev/null
        GTI_RESOURCE_NAME_VAL=$(python3 "${CUSTOM_GTI_DEPLOY_SCRIPT}" | grep -o "projects/${PROJECT_NUMBER}/locations/${REGION}/reasoningEngines/[0-9]\+" | tail -n 1)
        popd > /dev/null
        if [ -z "$GTI_RESOURCE_NAME_VAL" ]; then echo "❌ Error: Failed to get resource name from GTI script."; return 1; fi
        export GTI_AGENT_RESOURCE_NAME="${GTI_RESOURCE_NAME_VAL}"
        update_config "GTI_AGENT_RESOURCE_NAME" "${GTI_AGENT_RESOURCE_NAME}"
        echo "✅ GTI Agent custom deployment complete. Resource name saved."
    else
        echo "❌ Error: Custom deployment script not found at ${GTI_AGENT_DIR}/${CUSTOM_GTI_DEPLOY_SCRIPT}. Aborting."
        return 1
    fi
fi

# --- PART 3: DEPLOY REMAINING TOOLING AGENTS (GENERIC SCRIPT) ---
if (( START_STEP <= 3 )); then
    echo -e "\n============================================================"
    echo "🎬 PART 3: Starting Remaining Tooling Agent Deployments"
    echo "============================================================"
    if [ -z "$PROJECT_NUMBER" ]; then echo "❌ Error: PROJECT_NUMBER not set. Please run PART 1 first."; return 1; fi
    REMOTE_AGENTS_BASE_DIR="agents/remote_agents"
    AGENTS_TO_DEPLOY=("malware_analysis_agent" "post_mortem_agent" "incident_response_agent")
    for AGENT_NAME in "${AGENTS_TO_DEPLOY[@]}"; do
        echo "------------------------------------------------------------"
        echo "--- Preparing staging bucket for ${AGENT_NAME} ---"
        VAR_PREFIX=$(echo "${AGENT_NAME}" | tr '[:lower:]' '[:upper:]')
        STAGING_BUCKET_VAR_NAME="${VAR_PREFIX}_STAGING_BUCKET"
        STAGING_BUCKET_NAME="${PROJECT_NUMBER}-${AGENT_NAME}-staging-bucket"
        export "${STAGING_BUCKET_VAR_NAME}=${STAGING_BUCKET_NAME}"
        source ./deploy.sh "${AGENT_NAME}" "${REMOTE_AGENTS_BASE_DIR}"
        
        # After deploy.sh runs, the variable (e.g., MALWARE_ANALYSIS_AGENT_RESOURCE_NAME) is in the environment
        # Now, save it to the config file
        RESOURCE_VAR_NAME="${VAR_PREFIX}_RESOURCE_NAME"
        # Indirectly get the value of the variable
        RESOURCE_VALUE=$(eval echo "\$${RESOURCE_VAR_NAME}")
        echo "✅✅✅here is resource value: ${RESOURCE_VALUE}✅✅"
        echo "✅✅✅after printing resource value✅✅✅"
        update_config "${RESOURCE_VAR_NAME}" "${RESOURCE_VALUE}"
        echo "✅ ${AGENT_NAME} deployment complete. Resource name saved."
        echo "------------------------------------------------------------"
    done
fi

# --- PART 4: RUN FILE HANDLING BACKEND SCRIPT ---
if (( START_STEP <= 4 )); then
    echo -e "\n============================================================"
    echo "🎬 PART 4: Running File Handling Backend Script"
    echo "============================================================"
    FILE_HANDLING_SCRIPT="deploy_backend_file_handling.sh"
    if [ -f "$FILE_HANDLING_SCRIPT" ]; then
        source ./${FILE_HANDLING_SCRIPT}
        echo "✅ File Handling Backend script finished."
    else
        echo "⚠️  Warning: ${FILE_HANDLING_SCRIPT} not found. Skipping."
    fi
fi

# --- PART 5: DEPLOY CHAT AGENT ---
if (( START_STEP <= 5 )); then
    export SA_NAME="${FILE_HANDLER_SERVICE_ACCOUNT_NAME}"
    export SA_EMAIL="${SA_NAME}@${GOOGLE_CLOUD_PROJECT}.iam.gserviceaccount.com"
    echo -e "\n============================================================"
    echo "🎬 PART 4: Deploying the Chat Agent"
    echo "============================================================"
    if [ -z "$PROJECT_NUMBER" ]; then echo "❌ Error: PROJECT_NUMBER not set. Please run PART 1 first."; return 1; fi
    if [ -z "$GTI_AGENT_RESOURCE_NAME" ]; then echo "❌ Error: Tooling agent resource names not set. Please run previous parts."; return 1; fi
    export CHAT_AGENT_STAGING_BUCKET="${PROJECT_NUMBER}-chat_agent"
    source ./deploy.sh "chat_agent" "a2a_demo_front/agents" "BUCKET_UPLOAD_NAME=${BUCKET_UPLOAD_NAME},BUCKET_DOWNLOAD_NAME=${BUCKET_DOWNLOAD_NAME},SA_EMAIL=${SA_EMAIL}" 
    if [ -z "$CHAT_AGENT_RESOURCE_NAME" ]; then echo "❌ Error: Chat agent deployment failed. Aborting."; return 1; fi
    update_config "CHAT_AGENT_RESOURCE_NAME" "${CHAT_AGENT_RESOURCE_NAME}"
    echo "✅ Chat agent deployment complete. Resource name saved."
fi

# --- PART 6: UPDATE FRONTEND WITH CHAT AGENT URL ---
if (( START_STEP <= 6 )); then
    echo -e "\n============================================================"
    echo "🎬 PART 5: Updating Frontend with Chat Agent URL"
    echo "============================================================"
    if [ -z "$CHAT_AGENT_RESOURCE_NAME" ]; then echo "❌ Error: CHAT_AGENT_RESOURCE_NAME not set. Please run PART 5 first."; return 1; fi
    CHAT_AGENT_SERVER_URL="https://${REGION}-aiplatform.googleapis.com/v1beta1/${CHAT_AGENT_RESOURCE_NAME}/a2a"
    echo "Updating Cloud Run service '${SERVICE_NAME}' with CHAT_AGENT_SERVER_URL..."
    gcloud run services update ${SERVICE_NAME} \
        --update-env-vars="CHAT_AGENT_SERVER_URL=${CHAT_AGENT_SERVER_URL},REGION=${REGION}" \
        --region=${REGION} \
        --platform=managed \
        --project=${GOOGLE_CLOUD_PROJECT} \
        --quiet
    echo "✅ Frontend service updated successfully."
fi



if (( START_STEP == 1 )); then
    echo -e "\n🏁 All deployments and setups have been processed."
    echo "✅ Application deployed succefully.\naccess it from: ${SERVICE_URL}"
else
    echo -e "\n🏁 All deployments and setups from PART ${START_STEP} onwards have been processed."
    echo "✅ Application deployed succefully.\naccess it from: ${SERVICE_URL}"
fi
