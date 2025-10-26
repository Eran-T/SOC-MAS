#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e

# Check if the first two arguments were provided
if [ -z "$1" ] || [ -z "$2" ]; then
    echo "❌ Error: Missing arguments."
    echo "Usage: source ./deploy_and_export.sh <agent_name> <second_arg> [env_vars]"
    echo "   Example: source ./deploy_and_export.sh my_agent prod \"key1=val1,key2=val2\""
    return 1 # Use return instead of exit for sourced scripts
fi

AGENT_NAME="$1"
SECOND_ARG="$2"
ENV_VARS="$3" # This will be empty if $3 is not provided

echo "▶️  Deploying agent: ${AGENT_NAME}"
echo "   Second Arg: ${SECOND_ARG}"

# 1. Run the Python script and capture its standard output.
#    All info prints from Python go to stderr.
RESOURCE_NAME=""

if [ -n "$ENV_VARS" ]; then
    echo "   ...with env vars: ${ENV_VARS}"
    # Call with env_vars argument
    RESOURCE_NAME=$(python3 deploy.py "${AGENT_NAME}" "${SECOND_ARG}" --env_vars "${ENV_VARS}" | grep -o "projects/${PROJECT_NUMBER}/locations/${REGION}/reasoningEngines/[0-9]\+" | tail -n 1)
else
    # Call without env_vars argument
    RESOURCE_NAME=$(python3 deploy.py "${AGENT_NAME}" "${SECOND_ARG}" | grep -o "projects/${PROJECT_NUMBER}/locations/${REGION}/reasoningEngines/[0-9]\+" | tail -n 1)
fi

if [ -z "$RESOURCE_NAME" ]; then
    echo "❌ Error: Failed to get resource name. Deployment may have failed."
    return 1
fi

# 2. Convert the agent name to uppercase (e.g., "gti_agent" -> "GTI_AGENT")
VAR_PREFIX=$(echo "${AGENT_NAME}" | tr '[:lower:]' '[:upper:]')

# 3. Construct the full environment variable name
VAR_NAME="${VAR_PREFIX}_RESOURCE_NAME"

# 4. Export the environment variable with the captured resource name
export "${VAR_NAME}=${RESOURCE_NAME}"

echo "✅ Success! Environment variable set."
echo "   ${VAR_NAME}=${RESOURCE_NAME}"
