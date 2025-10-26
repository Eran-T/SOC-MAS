# Project Setup and Deployment Guide

This guide provides the necessary steps to set up your local environment, configure Google Cloud permissions, and deploy the project.

## Prerequisites

* [Python 3.8+](https://www.python.org/downloads/) installed.
* [Google Cloud SDK](https://cloud.google.com/sdk/docs/install) (gcloud CLI) installed.

---

## Setup and Deployment Steps

Follow these steps in order to configure your environment and run the deployment.

### 1. Create a Virtual Environment

This isolates your project's Python dependencies.

```bash
# Create the virtual environment
python3 -m venv venv
```

After creating it, you must **activate** it:

**On macOS/Linux:**
```bash
source venv/bin/activate
```

**On Windows (Command Prompt):**
```bash
.\venv\Scripts\activate.bat
```

**On Windows (PowerShell):**
```bash
.\venv\Scripts\Activate.ps1
```

### 2. Install Requirements

With your virtual environment activated, install the required Python packages.

```bash
pip install -r requirements.txt
```

### 3. Populate Configuration File (`.env`)

Before running any authentication or deployment commands, you must populate the required fields in the `.env` file.

Open the `.env` file in your editor and fill in the empty variables above the line:
`# --- Script-Managed Variables (do not edit manually unless you know what you are doing) ---`

### 4. Authenticate the gcloud CLI

This step logs you into the `gcloud` command-line tool, which is necessary for running commands to manage your GCP resources (like setting permissions in the next step).

```bash
gcloud auth login
```
> This will open a browser window for you to log in to your Google Account.

### 5. Grant IAM Roles

You need to grant your account the necessary permissions to manage Storage and Vertex AI.

**Important:** Replace `[PROJECT_ID]` with your Google Cloud Project ID and `[YOUR_EMAIL_ACCOUNT]` with the email you used to log in.

```bash
# Grant Storage Admin role
gcloud projects add-iam-policy-binding [PROJECT_ID] \
    --member="user:[YOUR_EMAIL_ACCOUNT]" \
    --role="roles/storage.admin"

# Grant Vertex AI Admin role
gcloud projects add-iam-policy-binding [PROJECT_ID] \
    --member="user:[YOUR_EMAIL_ACCOUNT]" \
    --role="roles/aiplatform.admin"
```

### 6. Set Application Default Credentials (ADC)

This command authenticates your local application code (e.g., Python scripts using Google client libraries) to use your user credentials for API calls.

```bash
gcloud auth application-default login
```

### 7. Run the Deployment Script

Finally, make the deployment script executable and run it.

```bash
# Make the script executable
chmod +x deploy_all.sh

# Run the script
./deploy_all.sh