# Use an official lightweight Python image
FROM python:3.11-slim

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file and install dependencies first
# This leverages Docker's layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application source code and templates
COPY app.py .
COPY templates ./templates

# Cloud Run provides the PORT environment variable.
# We'll use 8080 as a default if it's not set.
ENV PORT 8080

# Command to run the application using uvicorn
# The host 0.0.0.0 is crucial to accept connections from outside the container.
CMD ["uvicorn", "app:asgi_app", "--host", "0.0.0.0", "--port", "8080"]