#!/bin/bash
#
# Installation script for the gti-mcp tool.
# This script installs system dependencies and uses 'uv' to install the tool.

# Exit immediately if a command exits with a non-zero status.
set -e

# --- Script Start ---
echo "🚀 Starting gti-mcp tool installation..."

# 1. Check for root privileges
if [ "$(id -u)" -ne 0 ]; then
   echo "❌ This script must be run as root. Please use 'sudo bash install.sh'." >&2
   exit 1
fi

# 2. Install System Dependencies
echo "📦 Updating package list and installing dependencies (git, curl)..."
apt-get update
# git might be needed if gti-mcp has git-based dependencies
apt-get install -y git curl

# 3. Install uv (Python Package Manager)
echo "📦 Installing uv..."
curl -LsSf https://astral.sh/uv/install.sh | env UV_INSTALL_DIR="/usr/local/bin" sh

# 4. Install the gti-mcp tool
echo "🐍 Installing the gti-mcp tool system-wide using uv..."
# 'uv tool install' creates an isolated virtual environment for the tool
# and adds the executable to a managed path (~/.local/bin by default for uv).
# For system-wide access, you may need to ensure /root/.local/bin is in the PATH
# for services or adjust the uv installation.
uv tool install gti-mcp
echo "   -> 'gti-mcp' tool installed successfully."

# --- Final Instructions ---
echo ""
echo "✅ Setup complete!"
echo "The 'gti-mcp' tool has been installed."
echo ""
echo "--- How to Run the Server ---"
echo "You can now run the server using the 'uvx' command:"
echo "uvx gti_mcp"
echo ""
echo "Note: If you run this as a service, ensure the user running the service"
echo "has the uv tools directory (e.g., /root/.local/bin) in its PATH."