#!/bin/bash

# Script to install Python dependencies for Charliecloud
# This replaces the old bundled Lark approach with pip-installed dependencies

set -e

echo "Installing Python dependencies for Charliecloud..."
echo "This will install Lark and other required packages via pip."

# Check if we're in the right directory
if [[ ! -f "packaging/requirements.txt" ]]; then
    echo "Error: requirements.txt not found. Please run this script from the Charliecloud root directory."
    exit 1
fi

# Install dependencies
echo "Installing dependencies from packaging/requirements.txt..."
pip3 install -r packaging/requirements.txt

echo "Dependencies installed successfully!"
echo "You can now run './configure' and 'make' to build Charliecloud." 