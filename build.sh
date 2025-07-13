#!/usr/bin/env bash
# Build script for Render deployment

echo "Starting build process..."

# Install Python dependencies
pip install -r requirements.txt

# Create uploads directory if it doesn't exist
mkdir -p uploads

# Set proper permissions
chmod 755 uploads

echo "Build completed successfully!" 