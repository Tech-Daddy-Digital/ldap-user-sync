#!/bin/bash
# Build script for LDAP User Sync container

set -e

# Configuration
REGISTRY="${REGISTRY:-docker.io}"
REPOSITORY="${REPOSITORY:-ldap-user-sync}"
TAG="${TAG:-1.0.0}"
PLATFORM="${PLATFORM:-linux/amd64}"

# Full image name
IMAGE_NAME="${REGISTRY}/${REPOSITORY}:${TAG}"

echo "Building LDAP User Sync container..."
echo "Image: ${IMAGE_NAME}"
echo "Platform: ${PLATFORM}"

# Build the container
docker build \
    --platform "${PLATFORM}" \
    --tag "${IMAGE_NAME}" \
    --tag "${REGISTRY}/${REPOSITORY}:latest" \
    .

echo "Container built successfully!"
echo "Image name: ${IMAGE_NAME}"

# Optional: Push to registry
if [ "${PUSH:-false}" = "true" ]; then
    echo "Pushing to registry..."
    docker push "${IMAGE_NAME}"
    docker push "${REGISTRY}/${REPOSITORY}:latest"
    echo "Push completed!"
fi

# Optional: Run security scan
if [ "${SCAN:-false}" = "true" ]; then
    echo "Running security scan..."
    if command -v trivy &> /dev/null; then
        trivy image "${IMAGE_NAME}"
    else
        echo "Trivy not found, skipping security scan"
    fi
fi

echo "Build process completed!"