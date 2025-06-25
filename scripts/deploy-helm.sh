#!/bin/bash
# Deployment script for LDAP User Sync Helm chart

set -e

# Configuration
RELEASE_NAME="${RELEASE_NAME:-ldap-user-sync}"
NAMESPACE="${NAMESPACE:-default}"
CHART_PATH="${CHART_PATH:-helm/ldap-user-sync}"
VALUES_FILE="${VALUES_FILE:-helm/ldap-user-sync/values.yaml}"
DRY_RUN="${DRY_RUN:-false}"

echo "Deploying LDAP User Sync..."
echo "Release: ${RELEASE_NAME}"
echo "Namespace: ${NAMESPACE}"
echo "Chart: ${CHART_PATH}"

# Ensure namespace exists
kubectl create namespace "${NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f -

# Prepare Helm command
HELM_CMD="helm upgrade --install ${RELEASE_NAME} ${CHART_PATH}"
HELM_CMD="${HELM_CMD} --namespace ${NAMESPACE}"
HELM_CMD="${HELM_CMD} --values ${VALUES_FILE}"

# Add environment-specific values if provided
if [ -n "${ENV_VALUES_FILE}" ]; then
    HELM_CMD="${HELM_CMD} --values ${ENV_VALUES_FILE}"
fi

# Add individual value overrides if provided
if [ -n "${IMAGE_TAG}" ]; then
    HELM_CMD="${HELM_CMD} --set image.tag=${IMAGE_TAG}"
fi

if [ -n "${SCHEDULE}" ]; then
    HELM_CMD="${HELM_CMD} --set cronjob.schedule='${SCHEDULE}'"
fi

# Dry run if requested
if [ "${DRY_RUN}" = "true" ]; then
    HELM_CMD="${HELM_CMD} --dry-run --debug"
    echo "Running in dry-run mode..."
fi

# Execute deployment
echo "Running: ${HELM_CMD}"
eval "${HELM_CMD}"

if [ "${DRY_RUN}" != "true" ]; then
    echo ""
    echo "Deployment completed!"
    echo ""
    echo "To check the status:"
    echo "  kubectl get cronjob ${RELEASE_NAME} -n ${NAMESPACE}"
    echo ""
    echo "To view logs:"
    echo "  kubectl logs -l app.kubernetes.io/instance=${RELEASE_NAME} -n ${NAMESPACE}"
    echo ""
    echo "To manually trigger a job:"
    echo "  kubectl create job --from=cronjob/${RELEASE_NAME} ${RELEASE_NAME}-manual -n ${NAMESPACE}"
fi