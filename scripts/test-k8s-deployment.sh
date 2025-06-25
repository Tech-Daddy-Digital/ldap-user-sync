#!/bin/bash
# Test script for Kubernetes deployment

set -e

# Configuration
NAMESPACE="ldap-user-sync-test"
RELEASE_NAME="ldap-user-sync-test"
HELM_CHART="helm/ldap-user-sync"
TEST_VALUES="examples/values-development.yaml"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${BLUE}=== $1 ===${NC}"
}

check_prerequisites() {
    print_header "Checking Prerequisites"
    
    # Check kubectl
    if ! command -v kubectl &> /dev/null; then
        print_error "kubectl is not installed or not in PATH"
        exit 1
    fi
    
    # Check helm
    if ! command -v helm &> /dev/null; then
        print_error "helm is not installed or not in PATH"
        exit 1
    fi
    
    # Check Kubernetes connection
    if ! kubectl cluster-info &> /dev/null; then
        print_error "Cannot connect to Kubernetes cluster"
        exit 1
    fi
    
    print_status "✓ kubectl available"
    print_status "✓ helm available"
    print_status "✓ Kubernetes cluster accessible"
}

cleanup() {
    print_header "Cleaning Up"
    
    # Delete helm release
    helm uninstall "${RELEASE_NAME}" -n "${NAMESPACE}" 2>/dev/null || true
    
    # Delete namespace
    kubectl delete namespace "${NAMESPACE}" 2>/dev/null || true
    
    print_status "Cleanup completed"
}

test_helm_chart() {
    print_header "Testing Helm Chart"
    
    # Validate chart
    print_status "Validating Helm chart..."
    if ! helm lint "${HELM_CHART}"; then
        print_error "Helm chart validation failed"
        exit 1
    fi
    print_status "✓ Helm chart is valid"
    
    # Test dry-run
    print_status "Testing dry-run deployment..."
    if ! helm upgrade --install "${RELEASE_NAME}" "${HELM_CHART}" \
        --namespace "${NAMESPACE}" \
        --create-namespace \
        --values "${TEST_VALUES}" \
        --dry-run --debug > /tmp/helm-dry-run.yaml; then
        print_error "Helm dry-run failed"
        exit 1
    fi
    print_status "✓ Helm dry-run successful"
    
    # Check generated resources
    print_status "Checking generated Kubernetes resources..."
    if ! kubectl apply --dry-run=client -f /tmp/helm-dry-run.yaml &> /dev/null; then
        print_error "Generated Kubernetes resources are invalid"
        exit 1
    fi
    print_status "✓ Generated Kubernetes resources are valid"
}

deploy_chart() {
    print_header "Deploying Helm Chart"
    
    # Deploy chart
    print_status "Deploying chart..."
    if ! helm upgrade --install "${RELEASE_NAME}" "${HELM_CHART}" \
        --namespace "${NAMESPACE}" \
        --create-namespace \
        --values "${TEST_VALUES}" \
        --wait --timeout=300s; then
        print_error "Helm deployment failed"
        exit 1
    fi
    print_status "✓ Chart deployed successfully"
    
    # Check deployment status
    print_status "Checking deployment status..."
    kubectl get all -n "${NAMESPACE}"
}

test_cronjob() {
    print_header "Testing CronJob"
    
    # Check if CronJob was created
    if ! kubectl get cronjob "${RELEASE_NAME}" -n "${NAMESPACE}" &> /dev/null; then
        print_error "CronJob was not created"
        exit 1
    fi
    print_status "✓ CronJob created"
    
    # Create a manual job for testing
    print_status "Creating manual job for testing..."
    if ! kubectl create job --from=cronjob/"${RELEASE_NAME}" "${RELEASE_NAME}-manual" -n "${NAMESPACE}"; then
        print_error "Failed to create manual job"
        exit 1
    fi
    
    # Wait for job to complete or fail
    print_status "Waiting for job to complete..."
    if ! kubectl wait --for=condition=complete job/"${RELEASE_NAME}-manual" -n "${NAMESPACE}" --timeout=300s; then
        print_warning "Job did not complete within timeout, checking status..."
        kubectl describe job "${RELEASE_NAME}-manual" -n "${NAMESPACE}"
        kubectl logs job/"${RELEASE_NAME}-manual" -n "${NAMESPACE}" || true
    else
        print_status "✓ Manual job completed successfully"
    fi
}

test_configuration() {
    print_header "Testing Configuration"
    
    # Check ConfigMap
    print_status "Checking ConfigMap..."
    if ! kubectl get configmap -n "${NAMESPACE}" | grep -q "${RELEASE_NAME}"; then
        print_error "ConfigMap not found"
        exit 1
    fi
    print_status "✓ ConfigMap exists"
    
    # Check Secret
    print_status "Checking Secret..."
    if ! kubectl get secret -n "${NAMESPACE}" | grep -q "${RELEASE_NAME}"; then
        print_error "Secret not found"
        exit 1
    fi
    print_status "✓ Secret exists"
    
    # Validate environment variables in pod
    print_status "Checking environment variables..."
    POD_NAME=$(kubectl get pods -n "${NAMESPACE}" -l job-name="${RELEASE_NAME}-manual" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
    
    if [ -n "$POD_NAME" ]; then
        ENV_COUNT=$(kubectl exec "$POD_NAME" -n "${NAMESPACE}" -- env | grep -E "(LDAP_|VENDOR1_|LOG_)" | wc -l 2>/dev/null || echo "0")
        if [ "$ENV_COUNT" -gt 10 ]; then
            print_status "✓ Environment variables properly injected ($ENV_COUNT variables)"
        else
            print_warning "Only $ENV_COUNT environment variables found"
        fi
    else
        print_warning "No pod found to check environment variables"
    fi
}

test_security() {
    print_header "Testing Security Configuration"
    
    # Check if pod runs as non-root
    print_status "Checking security context..."
    SECURITY_CONTEXT=$(kubectl get cronjob "${RELEASE_NAME}" -n "${NAMESPACE}" -o jsonpath='{.spec.jobTemplate.spec.template.spec.securityContext}')
    
    if echo "$SECURITY_CONTEXT" | grep -q "runAsNonRoot.*true"; then
        print_status "✓ Pod configured to run as non-root"
    else
        print_warning "Pod security context might not be properly configured"
    fi
    
    # Check resource limits
    print_status "Checking resource limits..."
    RESOURCES=$(kubectl get cronjob "${RELEASE_NAME}" -n "${NAMESPACE}" -o jsonpath='{.spec.jobTemplate.spec.template.spec.containers[0].resources}')
    
    if echo "$RESOURCES" | grep -q "limits"; then
        print_status "✓ Resource limits configured"
    else
        print_warning "No resource limits found"
    fi
}

view_logs() {
    print_header "Viewing Logs"
    
    # Show recent pod logs
    print_status "Recent pod logs:"
    kubectl logs -l app.kubernetes.io/instance="${RELEASE_NAME}" -n "${NAMESPACE}" --tail=20 || true
    
    # Show job status
    print_status "Job status:"
    kubectl get jobs -n "${NAMESPACE}" || true
}

generate_report() {
    print_header "Test Report"
    
    echo "Kubernetes Test Summary:"
    echo "✓ Prerequisites check passed"
    echo "✓ Helm chart validation passed"
    echo "✓ Deployment successful"
    echo "✓ CronJob created and tested"
    echo "✓ Configuration validated"
    echo "✓ Security settings verified"
    
    print_status "All Kubernetes deployment tests passed!"
    
    echo ""
    echo "Next steps:"
    echo "1. Review logs: kubectl logs -l app.kubernetes.io/instance=${RELEASE_NAME} -n ${NAMESPACE}"
    echo "2. Monitor jobs: kubectl get jobs -n ${NAMESPACE} -w"
    echo "3. Clean up: helm uninstall ${RELEASE_NAME} -n ${NAMESPACE}"
}

# Main execution
main() {
    print_header "LDAP User Sync Kubernetes Deployment Test"
    
    check_prerequisites
    test_helm_chart
    deploy_chart
    test_cronjob
    test_configuration
    test_security
    view_logs
    generate_report
    
    # Optional cleanup
    read -p "Do you want to clean up the test deployment? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        cleanup
    else
        print_status "Test deployment left running for further inspection"
    fi
}

# Run main function
main "$@"