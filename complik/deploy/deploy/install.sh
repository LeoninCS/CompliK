#!/bin/bash

print() {
  echo -e "\033[1;32m >> $* \033[0m"
}

warn() {
  echo -e "\033[33m >> $* \033[0m"
}

NAMESPACE=${NAMESPACE:-"complik"}
INSTALL_PROCSCAN=${INSTALL_PROCSCAN:-"false"}
ADMIN_BASE_URL=${ADMIN_BASE_URL:-"http://sealos-complik-admin:8080"}
ADMIN_TIMEOUT_SECOND=${ADMIN_TIMEOUT_SECOND:-10}

print "Deploying CompliK service..."
helm upgrade -i complik-service -n ${NAMESPACE} charts/complik \
  --set external.admin.baseURL="${ADMIN_BASE_URL}" \
  --set external.admin.timeoutSecond="${ADMIN_TIMEOUT_SECOND}" \
  --set procscan.enabled="${INSTALL_PROCSCAN}" \
  --create-namespace

if [ "$INSTALL_PROCSCAN" = "true" ]; then
    print "Deploying Procscan..."
    helm upgrade -i procscan -n sealos charts/procscan \
      --set image.tag="${PROCSCAN_IMAGE_TAG:-v0.0.2-alpha-6}" \
      --set config.scanner.scan_interval="${PROCSCAN_SCAN_INTERVAL:-100s}" \
      --set config.notifications.lark.webhook="${PROCSCAN_LARK_WEBHOOK:-""}" \
      --create-namespace
    print "Procscan deployed!"
fi

print "Deployment completed!"
