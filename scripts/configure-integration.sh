#!/bin/bash
# Cortex-TheHive Integration Configuration Script

set -e

echo "=== Cortex-TheHive Integration Configuration ==="

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

# Variables
CORTEX_URL="http://127.0.0.1:9001"
THEHIVE_URL="http://127.0.0.1:9000"
CORTEX_ADMIN_USER="admin"
CORTEX_ADMIN_PASS="admin"
ORG_ADMIN_USER="thehive-user"
ORG_ADMIN_PASS="TheHive123!"

# Check if services are running
check_services() {
    log_info "Checking if services are running..."
    
    if ! curl -s "${CORTEX_URL}/api/status" >/dev/null; then
        log_warn "Cortex is not accessible at ${CORTEX_URL}"
        return 1
    fi
    
    if ! curl -s "${THEHIVE_URL}/api/status" >/dev/null; then
        log_warn "TheHive is not accessible at ${THEHIVE_URL}"
        return 1
    fi
    
    log_info "Both services are accessible"
    return 0
}

# Create organization admin in Cortex
create_org_admin() {
    log_info "Creating organization admin user in Cortex..."
    
    # First, get authentication token
    AUTH_RESPONSE=$(curl -s -XPOST "${CORTEX_URL}/api/login" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"${CORTEX_ADMIN_USER}\",\"password\":\"${CORTEX_ADMIN_PASS}\"}")
    
    if echo "${AUTH_RESPONSE}" | grep -q "error"; then
        log_warn "Failed to authenticate with Cortex. Using default credentials."
        log_warn "Please manually create an org-admin user in Cortex UI:"
        log_warn "1. Go to ${CORTEX_URL}"
        log_warn "2. Login with admin/admin"
        log_warn "3. Go to Organization → Users"
        log_warn "4. Create user with org-admin role"
        log_warn "5. Generate API key for the user"
        return 1
    fi
    
    TOKEN=$(echo "${AUTH_RESPONSE}" | grep -o '"token":"[^"]*' | cut -d'"' -f4)
    
    # Create organization admin user
    USER_CREATE_RESPONSE=$(curl -s -XPOST "${CORTEX_URL}/api/user" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${TOKEN}" \
        -d "{
            \"name\": \"${ORG_ADMIN_USER}\",
            \"password\": \"${ORG_ADMIN_PASS}\",
            \"roles\": [\"read\", \"analyze\", \"orgAdmin\"]
        }")
    
    if echo "${USER_CREATE_RESPONSE}" | grep -q "error"; then
        log_warn "Failed to create user: ${USER_CREATE_RESPONSE}"
        return 1
    fi
    
    log_info "Organization admin user created: ${ORG_ADMIN_USER}"
    
    # Generate API key
    API_KEY_RESPONSE=$(curl -s -XPOST "${CORTEX_URL}/api/user/${ORG_ADMIN_USER}/key/renew" \
        -H "Authorization: Bearer ${TOKEN}")
    
    API_KEY=$(echo "${API_KEY_RESPONSE}" | grep -o '"key":"[^"]*' | cut -d'"' -f4)
    
    if [[ -n "${API_KEY}" ]]; then
        log_info "API Key generated: ${API_KEY}"
        echo "${API_KEY}" > cortex-api-key.txt
        log_info "API key saved to cortex-api-key.txt"
        return 0
    else
        log_warn "Failed to generate API key"
        return 1
    fi
}

# Configure TheHive Cortex connector
configure_thehive_connector() {
    log_info "Configuring TheHive Cortex connector..."
    
    if [[ ! -f "cortex-api-key.txt" ]]; then
        log_warn "API key file not found. Please configure manually:"
        log_warn "1. Get API key from Cortex UI"
        log_warn "2. Edit /etc/thehive/application.conf"
        log_warn "3. Add Cortex server configuration with API key"
        return 1
    fi
    
    API_KEY=$(cat cortex-api-key.txt)
    
    # Backup current configuration
    cp /etc/thehive/application.conf /etc/thehive/application.conf.backup.$(date +%Y%m%d-%H%M%S)
    
    # Add Cortex configuration to TheHive config
    cat >> /etc/thehive/application.conf << EOF

# Cortex connector configuration
cortex {
  servers = [
    {
      name = "local-cortex"
      url = "http://127.0.0.1:9001"
      auth {
        type = "bearer"
        key = "${API_KEY}"
      }
    }
  ]
}
EOF
    
    log_info "TheHive configuration updated"
    
    # Restart TheHive
    systemctl restart thehive
    log_info "TheHive service restarted"
}

# Test integration
test_integration() {
    log_info "Testing Cortex-TheHive integration..."
    
    sleep 10  # Wait for services to start
    
    # Test Cortex analyzers from TheHive
    if curl -s "${THEHIVE_URL}/api/connector/cortex/analyzer" | grep -q "name"; then
        log_info "✅ Integration successful! Cortex analyzers are accessible from TheHive"
    else
        log_warn "❌ Integration test failed. Please check the configuration manually."
    fi
}

# Main execution
main() {
    log_info "Starting Cortex-TheHive integration configuration..."
    
    if check_services; then
        if create_org_admin; then
            configure_thehive_connector
            test_integration
        fi
    fi
    
    log_info "Configuration process completed"
    echo -e "\n=== Next Steps ==="
    echo "1. Access TheHive UI: ${THEHIVE_URL}"
    echo "2. Go to Administration → Connectors → Cortex"
    echo "3. Verify Cortex server is connected"
    echo "4. Test analyzers by creating a test case"
}

main "$@"
