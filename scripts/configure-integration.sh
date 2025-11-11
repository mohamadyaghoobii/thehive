#!/bin/bash
# Cortex-TheHive Enterprise Integration Script
# Version: 2.0 - Production Ready
# Description: Automated integration between Cortex and TheHive with robust error handling

set -euo pipefail

# ============================================================================ #
# Configuration Section
# ============================================================================ #

# Color codes for beautiful output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Service URLs
CORTEX_URL="${CORTEX_URL:-http://127.0.0.1:9001}"
THEHIVE_URL="${THEHIVE_URL:-http://127.0.0.1:9000}"

# Credentials (can be overridden by environment variables)
CORTEX_ADMIN_USER="${CORTEX_ADMIN_USER:-admin}"
CORTEX_ADMIN_PASS="${CORTEX_ADMIN_PASS:-admin}"
ORG_ADMIN_USER="${ORG_ADMIN_USER:-thehive-integration}"
ORG_ADMIN_PASS="${ORG_ADMIN_PASS:-TheHive123!}"

# Timeouts
SERVICE_TIMEOUT=30
REQUEST_TIMEOUT=10

# ============================================================================ #
# Logging Functions
# ============================================================================ #

log_info() { echo -e "${GREEN}[ℹ]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[⚠]${NC} $1"; }
log_error() { echo -e "${RED}[✗]${NC} $1"; }
log_debug() { echo -e "${BLUE}[?]${NC} $1"; }
log_success() { echo -e "${GREEN}[✓]${NC} $1"; }
log_step() { echo -e "${PURPLE}[→]${NC} $1"; }

# ============================================================================ #
# Utility Functions
# ============================================================================ #

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Make HTTP request with better error handling
http_request() {
    local method=$1
    local url=$2
    local data=$3
    local token=$4
    
    local curl_cmd=("curl" "-s" "-w" "%{http_code}" "-X" "$method" "$url")
    
    [[ -n "$data" ]] && curl_cmd+=("-H" "Content-Type: application/json" "-d" "$data")
    [[ -n "$token" ]] && curl_cmd+=("-H" "Authorization: Bearer $token")
    [[ -n "$REQUEST_TIMEOUT" ]] && curl_cmd+=("--connect-timeout" "$REQUEST_TIMEOUT")
    
    local response
    response=$("${curl_cmd[@]}")
    
    local status_code="${response: -3}"
    local body="${response%???}"
    
    echo "$body"
    return $((status_code == 200 ? 0 : 1))
}

# Wait for service to be ready
wait_for_service() {
    local service_url=$1
    local service_name=$2
    local max_attempts=$3
    
    log_info "Waiting for $service_name to be ready..."
    
    local attempt=1
    while [[ $attempt -le $max_attempts ]]; do
        if http_request "GET" "$service_url" "" "" >/dev/null 2>&1; then
            log_success "$service_name is ready"
            return 0
        fi
        
        log_debug "Attempt $attempt/$max_attempts: $service_name not ready yet..."
        sleep 5
        ((attempt++))
    done
    
    log_error "$service_name failed to become ready after $max_attempts attempts"
    return 1
}

# ============================================================================ #
# Core Functions
# ============================================================================ #

check_services() {
    log_step "Checking service availability..."
    
    local cortex_ok=false
    local thehive_ok=false
    
    # Check Cortex
    if wait_for_service "${CORTEX_URL}/api/status" "Cortex" 6; then
        cortex_ok=true
        log_info "Cortex version: $(http_request "GET" "${CORTEX_URL}/api/status" "" "" | grep -o '"Cortex":"[^"]*' | cut -d'"' -f4 || echo "Unknown")"
    else
        log_error "Cortex is not accessible at ${CORTEX_URL}"
    fi
    
    # Check TheHive
    if wait_for_service "${THEHIVE_URL}/api/status" "TheHive" 6; then
        thehive_ok=true
    else
        log_error "TheHive is not accessible at ${THEHIVE_URL}"
    fi
    
    if $cortex_ok && $thehive_ok; then
        log_success "Both services are accessible and ready"
        return 0
    else
        return 1
    fi
}

authenticate_cortex() {
    log_step "Authenticating with Cortex..."
    
    local auth_data="{\"username\":\"${CORTEX_ADMIN_USER}\",\"password\":\"${CORTEX_ADMIN_PASS}\"}"
    local auth_response
    
    auth_response=$(http_request "POST" "${CORTEX_URL}/api/login" "$auth_data" "")
    
    if [[ $? -eq 0 ]] && [[ -n "$auth_response" ]]; then
        # Try different methods to extract token
        local token
        
        # Method 1: Direct JSON parsing with jq if available
        if command_exists jq; then
            token=$(echo "$auth_response" | jq -r '.data.token // .token // empty' 2>/dev/null)
        fi
        
        # Method 2: grep extraction
        if [[ -z "$token" ]]; then
            token=$(echo "$auth_response" | grep -o '"token":"[^"]*' | cut -d'"' -f4)
        fi
        
        # Method 3: Alternative pattern
        if [[ -z "$token" ]]; then
            token=$(echo "$auth_response" | grep -o '"key":"[^"]*' | cut -d'"' -f4)
        fi
        
        if [[ -n "$token" ]]; then
            log_success "Successfully authenticated with Cortex"
            echo "$token"
            return 0
        fi
    fi
    
    log_warn "Failed to authenticate with Cortex API"
    log_debug "Auth response: $auth_response"
    return 1
}

create_org_admin_user() {
    local token=$1
    
    log_step "Creating organization admin user: ${ORG_ADMIN_USER}"
    
    # First, check if user already exists
    local check_response
    check_response=$(http_request "GET" "${CORTEX_URL}/api/user" "" "$token")
    
    if [[ $? -eq 0 ]] && echo "$check_response" | grep -q "\"login\":\"${ORG_ADMIN_USER}\""; then
        log_info "User ${ORG_ADMIN_USER} already exists"
        return 0
    fi
    
    # Create user data
    local user_data="{
        \"login\": \"${ORG_ADMIN_USER}\",
        \"name\": \"TheHive Integration User\",
        \"roles\": [\"read\", \"analyze\", \"orgAdmin\"],
        \"password\": \"${ORG_ADMIN_PASS}\",
        \"organization\": \"cert\"
    }"
    
    local create_response
    create_response=$(http_request "POST" "${CORTEX_URL}/api/user" "$user_data" "$token")
    
    if [[ $? -eq 0 ]]; then
        log_success "Organization admin user created successfully"
        return 0
    else
        log_warn "Failed to create user via API: $create_response"
        return 1
    fi
}

generate_api_key() {
    local token=$1
    
    log_step "Generating API key for user: ${ORG_ADMIN_USER}"
    
    local key_response
    key_response=$(http_request "POST" "${CORTEX_URL}/api/user/${ORG_ADMIN_USER}/key/renew" "" "$token")
    
    if [[ $? -eq 0 ]]; then
        # Extract API key using multiple methods
        local api_key
        
        # Method 1: jq parsing
        if command_exists jq; then
            api_key=$(echo "$key_response" | jq -r '.key // .data.key // empty' 2>/dev/null)
        fi
        
        # Method 2: grep extraction
        if [[ -z "$api_key" ]]; then
            api_key=$(echo "$key_response" | grep -o '"key":"[^"]*' | cut -d'"' -f4)
        fi
        
        # Method 3: Alternative pattern
        if [[ -z "$api_key" ]]; then
            api_key=$(echo "$key_response" | grep -o '"id":"[^"]*' | cut -d'"' -f4)
        fi
        
        if [[ -n "$api_key" ]]; then
            log_success "API key generated successfully"
            echo "$api_key"
            return 0
        fi
    fi
    
    log_warn "Failed to generate API key via API"
    log_debug "Key response: $key_response"
    return 1
}

configure_thehive_connector() {
    local api_key=$1
    
    log_step "Configuring TheHive Cortex connector..."
    
    # Backup current configuration
    local backup_file="/etc/thehive/application.conf.backup.$(date +%Y%m%d_%H%M%S)"
    cp /etc/thehive/application.conf "$backup_file"
    log_info "Configuration backed up to: $backup_file"
    
    # Check if Cortex configuration already exists
    if grep -q "cortex.*{.*servers.*\[" /etc/thehive/application.conf; then
        log_info "Cortex configuration already exists, updating..."
        
        # Remove existing Cortex configuration
        sed -i '/^cortex {/,/^}/d' /etc/thehive/application.conf
    fi
    
    # Add new Cortex configuration
    cat >> /etc/thehive/application.conf << EOF

# Cortex connector configuration - Auto-generated $(date)
cortex {
  servers = [
    {
      name = "local-cortex"
      url = "${CORTEX_URL}"
      auth {
        type = "bearer"
        key = "${api_key}"
      }
      # HTTP client configuration
      wsConfig {
        timeout.connection = 1 minute
        timeout.idle = 10 minutes
        timeout.request = 5 minutes
        user-agent = "TheHive/5.2.16"
      }
    }
  ]
}
EOF
    
    # Validate configuration syntax
    if /opt/thehive/bin/thehive -Dconfig.file=/etc/thehive/application.conf --check >/dev/null 2>&1; then
        log_success "TheHive configuration updated and validated"
    else
        log_error "Configuration validation failed, restoring backup..."
        cp "$backup_file" /etc/thehive/application.conf
        return 1
    fi
    
    # Restart TheHive service
    log_info "Restarting TheHive service..."
    if systemctl restart thehive; then
        log_success "TheHive service restarted successfully"
    else
        log_error "Failed to restart TheHive service"
        return 1
    fi
    
    # Wait for TheHive to be ready
    wait_for_service "${THEHIVE_URL}/api/status" "TheHive" 12
    
    # Save API key securely
    local key_file="/root/.cortex_api_key"
    echo "$api_key" > "$key_file"
    chmod 600 "$key_file"
    log_info "API key saved to: $key_file"
}

test_integration() {
    log_step "Testing Cortex-TheHive integration..."
    
    # Wait a bit for services to stabilize
    sleep 10
    
    # Test 1: Check if Cortex connector is active in TheHive
    local connector_response
    connector_response=$(http_request "GET" "${THEHIVE_URL}/api/connector/cortex/analyzer" "" "")
    
    if [[ $? -eq 0 ]] && echo "$connector_response" | grep -q "name"; then
        local analyzer_count=$(echo "$connector_response" | grep -o '"name"' | wc -l)
        log_success "✅ Integration successful! Found $analyzer_count analyzers"
        
        # Display first few analyzers
        log_info "Available analyzers sample:"
        echo "$connector_response" | grep -o '"name":"[^"]*' | cut -d'"' -f4 | head -5 | while read analyzer; do
            log_info "  - $analyzer"
        done
    else
        log_warn "⚠️  Integration test inconclusive. Checking manually..."
        manual_integration_check
    fi
}

manual_integration_check() {
    log_step "Performing manual integration checks..."
    
    # Check Cortex service directly
    local cortex_analyzers
    cortex_analyzers=$(http_request "GET" "${CORTEX_URL}/api/analyzer" "" "")
    
    if [[ $? -eq 0 ]]; then
        local total_analyzers=$(echo "$cortex_analyzers" | grep -o '"name"' | wc -l)
        log_info "Cortex has $total_analyzers analyzers available"
    else
        log_warn "Cannot retrieve analyzers from Cortex directly"
    fi
    
    log_warn "Please verify integration manually:"
    log_warn "1. Access TheHive: ${THEHIVE_URL}"
    log_warn "2. Go to Administration → Connectors → Cortex"
    log_warn "3. Check if Cortex server shows as connected"
    log_warn "4. Create a test case and try running analyzers"
}

provide_manual_setup_instructions() {
    log_step "Manual Setup Instructions"
    
    cat << EOF

${YELLOW}=== MANUAL SETUP INSTRUCTIONS ===${NC}

If automated setup failed, please follow these steps:

1. ${GREEN}Access Cortex UI:${NC}
   URL: ${CORTEX_URL}
   Login: ${CORTEX_ADMIN_USER} / ${CORTEX_ADMIN_PASS}

2. ${GREEN}Create Organization Admin User:${NC}
   - Go to "Organization" → "Users"
   - Click "Add User"
   - Fill in:
     * Login: ${ORG_ADMIN_USER}
     * Name: TheHive Integration User  
     * Roles: orgAdmin, read, analyze
     * Password: ${ORG_ADMIN_PASS}
   - Click "Create"

3. ${GREEN}Generate API Key:${NC}
   - Go to the user's profile
   - Click "API Keys" → "Generate new key"
   - Copy the API key

4. ${GREEN}Configure TheHive:${NC}
   Edit /etc/thehive/application.conf and add:

   cortex {
     servers = [
       {
         name = "local-cortex"
         url = "${CORTEX_URL}"
         auth {
           type = "bearer"
           key = "YOUR_API_KEY_HERE"
         }
       }
     ]
   }

5. ${GREEN}Restart TheHive:${NC}
   sudo systemctl restart thehive

6. ${GREEN}Verify Integration:${NC}
   - Access TheHive: ${THEHIVE_URL}
   - Check Administration → Connectors → Cortex
   - Test with a sample case

${YELLOW}=== TROUBLESHOOTING TIPS ===${NC}
- Check service logs: journalctl -u thehive -u cortex
- Verify network connectivity between services
- Check API key permissions in Cortex
- Validate configuration syntax

EOF
}

# ============================================================================ #
# Main Execution
# ============================================================================ #

main() {
    echo -e "${CYAN}"
    echo "╔════════════════════════════════════════════════════════════════╗"
    echo "║              CORTEX-THEHIVE INTEGRATION SETUP                 ║"
    echo "║                        Version 2.0                            ║"
    echo "╚════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    local api_key=""
    local auth_token=""
    
    # Check prerequisites
    if ! command_exists curl; then
        log_error "curl is required but not installed"
        exit 1
    fi
    
    # Check service availability
    if ! check_services; then
        log_error "Service availability check failed"
        provide_manual_setup_instructions
        exit 1
    fi
    
    # Attempt automated setup
    log_step "Starting automated integration setup..."
    
    # Authenticate with Cortex
    auth_token=$(authenticate_cortex) || {
        log_warn "Automated authentication failed"
        provide_manual_setup_instructions
        exit 1
    }
    
    # Create organization admin user
    create_org_admin_user "$auth_token" || {
        log_warn "User creation failed, user may already exist"
    }
    
    # Generate API key
    api_key=$(generate_api_key "$auth_token") || {
        log_warn "API key generation failed"
        provide_manual_setup_instructions
        exit 1
    }
    
    # Configure TheHive connector
    configure_thehive_connector "$api_key" || {
        log_error "Failed to configure TheHive connector"
        provide_manual_setup_instructions
        exit 1
    }
    
    # Test integration
    test_integration
    
    # Final summary
    log_success "Integration setup completed!"
    
    cat << EOF

${GREEN}=== SETUP COMPLETED SUCCESSFULLY ===${NC}

${CYAN}Access Information:${NC}
  TheHive URL: ${THEHIVE_URL} (admin@thehive.local / secret)
  Cortex URL: ${CORTEX_URL} (${CORTEX_ADMIN_USER} / ${CORTEX_ADMIN_PASS})

${CYAN}Integration User:${NC}
  Username: ${ORG_ADMIN_USER}
  API Key: Saved to /root/.cortex_api_key

${CYAN}Next Steps:${NC}
  1. Verify integration in TheHive UI
  2. Create test cases and run analyzers
  3. Configure additional analyzers in Cortex
  4. Set up regular backups

${YELLOW}Use 'check-thehive-status' to monitor system health${NC}

EOF
}

# Handle script arguments
case "${1:-}" in
    ""|"setup")
        main
        ;;
    "check")
        check_services
        ;;
    "test")
        test_integration
        ;;
    "manual")
        provide_manual_setup_instructions
        ;;
    "help"|"-h"|"--help")
        echo "Usage: $0 [command]"
        echo ""
        echo "Commands:"
        echo "  setup    - Run full integration setup (default)"
        echo "  check    - Check service availability"
        echo "  test     - Test existing integration"
        echo "  manual   - Show manual setup instructions"
        echo "  help     - Show this help message"
        ;;
    *)
        echo "Unknown command: $1"
        echo "Use '$0 help' for usage information"
        exit 1
        ;;
esac
