#!/bin/bash
# TheHive & Cortex Auto-Deployment Script
# Version: 1.0
# Description: Automated deployment of TheHive 5.2.16 and Cortex 3.1.8

set -e

echo "=== TheHive & Cortex Deployment ==="
echo "This script will install and configure TheHive 5.2.16 and Cortex 3.1.8"

# Variables
THEHIVE_VERSION="5.2.16-1"
CORTEX_VERSION="3.1.8-1"
INSTALL_DIR="/opt"
CONFIG_DIR="/etc"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

# Install dependencies
install_dependencies() {
    log_info "Installing dependencies..."
    apt update
    apt install -y openjdk-11-jdk curl wget gnupg2 software-properties-common
    
    # Install Elasticsearch
    log_info "Installing Elasticsearch..."
    wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | apt-key add -
    echo "deb https://artifacts.elastic.co/packages/7.x/apt stable main" | tee /etc/apt/sources.list.d/elastic-7.x.list
    apt update
    apt install -y elasticsearch=7.17.29
    
    # Install Cassandra
    log_info "Installing Cassandra..."
    echo "deb http://downloads.apache.org/cassandra/debian 311x main" | tee /etc/apt/sources.list.d/cassandra.list
    curl https://downloads.apache.org/cassandra/KEYS | apt-key add -
    apt update
    apt install -y cassandra
}

# Download and install TheHive
install_thehive() {
    log_info "Installing TheHive ${THEHIVE_VERSION}..."
    cd /tmp
    wget -q "https://thehive.download.strangebee.com/5.2/deb/thehive_${THEHIVE_VERSION}_all.deb"
    
    if [[ $? -ne 0 ]]; then
        log_error "Failed to download TheHive package"
        exit 1
    fi
    
    dpkg -i "thehive_${THEHIVE_VERSION}_all.deb" || true
    apt --fix-broken install -y
    
    log_info "TheHive installation completed"
}

# Download and install Cortex
install_cortex() {
    log_info "Installing Cortex ${CORTEX_VERSION}..."
    cd /tmp
    wget -q "https://download.thehive-project.org/package/cortex-${CORTEX_VERSION}.deb"
    
    if [[ $? -ne 0 ]]; then
        log_error "Failed to download Cortex package"
        exit 1
    fi
    
    dpkg -i "cortex-${CORTEX_VERSION}.deb" || true
    apt --fix-broken install -y
    
    log_info "Cortex installation completed"
}

# Configure services
configure_services() {
    log_info "Configuring services..."
    
    # Copy configuration files
    cp configs/thehive/application.conf ${CONFIG_DIR}/thehive/
    cp configs/cortex/application.conf ${CONFIG_DIR}/cortex/
    cp systemd/thehive.service ${CONFIG_DIR}/systemd/system/
    cp systemd/cortex.service ${CONFIG_DIR}/systemd/system/
    
    # Set permissions
    chown thehive:thehive ${CONFIG_DIR}/thehive/application.conf
    chown cortex:cortex ${CONFIG_DIR}/cortex/application.conf
    chmod 640 ${CONFIG_DIR}/thehive/application.conf
    chmod 640 ${CONFIG_DIR}/cortex/application.conf
    
    # Create data directories
    mkdir -p /opt/thp/thehive/{database,index,files}
    chown -R thehive:thehive /opt/thp/thehive/
}

# Start and enable services
start_services() {
    log_info "Starting services..."
    
    # Start Elasticsearch and Cassandra first
    systemctl daemon-reload
    systemctl enable elasticsearch cassandra
    systemctl start elasticsearch cassandra
    
    # Wait for services to be ready
    log_info "Waiting for Elasticsearch and Cassandra to start..."
    sleep 30
    
    # Start TheHive and Cortex
    systemctl enable thehive cortex
    systemctl start thehive cortex
    
    log_info "Waiting for services to initialize..."
    sleep 20
}

# Verify installation
verify_installation() {
    log_info "Verifying installation..."
    
    # Check service status
    echo -e "\n=== Service Status ==="
    systemctl is-active --quiet thehive && echo "TheHive: ✅ Running" || echo "TheHive: ❌ Failed"
    systemctl is-active --quiet cortex && echo "Cortex: ✅ Running" || echo "Cortex: ❌ Failed"
    systemctl is-active --quiet elasticsearch && echo "Elasticsearch: ✅ Running" || echo "Elasticsearch: ❌ Failed"
    systemctl is-active --quiet cassandra && echo "Cassandra: ✅ Running" || echo "Cassandra: ❌ Failed"
    
    # Test API endpoints
    echo -e "\n=== API Tests ==="
    curl -s http://127.0.0.1:9000/api/status >/dev/null && echo "TheHive API: ✅ Accessible" || echo "TheHive API: ❌ Not accessible"
    curl -s http://127.0.0.1:9001/api/status >/dev/null && echo "Cortex API: ✅ Accessible" || echo "Cortex API: ❌ Not accessible"
    
    # Check ports
    echo -e "\n=== Port Check ==="
    netstat -tulpn | grep -E '(9000|9001)' | grep LISTEN
}

# Main execution
main() {
    log_info "Starting deployment process..."
    check_root
    
    # Create backup of existing configurations
    if [[ -f "${CONFIG_DIR}/thehive/application.conf" ]]; then
        log_info "Backing up existing configurations..."
        cp ${CONFIG_DIR}/thehive/application.conf backups/thehive-application.conf.backup.$(date +%Y%m%d-%H%M%S)
    fi
    
    if [[ -f "${CONFIG_DIR}/cortex/application.conf" ]]; then
        cp ${CONFIG_DIR}/cortex/application.conf backups/cortex-application.conf.backup.$(date +%Y%m%d-%H%M%S)
    fi
    
    # Execute installation steps
    install_dependencies
    install_thehive
    install_cortex
    configure_services
    start_services
    verify_installation
    
    log_info "Deployment completed successfully!"
    echo -e "\n=== Access Information ==="
    echo "TheHive UI: http://$(hostname -I | awk '{print $1}'):9000"
    echo "Cortex UI: http://$(hostname -I | awk '{print $1}'):9001"
    echo -e "\nDefault credentials:"
    echo "TheHive: admin@thehive.local / secret"
    echo "Cortex: admin / admin"
    echo -e "\nNext steps:"
    echo "1. Access Cortex UI and create an org-admin user"
    echo "2. Generate API key for the new user"
    echo "3. Configure Cortex connector in TheHive"
    echo "4. Check docs/configuration.md for detailed instructions"
}

# Run main function
main "$@"
