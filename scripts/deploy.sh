#!/bin/bash
# TheHive & Cortex Ultimate Deployment Script
# Version: 2.0 - Enterprise Grade
# Description: Complete deployment of TheHive 5.2.16 + Cortex 3.1.8 with production-grade configuration
# Author: Security Engineer
# Date: $(date +%Y-%m-%d)

set -euo pipefail

# Color codes for beautiful output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Logging functions
log_info() { echo -e "${GREEN}[ℹ]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[⚠]${NC} $1"; }
log_error() { echo -e "${RED}[✗]${NC} $1"; }
log_debug() { echo -e "${BLUE}[?]${NC} $1"; }
log_success() { echo -e "${GREEN}[✓]${NC} $1"; }
log_step() { echo -e "${PURPLE}[→]${NC} $1"; }

# Banner
print_banner() {
    clear
    echo -e "${CYAN}"
    echo "╔════════════════════════════════════════════════════════════════╗"
    echo "║                                                                ║"
    echo "║           THEHIVE & CORTEX ENTERPRISE DEPLOYMENT              ║"
    echo "║                     Version 2.0 - Production Ready            ║"
    echo "║                                                                ║"
    echo "╚════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo "This script will deploy:"
    echo "  • TheHive 5.2.16 - Incident Response Platform"
    echo "  • Cortex 3.1.8 - Analysis Engine" 
    echo "  • Elasticsearch 7.17.29 - Search & Analytics"
    echo "  • Cassandra - Scalable Database"
    echo "  • Java 11 - Runtime Environment"
    echo ""
}

# Validation functions
validate_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
    log_success "Running as root user"
}

validate_os() {
    if [[ ! -f /etc/os-release ]]; then
        log_error "Cannot determine OS distribution"
        exit 1
    fi
    
    source /etc/os-release
    if [[ "$ID" != "ubuntu" && "$ID" != "debian" ]]; then
        log_error "This script supports only Ubuntu/Debian systems"
        exit 1
    fi
    
    log_success "OS detected: $PRETTY_NAME"
}

check_system_resources() {
    log_step "Checking system resources..."
    
    local total_ram=$(free -g | awk '/^Mem:/{print $2}')
    local free_disk=$(df -h / | awk 'NR==2{print $4}')
    local cpu_cores=$(nproc)
    
    log_info "System Resources:"
    log_info "  RAM: ${total_ram}GB"
    log_info "  Disk: ${free_disk} free"
    log_info "  CPU Cores: ${cpu_cores}"
    
    if [[ $total_ram -lt 8 ]]; then
        log_warn "Minimum 8GB RAM recommended for production use"
    fi
    
    if [[ $cpu_cores -lt 2 ]]; then
        log_warn "Multiple CPU cores recommended for better performance"
    fi
}

# Installation functions
install_dependencies() {
    log_step "Installing system dependencies..."
    
    # Update package list
    apt-get update
    
    # Install required packages
    apt-get install -y \
        curl \
        wget \
        gnupg2 \
        software-properties-common \
        apt-transport-https \
        ca-certificates \
        openjdk-11-jdk \
        haveged \
        python3 \
        python3-pip \
        git \
        tree \
        jq \
        net-tools
    
    log_success "System dependencies installed"
}

setup_elasticsearch() {
    log_step "Setting up Elasticsearch 7.17.29..."
    
    # Import Elasticsearch GPG key
    wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | apt-key add -
    
    # Add Elasticsearch repository
    echo "deb https://artifacts.elastic.co/packages/7.x/apt stable main" | \
        tee /etc/apt/sources.list.d/elastic-7.x.list
    
    # Install specific version
    apt-get update
    apt-get install -y elasticsearch=7.17.29
    
    # Configure Elasticsearch
    cat > /etc/elasticsearch/elasticsearch.yml << 'EOF'
# ======================== Elasticsearch Configuration =========================
#
# Cluster configuration
cluster.name: thehive-cortex-cluster
node.name: ${HOSTNAME}

# Paths
path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch

# Network
network.host: 127.0.0.1
http.port: 9200

# Discovery for single node
discovery.type: single-node

# Memory settings
bootstrap.memory_lock: true

# Security (disabled for simplicity - enable in production)
xpack.security.enabled: false

# Performance settings
thread_pool.write.queue_size: 1000
thread_pool.search.queue_size: 1000
EOF

    # Configure JVM options
    sed -i 's/-Xms1g/-Xms2g/' /etc/elasticsearch/jvm.options
    sed -i 's/-Xmx1g/-Xmx2g/' /etc/elasticsearch/jvm.options
    
    # Configure systemd limits
    echo "elasticsearch - nofile 65536" >> /etc/security/limits.conf
    echo "elasticsearch - memlock unlimited" >> /etc/security/limits.conf
    
    # Start and enable Elasticsearch
    systemctl daemon-reload
    systemctl enable elasticsearch
    systemctl start elasticsearch
    
    # Wait for Elasticsearch to be ready
    log_info "Waiting for Elasticsearch to start..."
    until curl -s http://127.0.0.1:9200 > /dev/null; do
        sleep 5
    done
    
    log_success "Elasticsearch configured and running"
}

setup_cassandra() {
    log_step "Setting up Cassandra database..."
    
    # Add Cassandra repository
    curl https://downloads.apache.org/cassandra/KEYS | apt-key add -
    echo "deb http://downloads.apache.org/cassandra/debian 311x main" | \
        tee /etc/apt/sources.list.d/cassandra.list
    
    # Install Cassandra
    apt-get update
    apt-get install -y cassandra
    
    # Configure Cassandra
    cat > /etc/cassandra/cassandra.yaml << 'EOF'
# Cassandra Configuration File

# Cluster name
cluster_name: 'TheHive Cluster'

# Listen address
listen_address: 127.0.0.1
rpc_address: 127.0.0.1

# Seed provider
seed_provider:
    - class_name: org.apache.cassandra.locator.SimpleSeedProvider
      parameters:
          - seeds: "127.0.0.1"

# Performance settings
concurrent_reads: 32
concurrent_writes: 32
concurrent_counter_writes: 16

# Memory settings
file_cache_size_in_mb: 512

# Security (disabled for simplicity)
authenticator: AllowAllAuthenticator
authorizer: AllowAllAuthorizer

# Data directories
data_file_directories:
    - /var/lib/cassandra/data
commitlog_directory: /var/lib/cassandra/commitlog
saved_caches_directory: /var/lib/cassandra/saved_caches

# Hinted handoff
max_hint_window_in_ms: 10800000 # 3 hours
hinted_handoff_enabled: true
EOF

    # Start and enable Cassandra
    systemctl enable cassandra
    systemctl start cassandra
    
    # Wait for Cassandra to be ready
    log_info "Waiting for Cassandra to start..."
    until cqlsh -e "DESCRIBE SYSTEM" 2>/dev/null; do
        sleep 10
    done
    
    # Create TheHive keyspace
    cqlsh -e "CREATE KEYSPACE IF NOT EXISTS thehive WITH replication = {'class': 'SimpleStrategy', 'replication_factor': 1};"
    
    log_success "Cassandra configured and running"
}

install_thehive() {
    log_step "Installing TheHive 5.2.16..."
    
    # Download TheHive package
    cd /tmp
    wget -q "https://thehive.download.strangebee.com/5.2/deb/thehive_5.2.16-1_all.deb"
    
    if [[ $? -ne 0 ]]; then
        log_error "Failed to download TheHive package"
        exit 1
    fi
    
    # Install TheHive
    dpkg -i thehive_5.2.16-1_all.deb || true
    apt-get install -f -y
    
    log_success "TheHive package installed"
}

install_cortex() {
    log_step "Installing Cortex 3.1.8..."
    
    # Download Cortex package
    cd /tmp
    wget -q "https://download.thehive-project.org/package/cortex-3.1.8-1.deb"
    
    if [[ $? -ne 0 ]]; then
        log_error "Failed to download Cortex package"
        exit 1
    fi
    
    # Install Cortex
    dpkg -i cortex-3.1.8-1.deb || true
    apt-get install -f -y
    
    log_success "Cortex package installed"
}

configure_thehive() {
    log_step "Configuring TheHive application..."
    
    # Create secret configuration
    mkdir -p /etc/thehive
    cat > /etc/thehive/secret.conf << 'EOF'
# TheHive Secret Configuration
# CHANGE THIS IN PRODUCTION!
play.http.secret.key="changeme_in_production_make_this_very_long_and_secure_12345"
EOF

    # Create main configuration
    cat > /etc/thehive/application.conf << 'EOF'
# ============================================================================ #
# TheHive Enterprise Configuration
# Version: 5.2.16
# Description: Production-ready configuration for TheHive
# ============================================================================ #

# Secret configuration
include "/etc/thehive/secret.conf"

# Database configuration - Cassandra
db.janusgraph {
  storage {
    backend = cql
    hostname = ["127.0.0.1"]
    cql {
      cluster-name = "thp"
      keyspace = "thehive"
      # Connection pool optimization
      connection-pool {
        max-requests-per-connection = 1024
        local {
          core-connections-per-host = 2
          max-connections-per-host = 4
        }
      }
    }
  }
  
  # Search index configuration - Elasticsearch
  index.search {
    backend = elasticsearch
    hostname = ["127.0.0.1"]
    index-name = "thehive"
    # Performance settings
    elasticsearch {
      client.sniff = false
      # Uncomment for authentication
      # http.auth {
      #   type: basic
      #   basic {
      #     username: "elastic"
      #     password: "your_password"
      #   }
      # }
    }
  }
  
  # Cache configuration for performance
  cache.db-cache = true
  cache.db-cache-size = 0.3
  cache.db-cache-clean-wait = 50
  cache.tx-cache-size = 20000
}

# Storage configuration
storage {
  provider = localfs
  localfs.location = "/opt/thp/thehive/files"
  localfs.thumbnail.location = "/opt/thp/thehive/files/thumbnails"
}

# HTTP server configuration
play.http.context = "/"
application.baseUrl = "http://0.0.0.0:9000"

# Request size limits
play.http.parser.maxDiskBuffer = 2GB
play.http.parser.maxMemoryBuffer = 50M

# Cortex connector configuration
play.modules.enabled += org.thp.thehive.connector.cortex.CortexModule

cortex {
  servers = [
    {
      name = "local-cortex"
      url = "http://127.0.0.1:9001"
      # Add API key after Cortex setup
      # auth {
      #   type = "bearer"
      #   key = "your_cortex_api_key_here"
      # }
      # HTTP client configuration
      wsConfig {
        timeout.connection = 1 minute
        timeout.idle = 10 minutes  
        timeout.request = 5 minutes
        user-agent = "TheHive/5.2.16"
        # Proxy configuration (if needed)
        # proxy {
        #   host = "proxy.example.com"
        #   port = 8080
        # }
      }
    }
  ]
}

# MISP connector (optional)
# play.modules.enabled += org.thp.thehive.connector.misp.MispModule
# misp {
#   servers = [
#     {
#       name = "local-misp"
#       url = "http://localhost"
#       auth {
#         type = "key"
#         key = "your_misp_api_key"
#       }
#     }
#   ]
# }

# Logging configuration
logger.application = INFO
logger.org.thp = INFO
logger.org.janusgraph = WARN
logger.org.apache.cassandra = WARN
logger.org.elasticsearch = WARN

# Security headers
play.filters.headers.contentSecurityPolicy = "default-src 'self' 'unsafe-inline' 'unsafe-eval' data: blob:"

# CORS configuration
play.filters.enabled += "play.filters.cors.CORSFilter"
play.filters.cors {
  pathPrefixes = ["/api"]
  allowedOrigins = ["http://localhost:9000", "http://127.0.0.1:9000", "http://0.0.0.0:9000"]
  allowedHttpMethods = ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
  allowedHttpHeaders = ["Accept", "Content-Type", "Origin", "X-Requested-With", "Authorization"]
  preflightMaxAge = 1 hour
}

# Additional security settings
play.filters.hosts {
  allowed = ["."]  # Allow all hosts in development
}

# Performance tuning
play.server.akka {
  max-header-size = 10m
  request-timeout = 60s
}

# Application-specific settings
application.global = org.thp.thehive.controllers.TheHive
application.langs = "en"
EOF

    # Create data directories
    mkdir -p /opt/thp/thehive/{database,index,files,thumbnails}
    chown -R thehive:thehive /opt/thp/thehive
    
    log_success "TheHive application configured"
}

configure_cortex() {
    log_step "Configuring Cortex application..."
    
    # Create main configuration
    cat > /etc/cortex/application.conf << 'EOF'
# ============================================================================ #
# Cortex Enterprise Configuration
# Version: 3.1.8
# Description: Production-ready configuration for Cortex
# ============================================================================ #

# Secret key - CHANGE IN PRODUCTION!
play.http.secret.key = "cortex_production_secret_change_this_make_it_very_long_and_secure_67890"

# Database configuration - Elasticsearch
search {
  host = ["127.0.0.1:9200"]
  index = "cortex_6"
  # Connection settings
  connection {
    timeout = 30s
    retry = 3
  }
  # Uncomment for authentication
  # http {
  #   auth {
  #     type = basic
  #     basic {
  #       username = "elastic"
  #       password = "your_password"
  #     }
  #   }
  # }
}

# HTTP server configuration
http {
  address = "0.0.0.0"
  port = 9001
  # HTTPS configuration (recommended for production)
  # ssl {
  #   keyStore = {
  #     path = "/path/to/keystore.jks"
  #     password = "keystore_password"
  #   }
  # }
}

# Authentication configuration
auth {
  basic {
    realm = "Cortex"
  }
}

# Supported authentication methods
auth.methods = [
  {name = "basic"}
  {name = "key"}
]

# Secret for token verification
auth.verification {
  secret = "cortex_verification_secret_change_this_12345"
}

# Analyzer configuration
analyzer {
  # Analyzer locations
  urls = [
    "https://download.thehive-project.org/analyzers.json"
    # Alternative source if primary fails:
    # "https://raw.githubusercontent.com/TheHive-Project/Cortex-Analyzers/master/analyzers"
    # Local analyzers directory:
    # "/opt/cortex/analyzers"
  ]

  # Analyzer execution configuration
  fork-join-executor {
    # Thread pool settings
    parallelism-min = 4
    parallelism-factor = 2.0
    parallelism-max = 16
  }
  
  # Global analyzer configurations (add your API keys here)
  configs = [
    # Example: VirusTotal analyzer
    # {
    #   name = "VirusTotal_GetReport_3_0"
    #   configuration = {
    #     key = "your_virustotal_api_key"
    #     rateLimit = 4  # requests per minute
    #     timeout = 30
    #   }
    # },
    # Example: AbuseIPDB analyzer
    # {
    #   name = "AbuseIPDB_1_0"
    #   configuration = {
    #     key = "your_abuseipdb_api_key"
    #     timeout = 30
    #   }
    # }
  ]
}

# Responder configuration
responder {
  # Responder locations
  urls = [
    "https://download.thehive-project.org/responders.json"
    # Local responders directory:
    # "/opt/cortex/responders"
  ]

  # Responder execution configuration
  fork-join-executor {
    parallelism-min = 2
    parallelism-factor = 1.0
    parallelism-max = 8
  }
}

# CORS configuration for TheHive integration
play.filters.enabled += "play.filters.cors.CORSFilter"
play.filters.cors {
  pathPrefixes = ["/api"]
  allowedOrigins = ["http://localhost:9000", "http://127.0.0.1:9000", "http://0.0.0.0:9000"]
  allowedHttpMethods = ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
  allowedHttpHeaders = ["Accept", "Content-Type", "Origin", "X-Requested-With", "Authorization"]
  supportsCredentials = true
  preflightMaxAge = 1 hour
}

# HTTP client configuration
play.ws {
  timeout.connection = 30s
  timeout.idle = 5 minutes
  timeout.request = 5 minutes
  useragent = "Cortex/3.1.8"
  
  # SSL configuration
  ssl {
    loose {
      acceptAnyCertificate = true
    }
  }
}

# Logging configuration
logger.analyzer = INFO
logger.responder = INFO
logger.cortex = INFO
logger.org.elasticsearch = WARN
logger.com.sksamuel.elastic4s = WARN

# Additional modules
play.modules.enabled += "play.api.libs.ws.ahc.AhcWSModule"

# Cache configuration
play.modules.enabled += "play.api.cache.ehcache.EhCacheModule"

# Job configuration (for periodic tasks)
cortex.jobs {
  clean-status-timeout = 1 hour
  clean-action-timeout = 7 days
}

# Docker configuration (for analyzers using Docker)
docker {
  host = "unix:///var/run/docker.sock"
  # For remote Docker:
  # host = "tcp://docker-host:2375"
  # tls {
  #   cert = "/path/to/cert.pem"
  #   key = "/path/to/key.pem"
  #   ca = "/path/to/ca.pem"
  # }
}
EOF

    # Create logback configuration
    cat > /etc/cortex/logback.xml << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    
    <appender name="FILE" class="ch.qos.logback.core.rolling.RollingFileAppender">
        <file>/var/log/cortex/application.log</file>
        <rollingPolicy class="ch.qos.logback.core.rolling.TimeBasedRollingPolicy">
            <fileNamePattern>/var/log/cortex/application.%d{yyyy-MM-dd}.log</fileNamePattern>
            <maxHistory>30</maxHistory>
            <totalSizeCap>3GB</totalSizeCap>
        </rollingPolicy>
        <encoder>
            <pattern>%date [%level] from %logger in %thread - %message%n%xException</pattern>
        </encoder>
    </appender>

    <appender name="STDOUT" class="ch.qos.logback.core.ConsoleAppender">
        <encoder>
            <pattern>%date [%level] from %logger in %thread - %message%n%xException</pattern>
        </encoder>
    </appender>

    <logger name="play" level="INFO"/>
    <logger name="application" level="INFO"/>
    <logger name="analyzer" level="INFO"/>
    <logger name="responder" level="INFO"/>
    
    <root level="INFO">
        <appender-ref ref="FILE"/>
        <appender-ref ref="STDOUT"/>
    </root>

</configuration>
EOF

    # Create log directory
    mkdir -p /var/log/cortex
    chown -R cortex:cortex /var/log/cortex
    
    log_success "Cortex application configured"
}

setup_systemd_services() {
    log_step "Configuring systemd services..."
    
    # TheHive service
    cat > /etc/systemd/system/thehive.service << 'EOF'
[Unit]
Description=TheHive 5.2.16 - Security Incident Response Platform
Documentation=https://docs.thehive-project.org/
After=network.target elasticsearch.service cassandra.service
Wants=elasticsearch.service cassandra.service
Requires=elasticsearch.service cassandra.service

[Service]
Type=simple
User=thehive
Group=thehive
WorkingDirectory=/opt/thehive

# Environment
Environment="JAVA_OPTS=-Xms2g -Xmx4g -XX:+UseG1GC -XX:MaxGCPauseMillis=200 -XX:ParallelGCThreads=4 -Djava.awt.headless=true"
Environment="CONFIG_FILE=/etc/thehive/application.conf"

# Security
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/opt/thp/thehive /var/log/thehive

# Resource limits
LimitNOFILE=65536
LimitNPROC=4096
LimitMEMLOCK=infinity

# Process configuration
ExecStart=/opt/thehive/bin/thehive \
  -Dconfig.file=/etc/thehive/application.conf \
  -Dhttp.address=0.0.0.0 \
  -Dhttp.port=9000 \
  -Dplay.server.pidfile.path=/dev/null \
  -Dlogger.file=/opt/thehive/conf/logback.xml \
  -Djava.security.egd=file:/dev/./urandom

# Logging
StandardOutput=journal
StandardError=journal

# Restart configuration
Restart=on-failure
RestartSec=10s
StartLimitInterval=60s
StartLimitBurst=3

# Timeout settings
TimeoutStartSec=300
TimeoutStopSec=30

[Install]
WantedBy=multi-user.target
EOF

    # Cortex service
    cat > /etc/systemd/system/cortex.service << 'EOF'
[Unit]
Description=Cortex 3.1.8 - Observable Analysis Engine
Documentation=https://docs.thehive-project.org/cortex/
After=network.target elasticsearch.service
Wants=network.target elasticsearch.service
Requires=elasticsearch.service

[Service]
Type=simple
User=cortex
Group=cortex
WorkingDirectory=/opt/cortex

# Environment
Environment="JAVA_OPTS=-Xms1g -Xmx2g -XX:+UseG1GC -XX:MaxGCPauseMillis=200 -Djava.awt.headless=true"
Environment="CONFIG_FILE=/etc/cortex/application.conf"

# Security
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/opt/cortex/data /var/log/cortex

# Resource limits
LimitNOFILE=65536
LimitNPROC=4096

# Process configuration
ExecStart=/opt/cortex/bin/cortex \
  -Dconfig.file=/etc/cortex/application.conf \
  -Dlogger.file=/etc/cortex/logback.xml \
  -Dpidfile.path=/dev/null \
  -Djava.security.egd=file:/dev/./urandom

# Logging
StandardOutput=journal
StandardError=journal

# Restart configuration
Restart=on-failure
RestartSec=10s
StartLimitInterval=60s
StartLimitBurst=3

# Timeout settings
TimeoutStartSec=300
TimeoutStopSec=30

# Exit status
SuccessExitStatus=143

[Install]
WantedBy=multi-user.target
EOF

    # Reload systemd and enable services
    systemctl daemon-reload
    
    log_success "Systemd services configured"
}

start_services() {
    log_step "Starting all services..."
    
    # Start services in correct order
    log_info "Starting Elasticsearch..."
    systemctl restart elasticsearch
    sleep 10
    
    log_info "Starting Cassandra..."
    systemctl restart cassandra
    sleep 15
    
    log_info "Starting Cortex..."
    systemctl enable cortex
    systemctl start cortex
    sleep 10
    
    log_info "Starting TheHive..."
    systemctl enable thehive
    systemctl start thehive
    sleep 15
    
    log_success "All services started"
}

wait_for_services() {
    log_step "Waiting for services to be ready..."
    
    # Wait for Elasticsearch
    log_info "Waiting for Elasticsearch..."
    until curl -s http://127.0.0.1:9200 > /dev/null; do
        sleep 5
    done
    
    # Wait for Cassandra
    log_info "Waiting for Cassandra..."
    until cqlsh -e "DESCRIBE KEYSPACES" 2>/dev/null; do
        sleep 5
    done
    
    # Wait for Cortex
    log_info "Waiting for Cortex..."
    until curl -s http://127.0.0.1:9001/api/status > /dev/null; do
        sleep 5
    done
    
    # Wait for TheHive
    log_info "Waiting for TheHive..."
    until curl -s http://127.0.0.1:9000/api/status > /dev/null; do
        sleep 5
    done
    
    log_success "All services are ready"
}

create_integration_script() {
    log_step "Creating Cortex-TheHive integration script..."
    
    cat > /root/configure-integration.sh << 'EOF'
#!/bin/bash
# Cortex-TheHive Integration Script
# Run this after deployment to connect TheHive with Cortex

set -euo pipefail

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[ℹ]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[⚠]${NC} $1"; }
log_error() { echo -e "${RED}[✗]${NC} $1"; }

CORTEX_URL="http://127.0.0.1:9001"
THEHIVE_URL="http://127.0.0.1:9000"

# Check if services are accessible
check_services() {
    log_info "Checking service accessibility..."
    
    if ! curl -s "${CORTEX_URL}/api/status" > /dev/null; then
        log_error "Cortex is not accessible at ${CORTEX_URL}"
        return 1
    fi
    
    if ! curl -s "${THEHIVE_URL}/api/status" > /dev/null; then
        log_error "TheHive is not accessible at ${THEHIVE_URL}"
        return 1
    fi
    
    log_info "Both services are accessible"
    return 0
}

create_cortex_user() {
    log_info "Creating organization admin user in Cortex..."
    
    cat > /tmp/create_cortex_user.cql << 'CQL'
// First, authenticate as superuser
// Then create thehive user with proper permissions
// Note: This is a simplified approach - adjust based on your auth setup
CQL

    log_warn "Manual step required:"
    echo ""
    echo "Please perform the following steps in Cortex UI:"
    echo "1. Open http://$(hostname -I | awk '{print $1}'):9001"
    echo "2. Login with: admin / admin"
    echo "3. Go to 'Organization' → 'Users'"
    echo "4. Click 'Add User'"
    echo "5. Fill in details:"
    echo "   - Login: thehive-integration"
    echo "   - Name: TheHive Integration User"
    echo "   - Roles: Check 'orgAdmin', 'read', 'analyze'"
    echo "   - Password: Choose a strong password"
    echo "6. Click 'Create'"
    echo "7. Go to the user's profile and generate an API Key"
    echo "8. Copy the API key for the next step"
    echo ""
    read -p "Press Enter when you have the API key..."
}

configure_thehive_connector() {
    log_info "Configuring TheHive Cortex connector..."
    
    echo ""
    read -p "Enter the Cortex API key: " API_KEY
    
    if [[ -z "$API_KEY" ]]; then
        log_error "No API key provided"
        return 1
    fi
    
    # Backup current configuration
    cp /etc/thehive/application.conf /etc/thehive/application.conf.backup.$(date +%Y%m%d_%H%M%S)
    
    # Update configuration with API key
    sed -i '/# Add API key after Cortex setup/,/}/ {
        /# Add API key after Cortex setup/ {
            n
            n
            n
            c\
      auth {\
        type = "bearer"\
        key = "'"$API_KEY"'"\
      }
        }
    }' /etc/thehive/application.conf
    
    # Restart TheHive
    systemctl restart thehive
    
    log_info "Waiting for TheHive to restart..."
    sleep 10
    
    until curl -s http://127.0.0.1:9000/api/status > /dev/null; do
        sleep 5
    done
    
    log_info "TheHive configuration updated and restarted"
}

test_integration() {
    log_info "Testing Cortex-TheHive integration..."
    
    # Test if analyzers are available in TheHive
    if curl -s http://127.0.0.1:9000/api/connector/cortex/analyzer | grep -q "name"; then
        log_info "✅ Integration successful! Cortex analyzers are accessible from TheHive"
    else
        log_warn "⚠️  Integration may need additional configuration"
        log_warn "Check TheHive UI: Administration → Connectors → Cortex"
    fi
}

main() {
    log_info "Starting Cortex-TheHive integration process..."
    
    if check_services; then
        create_cortex_user
        configure_thehive_connector
        test_integration
    fi
    
    log_info "Integration process completed"
    echo ""
    echo "Next steps:"
    echo "1. Access TheHive: http://$(hostname -I | awk '{print $1}'):9000"
    echo "2. Login with: admin@thehive.local / secret"
    echo "3. Go to Administration → Connectors → Cortex"
    echo "4. Verify the Cortex server is connected"
    echo "5. Create a test case and try running analyzers"
}

main "$@"
EOF

    chmod +x /root/configure-integration.sh
    log_success "Integration script created at /root/configure-integration.sh"
}

create_health_check() {
    log_step "Creating health check script..."
    
    cat > /usr/local/bin/check-thehive-status << 'EOF'
#!/bin/bash
# TheHive & Cortex Health Check Script

echo "=== TheHive & Cortex Health Check ==="
echo "Timestamp: $(date)"
echo ""

# Service status
echo "Service Status:"
echo "---------------"
systemctl is-active thehive >/dev/null 2>&1 && echo "✅ TheHive: Running" || echo "❌ TheHive: Not running"
systemctl is-active cortex >/dev/null 2>&1 && echo "✅ Cortex: Running" || echo "❌ Cortex: Not running"
systemctl is-active elasticsearch >/dev/null 2>&1 && echo "✅ Elasticsearch: Running" || echo "❌ Elasticsearch: Not running"
systemctl is-active cassandra >/dev/null 2>&1 && echo "✅ Cassandra: Running" || echo "❌ Cassandra: Not running"

echo ""

# API status
echo "API Status:"
echo "-----------"
curl -s http://127.0.0.1:9000/api/status >/dev/null && echo "✅ TheHive API: Accessible" || echo "❌ TheHive API: Not accessible"
curl -s http://127.0.0.1:9001/api/status >/dev/null && echo "✅ Cortex API: Accessible" || echo "❌ Cortex API: Not accessible"
curl -s http://127.0.0.1:9200 >/dev/null && echo "✅ Elasticsearch API: Accessible" || echo "❌ Elasticsearch API: Not accessible"

echo ""

# Resource usage
echo "Resource Usage:"
echo "---------------"
ps aux --sort=-%mem | head -n 5 | awk '{print $2, $4, $11}' | while read pid mem cmd; do
    if [[ $mem != "%MEM" ]]; then
        echo "PID: $pid, MEM: ${mem}%, CMD: $(basename $cmd)"
    fi
done

echo ""

# Disk space
echo "Disk Space:"
echo "-----------"
df -h / /opt /var/lib | grep -v tmpfs

echo ""

# Recent errors
echo "Recent Errors (last 10 lines):"
echo "------------------------------"
journalctl -u thehive --since "1 hour ago" | grep -i error | tail -5
journalctl -u cortex --since "1 hour ago" | grep -i error | tail -5
EOF

    chmod +x /usr/local/bin/check-thehive-status
    log_success "Health check script created"
}

finalize_installation() {
    log_step "Finalizing installation..."
    
    # Create installation summary
    cat > /root/thehive-installation-summary.txt << EOF
=== THEHIVE & CORTEX INSTALLATION SUMMARY ===

Installation Date: $(date)
TheHive Version: 5.2.16
Cortex Version: 3.1.8
Elasticsearch Version: 7.17.29

=== ACCESS INFORMATION ===

TheHive URL: http://$(hostname -I | awk '{print $1}'):9000
Default credentials: admin@thehive.local / secret

Cortex URL: http://$(hostname -I | awk '{print $1}'):9001  
Default credentials: admin / admin

=== IMPORTANT FILES ===

TheHive Configuration: /etc/thehive/application.conf
Cortex Configuration: /etc/cortex/application.conf
TheHive Service: /etc/systemd/system/thehive.service
Cortex Service: /etc/systemd/system/cortex.service

=== NEXT STEPS ===

1. Run the integration script:
   sudo /root/configure-integration.sh

2. Check system status:
   check-thehive-status

3. Configure firewall (if needed):
   ufw allow 9000/tcp  # TheHive
   ufw allow 9001/tcp  # Cortex

4. Change default passwords in both applications

5. Configure backups for data directories

=== SUPPORT ===

Documentation: https://docs.thehive-project.org/
Community: https://forum.thehive-project.org/

Installation completed successfully!
EOF

    log_success "Installation finalized"
    echo ""
    cat /root/thehive-installation-summary.txt
}

main() {
    print_banner
    validate_root
    validate_os
    check_system_resources
    
    log_step "Starting deployment process..."
    
    # Execute deployment steps
    install_dependencies
    setup_elasticsearch
    setup_cassandra
    install_thehive
    install_cortex
    configure_thehive
    configure_cortex
    setup_systemd_services
    start_services
    wait_for_services
    create_integration_script
    create_health_check
    finalize_installation
    
    # Final success message
    echo ""
    echo -e "${GREEN}"
    echo "╔════════════════════════════════════════════════════════════════╗"
    echo "║                    DEPLOYMENT COMPLETED!                      ║"
    echo "║                                                                ║"
    echo "║     TheHive and Cortex have been successfully deployed!       ║"
    echo "║                                                                ║"
    echo "╚════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo ""
    echo "Quick start:"
    echo "1. Run: sudo /root/configure-integration.sh"
    echo "2. Check status: check-thehive-status" 
    echo "3. Access TheHive: http://$(hostname -I | awk '{print $1}'):9000"
    echo "4. Access Cortex: http://$(hostname -I | awk '{print $1}'):9001"
    echo ""
    echo "Installation details saved to: /root/thehive-installation-summary.txt"
}

# Run main function
main "$@"
