# TheHive & Cortex Enterprise Deployment Platform

![Platform](https://img.shields.io/badge/Platform-SOC%20Incident%20Response-blue)
![Version](https://img.shields.io/badge/Version-2.5--Enterprise-green)
![Stack](https://img.shields.io/badge/Stack-TheHive%205.2.16%20%7C%20Cortex%203.1.8%20%7C%20ES%207.17.29%20%7C%20Cassandra%204.1.x-purple)
![License](https://img.shields.io/badge/License-MIT-orange)

A deployment blueprint for **TheHive 5.2.16** and **Cortex 3.1.8** designed for Security Operations Centers (SOC).  
This environment supports incident response, automated enrichment, collaboration, and large-scale case management.

You can deploy the platform in **two ways**:

1. **Automated deployment** using `deploy.sh`  
2. **Manual installation** (fully documented step-by-step)

---

## 📚 Table of Contents

1. [Architecture Overview](#-architecture-overview)  
2. [Installed Components](#-installed-components)  
3. [Requirements](#-requirements)  
4. [Option A – Automated Deployment](#-option-a--automated-deployment-deploysh)  
5. [Option B – Manual Deployment](#-option-b--manual-deployment-step-by-step)  
   - [1. System Preparation](#1-system-preparation)  
   - [2. Install Elasticsearch 71729](#2-install-elasticsearch-71729)  
   - [3. Install Cassandra 41x](#3-install-cassandra-41x)  
   - [4. Install TheHive-5216](#4-install-thehive-5216)  
   - [5. Install Cortex-318](#5-install-cortex-318)  
   - [6. Configure TheHive](#6-configure-thehive)  
   - [7. Configure Cortex](#7-configure-cortex)  
   - [8. Create systemd Units](#8-create-systemd-units-for-thehive-and-cortex)  
   - [9. Initial Access & Credentials](#9-initial-access--default-credentials)  
   - [10. Connect TheHive & Cortex](#10-connect-thehive-and-cortex-api-key-integration)  
6. [Health Checks](#-health-checks)  
7. [Key Directories](#-key-directories)  
8. [Production Recommendations](#-production-recommendations)  
9. [Optional: Splunk Integration (setupsh)](#-optional-splunk-integration-setupsh)  
10. [License](#-license)

---

## 🏗️ Architecture Overview

This deployment consists of four core services (plus optional reverse proxy):

### 1. TheHive (Port 9000)
- Incident Response platform (cases, alerts, tasks, observables, workflows, collaboration)
- Stores graph data in **Cassandra** and uses **Elasticsearch** for search and indexing.

### 2. Cortex (Port 9001)
- Analysis & response engine for observables and automated actions.
- TheHive talks to Cortex via REST API and uses an **API key** for authentication.

### 3. Cassandra (Port 9042)
- Distributed NoSQL database for TheHive case data, observables, and metadata.
- Single-node lab configuration (no authentication, `AllowAllAuthenticator`).

### 4. Elasticsearch (Port 9200)
- Search and analytics engine used by both TheHive and Cortex.
- Version **7.17.29** (last 7.x LTS line) for TheHive 5.x compatibility.

### 5. Nginx Reverse Proxy (Optional, 80/443)
- Optional component for:
  - HTTPS termination
  - Publishing TheHive/Cortex securely (TLS, WAF, etc.)
  - Centralized access control

---

## 📦 Installed Components

| Component       | Version   | Purpose                      | Port |
|----------------|-----------|------------------------------|------|
| TheHive        | 5.2.16    | Incident Response Platform   | 9000 |
| Cortex         | 3.1.8     | Analysis Engine              | 9001 |
| Elasticsearch  | 7.17.29   | Search & Analytics           | 9200 |
| Cassandra      | 4.1.x     | Distributed Database         | 9042 |
| Java (OpenJDK) | 11        | Runtime Environment          | –    |

---

## 📋 Requirements

- **OS:** Ubuntu 20.04 / 22.04 (recommended) or Debian 11 / 12  
- **RAM:** 8 GB minimum (3–4 GB is OK for lab/PoC only)  
- **CPU:** 4 vCPUs recommended  
- **Disk:** 50 GB+ (more for production)  
- **Network:**
  - Outbound internet access (for packages/analyzers) or local mirrors
  - Inbound access to ports: `9000` (TheHive), `9001` (Cortex), optionally `443` (Nginx)

---

## 🚀 Option A – Automated Deployment (`deploy.sh`)

> Use this if you trust and maintain the script in your own repository.

### Download and run the deployment script

```bash
wget -O deploy.sh https://raw.githubusercontent.com/mohamadyaghoobii/thehive-cortex-deploy/master/deploy.sh
chmod +x deploy.sh
sudo ./deploy.sh
```

The script will:

- Stop and clean any existing TheHive/Cortex/ES/Cassandra data on the host  
- Install:
  - Elasticsearch **7.17.29** (using `.deb`, e.g. Aliyun mirror in restricted networks)
  - Cassandra **4.1.x**
  - TheHive **5.2.16**
  - Cortex **3.1.8**
- Configure systemd services
- Start all components
- (Optionally) create helper scripts such as:
  - `configure-integration.sh` – for TheHive ↔ Cortex API integration
  - `check-thehive-status` – basic health check

If you prefer not to rely on scripts at all, follow **Option B – Manual Deployment** below.

---

## 🧩 Option B – Manual Deployment (Step-by-Step)

This section describes how to install and configure **everything manually**, without relying on `deploy.sh`.  
Use this as a reference document for audits, manual rebuilds, or environments where scripts are restricted.

> **Important:** All commands assume you are running as `root` (or via `sudo -i`).

---

### 1. System Preparation

```bash
sudo -i

apt-get update
apt-get upgrade -y

apt-get install -y \
  curl wget gnupg2 software-properties-common \
  apt-transport-https ca-certificates \
  openjdk-11-jdk haveged \
  python3 python3-pip \
  git tree jq net-tools lsof
```

Optional: verify resources:

```bash
free -h
df -h /
nproc
```

---

### 2. Install Elasticsearch 7.17.29

#### 2.1. Download Elasticsearch `.deb`

If `artifacts.elastic.co` is blocked, use a trusted mirror (example: Aliyun):

```bash
cd /tmp
wget https://mirrors.aliyun.com/elasticstack/apt/7.x/pool/main/e/elasticsearch/elasticsearch-7.17.29-amd64.deb
```

#### 2.2. Install the package

```bash
cd /tmp
dpkg -i elasticsearch-7.17.29-amd64.deb || true
apt-get install -f -y

dpkg -l | grep elasticsearch
```

#### 2.3. Configure `elasticsearch.yml`

```bash
cat > /etc/elasticsearch/elasticsearch.yml << 'EOF'
cluster.name: thehive-cortex-cluster
node.name: thehive-node-1

path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch

network.host: 127.0.0.1
http.port: 9200

discovery.type: single-node

bootstrap.memory_lock: true
xpack.security.enabled: false

thread_pool.write.queue_size: 1000
thread_pool.search.queue_size: 1000
EOF
```

#### 2.4. Tune JVM heap (lab mode)

```bash
if [ -f /etc/elasticsearch/jvm.options ]; then
  sed -i 's/^-Xms[0-9]\+[mgMG]/-Xms1g/' /etc/elasticsearch/jvm.options
  sed -i 's/^-Xmx[0-9]\+[mgMG]/-Xmx1g/' /etc/elasticsearch/jvm.options
fi
```

#### 2.5. Permissions and service start

```bash
mkdir -p /var/lib/elasticsearch /var/log/elasticsearch
chown -R elasticsearch:elasticsearch /var/lib/elasticsearch /var/log/elasticsearch

systemctl daemon-reload
systemctl enable elasticsearch
systemctl start elasticsearch
```

Test:

```bash
curl -s http://127.0.0.1:9200 | jq . || curl -s http://127.0.0.1:9200
```

---

### 3. Install Cassandra 4.1.x

Assuming official Cassandra APT repos are already configured (e.g. `apache.jfrog.io`).

#### 3.1. Install the package

```bash
apt-get update
apt-get install -y cassandra
```

#### 3.2. Configure single-node `/etc/cassandra/cassandra.yaml`

```bash
systemctl stop cassandra || true

if [ -f /etc/cassandra/cassandra.yaml ] && [ ! -f /etc/cassandra/cassandra.yaml.orig ]; then
  cp /etc/cassandra/cassandra.yaml /etc/cassandra/cassandra.yaml.orig
fi

cat > /etc/cassandra/cassandra.yaml << 'EOF'
cluster_name: 'TheHive Cluster'

num_tokens: 16
partitioner: org.apache.cassandra.dht.Murmur3Partitioner

listen_address: 127.0.0.1
rpc_address: 127.0.0.1

seed_provider:
  - class_name: org.apache.cassandra.locator.SimpleSeedProvider
    parameters:
      - seeds: "127.0.0.1"

data_file_directories:
  - /var/lib/cassandra/data

commitlog_directory: /var/lib/cassandra/commitlog
saved_caches_directory: /var/lib/cassandra/saved_caches

commitlog_sync: periodic
commitlog_sync_period: 10000ms

authenticator: AllowAllAuthenticator
authorizer: AllowAllAuthorizer

start_native_transport: true
native_transport_port: 9042

endpoint_snitch: SimpleSnitch
EOF
```

#### 3.3. Tune Cassandra heap

```bash
if [ -f /etc/cassandra/jvm-server.options ]; then
  sed -i -E 's/^-Xms[0-9]+[mMgG]/-Xms512M/' /etc/cassandra/jvm-server.options
  sed -i -E 's/^-Xmx[0-9]+[mMgG]/-Xmx512M/' /etc/cassandra/jvm-server.options
fi
```

#### 3.4. Directories and permissions

```bash
mkdir -p /var/lib/cassandra/data /var/lib/cassandra/commitlog /var/lib/cassandra/saved_caches /var/log/cassandra
chown -R cassandra:cassandra /var/lib/cassandra /var/log/cassandra
```

#### 3.5. Start and validate

```bash
systemctl enable cassandra || true
systemctl start cassandra

ss -lntp | grep 9042 || echo "Cassandra not listening on 9042 yet"
journalctl -u cassandra -n 50 --no-pager
```

#### 3.6. Create `thehive` keyspace

```bash
cqlsh -e "CREATE KEYSPACE IF NOT EXISTS thehive WITH replication = {'class': 'SimpleStrategy', 'replication_factor': 1};"
```

---

### 4. Install TheHive 5.2.16

#### 4.1. Download deb

```bash
cd /tmp
wget https://thehive.download.strangebee.com/5.2/deb/thehive_5.2.16-1_all.deb
```

#### 4.2. Install deb

```bash
dpkg -i thehive_5.2.16-1_all.deb || true
apt-get install -f -y

dpkg -l | grep thehive
```

---

### 5. Install Cortex 3.1.8

#### 5.1. Download deb

```bash
cd /tmp
wget https://cortex.download.strangebee.com/3.1/deb/cortex_3.1.8-1_all.deb
```

#### 5.2. Install deb

```bash
dpkg -i cortex_3.1.8-1_all.deb || true
apt-get install -f -y

dpkg -l | grep cortex
```

---

### 6. Configure TheHive

#### 6.1. Secret key

```bash
mkdir -p /etc/thehive

cat > /etc/thehive/secret.conf << 'EOF'
# IMPORTANT: Change this in production.
play.http.secret.key="changeme_in_production_make_this_very_long_and_secure_12345"
EOF
```

#### 6.2. Main configuration (`/etc/thehive/application.conf`)

```bash
cat > /etc/thehive/application.conf << 'EOF'
include "/etc/thehive/secret.conf"

db.janusgraph {
  storage {
    backend = cql
    hostname = ["127.0.0.1"]
    cql {
      cluster-name = "TheHive Cluster"
      keyspace = "thehive"
      connection-pool {
        max-requests-per-connection = 1024
        local {
          core-connections-per-host = 2
          max-connections-per-host = 4
        }
      }
    }
  }

  index.search {
    backend = elasticsearch
    hostname = ["127.0.0.1"]
    index-name = "thehive"
    elasticsearch {
      client.sniff = false
    }
  }

  cache.db-cache = true
  cache.db-cache-size = 0.3
  cache.db-cache-clean-wait = 50
  cache.tx-cache-size = 20000
}

storage {
  provider = localfs
  localfs.location = "/opt/thp/thehive/files"
  localfs.thumbnail.location = "/opt/thp/thehive/files/thumbnails"
}

play.http.context = "/"
application.baseUrl = "http://0.0.0.0:9000"

play.http.parser.maxDiskBuffer = 2GB
play.http.parser.maxMemoryBuffer = 50M

play.modules.enabled += org.thp.thehive.connector.cortex.CortexModule

cortex {
  servers = [
    {
      name = "local-cortex"
      url = "http://127.0.0.1:9001"

      # auth block will be added later using Cortex API key

      wsConfig {
        timeout.connection = 1 minute
        timeout.idle = 10 minutes
        timeout.request = 5 minutes
        user-agent = "TheHive/5.2.16"
      }
    }
  ]
}

logger.application = INFO
logger.org.thp = INFO
logger.org.janusgraph = WARN
logger.org.apache.cassandra = WARN
logger.org.elasticsearch = WARN

play.filters.headers.contentSecurityPolicy = "default-src 'self' 'unsafe-inline' 'unsafe-eval' data: blob:"

play.filters.enabled += "play.filters.cors.CORSFilter"
play.filters.cors {
  pathPrefixes = ["/api"]
  allowedOrigins = ["http://localhost:9000", "http://127.0.0.1:9000", "http://0.0.0.0:9000"]
  allowedHttpMethods = ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
  allowedHttpHeaders = ["Accept", "Content-Type", "Origin", "X-Requested-With", "Authorization"]
  preflightMaxAge = 1 hour
}

play.filters.hosts {
  allowed = ["."]
}

play.server.akka {
  max-header-size = 10m
  request-timeout = 60s
}

application.langs = "en"
EOF
```

#### 6.3. Directories and permissions

```bash
mkdir -p /opt/thp/thehive/{database,index,files,thumbnails} /var/log/thehive
chown -R thehive:thehive /opt/thp/thehive /var/log/thehive
```

---

### 7. Configure Cortex

#### 7.1. Main configuration (`/etc/cortex/application.conf`)

```bash
mkdir -p /etc/cortex

cat > /etc/cortex/application.conf << 'EOF'
play.http.secret.key = "cortex_production_secret_change_this_make_it_long-and-secure_67890"

search {
  host = ["127.0.0.1:9200"]
  index = "cortex_6"
  connection {
    timeout = 30s
    retry = 3
  }
}

http {
  address = "0.0.0.0"
  port = 9001
}

auth {
  basic {
    realm = "Cortex"
  }
}

auth.methods = [
  {name = "basic"}
  {name = "key"}
]

auth.verification {
  secret = "cortex_verification_secret_change_this_12345"
}

analyzer {
  urls = [
    "https://download.thehive-project.org/analyzers.json"
  ]
  fork-join-executor {
    parallelism-min = 4
    parallelism-factor = 2.0
    parallelism-max = 16
  }
  configs = [ ]
}

responder {
  urls = [
    "https://download.thehive-project.org/responders.json"
  ]
  fork-join-executor {
    parallelism-min = 2
    parallelism-factor = 1.0
    parallelism-max = 8
  }
}

play.filters.enabled += "play.filters.cors.CORSFilter"
play.filters.cors {
  pathPrefixes = ["/api"]
  allowedOrigins = ["http://localhost:9000", "http://127.0.0.1:9000", "http://0.0.0.0:9000"]
  allowedHttpMethods = ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
  allowedHttpHeaders = ["Accept", "Content-Type", "Origin", "X-Requested-With", "Authorization"]
  supportsCredentials = true
  preflightMaxAge = 1 hour
}

play.ws {
  timeout.connection = 30s
  timeout.idle = 5 minutes
  timeout.request = 5 minutes
  useragent = "Cortex/3.1.8"
  ssl {
    loose {
      acceptAnyCertificate = true
    }
  }
}

logger.analyzer = INFO
logger.responder = INFO
logger.cortex = INFO
logger.org.elasticsearch = WARN
logger.com.sksamuel.elastic4s = WARN

cortex.jobs {
  clean-status-timeout = 1 hour
  clean-action-timeout = 7 days
}

docker {
  host = "unix:///var/run/docker.sock"
}
EOF
```

#### 7.2. Logging config and permissions

```bash
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

    <root level="INFO">
        <appender-ref ref="FILE"/>
        <appender-ref ref="STDOUT"/>
    </root>
</configuration>
EOF

mkdir -p /var/log/cortex
chown -R cortex:cortex /var/log/cortex
```

---

### 8. Create systemd Units for TheHive and Cortex

#### 8.1. TheHive service

```bash
cat > /etc/systemd/system/thehive.service << 'EOF'
[Unit]
Description=TheHive 5.2.16
Documentation=https://thehive-project.org
After=network.target elasticsearch.service cassandra.service
Wants=elasticsearch.service cassandra.service

[Service]
Type=simple
User=thehive
Group=thehive
WorkingDirectory=/opt/thehive

Environment="JAVA_OPTS=-Xms512m -Xmx1g -XX:+UseG1GC -XX:MaxGCPauseMillis=200"
Environment="CONFIG_FILE=/etc/thehive/application.conf"

LimitNOFILE=65536
NoNewPrivileges=yes

ExecStart=/opt/thehive/bin/thehive \
  -Dconfig.file=/etc/thehive/application.conf \
  -Dhttp.address=0.0.0.0 \
  -Dhttp.port=9000 \
  -Dplay.server.pidfile.path=/dev/null \
  -Dlogger.file=/etc/thehive/logback.xml

Restart=on-failure
RestartSec=10s
StartLimitInterval=60s
StartLimitBurst=3

TimeoutStartSec=300
TimeoutStopSec=30

[Install]
WantedBy=multi-user.target
EOF
```

#### 8.2. Cortex service

```bash
cat > /etc/systemd/system/cortex.service << 'EOF'
[Unit]
Description=Cortex 3.1.8 - Observable Analysis Engine
Documentation=https://docs.thehive-project.org/cortex/
After=network.target elasticsearch.service
Wants=elasticsearch.service
Requires=elasticsearch.service

[Service]
Type=simple
User=cortex
Group=cortex
WorkingDirectory=/opt/cortex

Environment="JAVA_OPTS=-Xms256m -Xmx512m -XX:+UseG1GC -XX:MaxGCPauseMillis=200 -Djava.awt.headless=true"
Environment="CONFIG_FILE=/etc/cortex/application.conf"

NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/opt/cortex/data /var/log/cortex

LimitNOFILE=65536
LimitNPROC=4096

ExecStart=/opt/cortex/bin/cortex \
  -Dconfig.file=/etc/cortex/application.conf \
  -Dlogger.file=/etc/cortex/logback.xml \
  -Dpidfile.path=/dev/null \
  -Djava.security.egd=file:/dev/./urandom

StandardOutput=journal
StandardError=journal

Restart=on-failure
RestartSec=10s
StartLimitInterval=60s
StartLimitBurst=3

TimeoutStartSec=300
TimeoutStopSec=30

SuccessExitStatus=143

[Install]
WantedBy=multi-user.target
EOF
```

#### 8.3. Reload and start

```bash
systemctl daemon-reload

systemctl restart elasticsearch
sleep 10

systemctl restart cassandra
sleep 20

systemctl enable cortex thehive
systemctl restart cortex
sleep 10

systemctl restart thehive
```

---

### 9. Initial Access & Default Credentials

| Service | URL                          | Default Username       | Default Password |
|--------|-------------------------------|------------------------|------------------|
| TheHive | `http://<server-ip>:9000`   | `admin@thehive.local` | `secret`         |
| Cortex  | `http://<server-ip>:9001`   | `admin`               | `admin`          |

> ⚠️ Change all default credentials immediately after first login.

---

### 10. Connect TheHive and Cortex (API Key Integration)

This is the **final manual step**: using a Cortex API key (from an `org-admin` user) inside TheHive configuration and restarting TheHive.

#### 10.1. Create an org admin user and API key in Cortex

1. Open Cortex: `http://<server-ip>:9001`  
2. Login with `admin / admin`  
3. Go to **Organization → Users**  
4. Create a new user:
   - Login: `thehive-integration`
   - Roles: `orgAdmin`, `read`, `analyze`
5. Generate an **API key** for this user and copy it.

#### 10.2. Add the API key to TheHive configuration

Edit `/etc/thehive/application.conf` and update the `cortex.servers` block:

```hocon
cortex {
  servers = [
    {
      name = "local-cortex"
      url = "http://127.0.0.1:9001"

      auth {
        type = "bearer"
        key  = "PASTE_YOUR_CORTEX_API_KEY_HERE"
      }

      wsConfig {
        timeout.connection = 1 minute
        timeout.idle = 10 minutes
        timeout.request = 5 minutes
        user-agent = "TheHive/5.2.16"
      }
    }
  ]
}
```

Then restart TheHive:

```bash
systemctl restart thehive
```

Now open TheHive → **Administration → Connectors → Cortex** and verify that `local-cortex` is **connected**.  
Create a test case, add an observable, and run an Analyzer to confirm integration works.

---

## 🧪 Health Checks

### Basic systemd status

```bash
systemctl status elasticsearch cassandra cortex thehive --no-pager
```

### API endpoints

```bash
curl -s http://127.0.0.1:9200 | jq .     # Elasticsearch
curl -s http://127.0.0.1:9001/api/status # Cortex
curl -s http://127.0.0.1:9000/api/status # TheHive
```

### Useful logs

```bash
journalctl -u elasticsearch -n 50 --no-pager
journalctl -u cassandra    -n 50 --no-pager
journalctl -u cortex       -n 50 --no-pager
journalctl -u thehive      -n 50 --no-pager
```

---

## 🗂️ Key Directories

| Path                               | Description                    |
|------------------------------------|--------------------------------|
| `/etc/thehive/application.conf`    | TheHive main configuration    |
| `/etc/thehive/secret.conf`         | TheHive secret key            |
| `/etc/cortex/application.conf`     | Cortex main configuration     |
| `/etc/cortex/logback.xml`          | Cortex logging                |
| `/var/lib/cassandra/`              | Cassandra data                |
| `/var/lib/elasticsearch/`          | Elasticsearch data            |
| `/opt/thp/thehive/`                | TheHive data & attachments    |
| `/var/log/thehive/`                | TheHive logs                  |
| `/var/log/cortex/`                 | Cortex logs                   |

---

## 📈 Production Recommendations

- Use **HTTPS** (Nginx/Traefik + TLS certificates)
- Change all default passwords and rotate keys regularly
- Configure strict firewall rules for ports 9000/9001/9200/9042
- Move from single-node Cassandra to a multi-node cluster for HA
- Tune JVM heap sizes based on real memory & load
- Configure backup for:
  - Cassandra data
  - Elasticsearch indices
  - TheHive files (`/opt/thp/thehive`)

---

## 🔌 Optional: Splunk Integration (`setup.sh`)

The repository also provides an optional helper script named `setup.sh` to integrate **TheHive** with **Splunk** using the official `TA-thehive-cortex` add-on.

### What `setup.sh` does

When executed on the **Splunk / TheHive host**, `setup.sh` will:

1. Ask you for the TheHive FQDN (for example: `thehive.example.com`).
2. Generate a **self-signed TLS certificate** and key for Nginx (if `/etc/ssl/certs/thehive.crt` and `/etc/ssl/private/thehive.key` do not already exist).
3. Configure an **Nginx reverse proxy** for TheHive:
   - Listens on `443` (HTTPS).
   - Forwards traffic to `http://127.0.0.1:9000`.
4. Prepare the **TA-thehive-cortex** app on Splunk:
   - Ensure the app directory under `/opt/splunk/etc/apps/TA-thehive-cortex` has correct ownership (`splunk:splunk`).
   - Create the `lookups/` directory (if missing).
   - Create an **empty** lookup file:  
     `/opt/splunk/etc/apps/TA-thehive-cortex/lookups/thehive_cortex_instances.csv`  
     > This file is intentionally left empty. The TheHive/TA UI will populate it with instance definitions.
5. Configure the **TheHive Alerts & Cases** data input:
   - Creates or updates `/opt/splunk/etc/apps/TA-thehive-cortex/local/inputs.conf`.
   - Adds the stanza:

     ```ini
     [thehive_alerts_cases://thehive_alerts_cases]
     instance_id = aa9d6b2a
     type = alerts_cases
     index = thehive
     sourcetype = thehive:alerts_cases
     disabled = 0
     ```

   - `instance_id` here is just a sample ID; it must match the ID used by the TA in your environment.
6. Append the generated TheHive certificate to **certifi's** `cacert.pem` file inside the TA:
   - Path used by the script:  
     `/opt/splunk/etc/apps/TA-thehive-cortex/bin/ta_thehive_cortex/aob_py3/certifi/cacert.pem`
   - A timestamped backup of `cacert.pem` is created before modification.
7. Clean temporary Splunk lookup/KVS directories (optional) and restart Splunk.

### Prerequisites for `setup.sh`

- Splunk installed at `/opt/splunk`.
- `TA-thehive-cortex` already installed under `/opt/splunk/etc/apps/TA-thehive-cortex`.
- Nginx installed (script will skip Nginx configuration if `nginx` is not found).
- Run the script as `root` (or via `sudo`).

### How to run it

```bash
wget -O setup.sh https://your-repo-url.example.com/setup.sh
chmod +x setup.sh
sudo ./setup.sh
```

During execution you will be prompted for:

```text
Enter TheHive FQDN (default: thehive.example.com):
```

Use the same FQDN that Splunk and your browsers will use to reach TheHive (for example: `thehive.yourcompany.local`).

After the script completes:

- Test access to TheHive through Nginx:

  ```bash
  curl -sk https://<thehive-fqdn>/api/v1/status
  ```

- In Splunk Search, verify the lookup file (once the TA UI has written an instance):

  ```spl
  | inputlookup thehive_cortex_instances
  ```

- In Splunk Web, verify the Data Input:
  - **Settings → Data inputs → TheHive: Alerts & Cases**
  - Ensure `thehive_alerts_cases` is enabled and configured with the correct `instance_id` and `index`.

> Note: You still need to configure the **TheHive API key** in Splunk UI under  
> **Apps → TA-thehive-cortex → Configuration → Account** and ensure `account_name` and `instance_id` are consistent with what the TA uses internally.

---

## 📄 License

Licensed under the **MIT License** (or your organization’s license policy).
