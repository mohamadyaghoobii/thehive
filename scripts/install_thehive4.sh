#!/usr/bin/env bash
#
# TheHive 4 One-Click Bootstrap for Ubuntu 22.04 (Jammy)
# - Installs: Cassandra 3.11, Elasticsearch 7.17, TheHive 4.1.24, Nginx
# - Single-node, lab/POC ready. For production, harden and size properly.
#
# Usage:
#   sudo bash scripts/install_thehive4.sh
#
# Optional env overrides:
#   ES_HEAP=1g THEHIVE_HEAP_MB=1024 PUBLIC_BASEURL="http://<SERVER-IP>" \
#   THEHIVE_ZIP_URL="https://<vendor>/thehive4-4.1.24-1.zip" \
#   bash scripts/install_thehive4.sh
#
set -euo pipefail

### -------- Settings (override via env) --------
ES_HEAP="${ES_HEAP:-1g}"                       # Elasticsearch heap (Xms/Xmx)
THEHIVE_HEAP_MB="${THEHIVE_HEAP_MB:-1024}"     # TheHive heap (MB)
PUBLIC_BASEURL="${PUBLIC_BASEURL:-}"           # e.g., http://10.10.14.12
THEHIVE_VERSION="4.1.24-1"

# Candidate URLs to fetch the TheHive 4.1.24 distribution ZIP. The first working one will be used.
# If none work, place the ZIP at /tmp/thehive4-4.1.24-1.zip and re-run.
DEFAULT_THEHIVE_CANDIDATES=(
  "https://github.com/TheHive-Project/TheHive/releases/download/4.1.24/thehive4-4.1.24-1.zip"
  "https://download.thehive-project.org/release/thehive4-4.1.24-1.zip"
  "https://download.thehive-project.org/thehive4-4.1.24-1.zip"
)
THEHIVE_ZIP_URL="${THEHIVE_ZIP_URL:-}"

### -------- Helpers --------
log()  { printf "\033[1;32m[+]\033[0m %s\n" "$*"; }
warn() { printf "\033[1;33m[!]\033[0m %s\n" "$*"; }
die()  { printf "\033[1;31m[x]\033[0m %s\n" "$*"; exit 1; }

require_root() {
  if [[ "$(id -u)" -ne 0 ]]; then
    die "Run this script as root (sudo)."
  fi
}

detect_ip() {
  hostname -I 2>/dev/null | awk '{print $1}'
}

retry() {
  local -r n="$1"; shift
  local -i c=0
  until "$@"; do
    c=$((c+1))
    if (( c >= n )); then return 1; fi
    sleep 2
  done
}

### -------- Begin --------
require_root
export DEBIAN_FRONTEND=noninteractive

log "System update & basic tools"
apt-get update -y
apt-get install -y ca-certificates curl wget gnupg lsb-release jq unzip apt-transport-https openjdk-11-jre-headless nginx

### -------- Cassandra 3.11 --------
if ! dpkg -s cassandra >/dev/null 2>&1; then
  log "Configure Apache Cassandra 3.11 repo"
  install -d -m 0755 /etc/apt/keyrings
  curl -fsSL https://downloads.apache.org/cassandra/KEYS | gpg --dearmor -o /etc/apt/keyrings/cassandra.gpg
  echo "deb [signed-by=/etc/apt/keyrings/cassandra.gpg] https://apache.jfrog.io/artifactory/cassandra-deb 311x main" >/etc/apt/sources.list.d/cassandra.list
  apt-get update -y
  log "Install Cassandra"
  apt-get install -y cassandra
  systemctl enable cassandra --now
else
  log "Cassandra already installed, ensuring it is running"
  systemctl enable cassandra --now
fi

log "Wait for Cassandra to be up (9042)"
retry 15 bash -c 'ss -lnt | grep -q ":9042"' || die "Cassandra (9042) did not start in time"

### -------- Elasticsearch 7.17 --------
if ! dpkg -s elasticsearch >/dev/null 2>&1; then
  log "Configure Elasticsearch 7.x repo"
  install -d -m 0755 /etc/apt/keyrings
  curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch | gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
  echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/7.x/apt stable main" >/etc/apt/sources.list.d/elastic-7.x.list
  apt-get update -y
  log "Install Elasticsearch"
  apt-get install -y elasticsearch
else
  log "Elasticsearch already installed"
fi

log "Tune vm.max_map_count (required by Elasticsearch)"
sysctl -w vm.max_map_count=262144 >/etc/sysctl.d/99-thehive-vm.conf
sysctl -p /etc/sysctl.d/99-thehive-vm.conf >/dev/null

log "Configure Elasticsearch single-node (no security)"
cat >/etc/elasticsearch/elasticsearch.yml <<'ESYML'
cluster.name: thehive
node.name: srv-hivecortex
path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch

network.host: 127.0.0.1
http.port: 9200

discovery.type: single-node

xpack.security.enabled: false
xpack.security.transport.ssl.enabled: false
ESYML

log "Set Elasticsearch heap to ${ES_HEAP}"
install -d -m 0755 /etc/elasticsearch/jvm.options.d
cat >/etc/elasticsearch/jvm.options.d/heap.options <<EOF
-Xms${ES_HEAP}
-Xmx${ES_HEAP}
EOF

systemctl daemon-reload
systemctl enable elasticsearch --now

log "Wait for Elasticsearch to be up (9200)"
retry 15 bash -c 'curl -fsS http://127.0.0.1:9200 >/dev/null' || { journalctl -u elasticsearch -n 200 --no-pager; die "Elasticsearch did not start"; }

### -------- TheHive 4.1.24 --------
THEHIVE_DIR="/opt/thehive"
THEHIVE_USER="thehive"
THEHIVE_GROUP="thehive"
THEHIVE_ZIP="/tmp/thehive4-4.1.24-1.zip"

log "Create thehive user and directories"
id -u "${THEHIVE_USER}" >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin "${THEHIVE_USER}"
install -d -o "${THEHIVE_USER}" -g "${THEHIVE_GROUP}" -m 0755 "${THEHIVE_DIR}"
install -d -o "${THEHIVE_USER}" -g "${THEHIVE_GROUP}" -m 0750 /etc/thehive /var/log/thehive "${THEHIVE_DIR}/files"

download_thehive_zip() {
  local url="$1"
  log "Trying to download TheHive from: $url"
  curl -fL "$url" -o "${THEHIVE_ZIP}.tmp" && mv "${THEHIVE_ZIP}.tmp" "${THEHIVE_ZIP}"
}

if [[ ! -f "${THEHIVE_ZIP}" ]]; then
  if [[ -n "${THEHIVE_ZIP_URL}" ]]; then
    download_thehive_zip "${THEHIVE_ZIP_URL}" || warn "Failed: ${THEHIVE_ZIP_URL}"
  fi
  if [[ ! -f "${THEHIVE_ZIP}" ]]; then
    for u in "${DEFAULT_THEHIVE_CANDIDATES[@]}"; do
      if download_thehive_zip "$u"; then break; fi
      warn "Candidate URL failed: $u"
    done
  fi
fi

[[ -f "${THEHIVE_ZIP}" ]] || die "TheHive ZIP not found. Set THEHIVE_ZIP_URL or place ${THEHIVE_ZIP} and re-run."

log "Unpack TheHive to ${THEHIVE_DIR}"
tmpdir="$(mktemp -d)"
unzip -q "${THEHIVE_ZIP}" -d "${tmpdir}"
# Expect a directory like thehive4-4.1.24-1/
src_dir="$(find "${tmpdir}" -maxdepth 1 -type d -name 'thehive4-*' | head -n1)"
[[ -d "${src_dir}" ]] || die "Unexpected archive layout in ${THEHIVE_ZIP}"

# rsync-like copy
cp -a "${src_dir}/." "${THEHIVE_DIR}/"
chown -R "${THEHIVE_USER}:${THEHIVE_GROUP}" "${THEHIVE_DIR}"
rm -rf "${tmpdir}"

log "Generate TheHive secret"
SECRET="$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 64 || true)"
cat >/etc/thehive/secret.conf <<EOF
app {
  secret = "${SECRET}"
}
EOF
chown "${THEHIVE_USER}:${THEHIVE_GROUP}" /etc/thehive/secret.conf
chmod 640 /etc/thehive/secret.conf

log "Write TheHive application.conf"
SERVER_IP="$(detect_ip)"
BASEURL="${PUBLIC_BASEURL:-http://${SERVER_IP}}"

cat >/etc/thehive/application.conf <<EOF
include "/etc/thehive/secret.conf"

db {
  provider = janusgraph

  janusgraph {
    storage {
      backend  = cql
      hostname = ["127.0.0.1"]
      cql {
        cluster-name = thehive
        keyspace     = thehive
      }
    }

    index {
      search {
        backend    = elasticsearch
        hostname   = ["127.0.0.1:9200"]
        index-name = thehive
      }
    }
  }
}

storage {
  provider = localfs
  localfs.location = ${THEHIVE_DIR}/files
}

# Optional: base URL used in links/emails (reverse proxy in front)
application.baseUrl = "${BASEURL}"

# Serve UI on root
play.http.context = "/"
EOF

chown -R "${THEHIVE_USER}:${THEHIVE_GROUP}" /etc/thehive
chmod 640 /etc/thehive/application.conf

log "Create systemd unit for TheHive"
cat >/etc/systemd/system/thehive.service <<EOF
[Unit]
Description=TheHive ${THEHIVE_VERSION}
After=network.target cassandra.service elasticsearch.service
Wants=cassandra.service elasticsearch.service

[Service]
Type=simple
User=${THEHIVE_USER}
Group=${THEHIVE_GROUP}
WorkingDirectory=${THEHIVE_DIR}
LimitNOFILE=65536
Environment="JAVA_OPTS=-Xms${THEHIVE_HEAP_MB}m -Xmx${THEHIVE_HEAP_MB}m"
ExecStart=${THEHIVE_DIR}/bin/thehive \
  -Dconfig.file=/etc/thehive/application.conf \
  -Dlogger.file=${THEHIVE_DIR}/conf/logback.xml \
  -Dhttp.address=127.0.0.1 \
  -Dhttp.port=9000
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable thehive --now

log "Wait for TheHive backend on 127.0.0.1:9000"
retry 20 bash -c 'ss -lnt | grep -q "\[::ffff:127\.0\.0\.1\]:9000\|127\.0\.0\.1:9000"' || { journalctl -u thehive -n 200 --no-pager; die "TheHive did not bind to 127.0.0.1:9000"; }

log "Check TheHive status API"
curl -fsS http://127.0.0.1:9000/api/status | jq . >/dev/null || true

### -------- Nginx reverse proxy --------
log "Configure Nginx reverse proxy on :80"
cat >/etc/nginx/sites-available/thehive.conf <<'NGX'
server {
    listen 80;
    server_name _;

    access_log /var/log/nginx/thehive-access.log;
    error_log  /var/log/nginx/thehive-error.log;

    client_max_body_size 50m;

    # Explicit redirect for root to the SPA entrypoint
    location = / { return 302 /index.html; }

    location / {
        proxy_pass http://127.0.0.1:9000;
        proxy_http_version 1.1;

        proxy_set_header Host               $http_host;
        proxy_set_header X-Real-IP          $remote_addr;
        proxy_set_header X-Forwarded-For    $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Host   $http_host;
        proxy_set_header X-Forwarded-Proto  $scheme;

        proxy_read_timeout 300s;
        proxy_connect_timeout 60s;
        proxy_send_timeout 300s;

        proxy_intercept_errors off;
    }
}
NGX

ln -sf /etc/nginx/sites-available/thehive.conf /etc/nginx/sites-enabled/thehive.conf
if [[ -e /etc/nginx/sites-enabled/default ]]; then rm -f /etc/nginx/sites-enabled/default; fi
nginx -t
systemctl reload nginx

log "All done."
echo
echo "Open your browser at: http://$(detect_ip)/"
echo "Status API (server side): curl -s http://127.0.0.1:9000/api/status | jq ."
