#!/bin/bash
# setup_thehive_all_in_one.sh
#
# Purpose:
#   End-to-end bootstrap for a lab/POC where TheHive, Nginx and Splunk
#   all run on the same server.
#
#   This script will:
#     1) Ask for TheHive FQDN (server name).
#     2) Generate a self-signed TLS certificate/key for Nginx (if missing).
#     3) Configure an Nginx reverse proxy for TheHive (HTTPS on port 443).
#     4) Configure the TA-thehive-cortex app on Splunk:
#        - Create an *empty* thehive_cortex_instances.csv lookup (TheHive/TA UI will populate it).
#        - Create a Data Input stanza for "TheHive: Alerts & Cases".
#        - Append TheHive certificate to certifi's cacert.pem for TLS verify.
#     5) Restart Splunk.
#
# IMPORTANT:
#   - You must install TheHive and Splunk (and TA-thehive-cortex) beforehand.
#   - Run this script as root.
#   - You still need to configure the TheHive API key in Splunk UI
#     (TA-thehive-cortex > Configuration > Account).

set -euo pipefail

########################
# Ask for SERVER_NAME  #
########################

read -rp "Enter TheHive FQDN (default: thehive.example.com): " SERVER_NAME_INPUT
SERVER_NAME="${SERVER_NAME_INPUT:-thehive.example.com}"

echo "==> Using SERVER_NAME=${SERVER_NAME}"

########################
# NGINX / TheHive      #
########################

# Paths to TLS certificate and key consumed by Nginx.
CERT_PATH="/etc/ssl/certs/thehive.crt"
KEY_PATH="/etc/ssl/private/thehive.key"

# Where TheHive itself is listening (HTTP).
BACKEND_HOST="127.0.0.1"
BACKEND_PORT="9000"

NGINX_SITES_AVAILABLE="/etc/nginx/sites-available"
NGINX_SITES_ENABLED="/etc/nginx/sites-enabled"
NGINX_SITE_NAME="thehive"
NGINX_SITE_CONF="${NGINX_SITES_AVAILABLE}/${NGINX_SITE_NAME}.conf"
NGINX_ENABLED_LINK="${NGINX_SITES_ENABLED}/${NGINX_SITE_NAME}.conf"

########################
# Splunk / TA config   #
########################

# Splunk runtime paths and user.
SPLUNK_USER="splunk"
SPLUNK_GROUP="splunk"
SPLUNK_HOME="/opt/splunk"

# TA-thehive-cortex app paths.
APP_NAME="TA-thehive-cortex"
APP_DIR="${SPLUNK_HOME}/etc/apps/${APP_NAME}"
LOOKUP_DIR="${APP_DIR}/lookups"
LOOKUP_FILE="${LOOKUP_DIR}/thehive_cortex_instances.csv"

LOCAL_DIR="${APP_DIR}/local"
INPUTS_CONF="${LOCAL_DIR}/inputs.conf"

# certifi bundle path inside the TA (where we'll append TheHive cert)
CERTIFI_CACERT="${APP_DIR}/bin/ta_thehive_cortex/aob_py3/certifi/cacert.pem"

# TheHive instance parameters as seen by the TA.
INSTANCE_ID="aa9d6b2a"          # Any unique ID (string). UI normally generates one.
ACCOUNT_NAME="thehive"          # Must match the account name created in TA UI.
AUTH_TYPE="api_key"
HOST="${SERVER_NAME}"           # Can be FQDN or IP. Here we use the Nginx FQDN.
PORT="443"
PROTO="https"
TYPE="TheHive5"
URI="/"
ORG="-"
VERIFY="true"                   # true = verify TLS cert (we will append the cert to cacert.pem).

# Splunk index where TheHive alerts/cases will be stored.
THEHIVE_INDEX="thehive"

#########################################
# 0) Generate self-signed TLS certificate
#########################################

echo "==> Checking TLS certificate/key for Nginx ..."

if [[ -f "${CERT_PATH}" && -f "${KEY_PATH}" ]]; then
  echo "==> Existing certificate and key found:"
  echo "    CERT_PATH=${CERT_PATH}"
  echo "    KEY_PATH=${KEY_PATH}"
else
  echo "==> No valid certificate/key found. Generating self-signed certificate ..."
  mkdir -p "$(dirname "${CERT_PATH}")" "$(dirname "${KEY_PATH}")"

  openssl req -x509 -nodes -newkey rsa:4096 \
    -keyout "${KEY_PATH}" \
    -out "${CERT_PATH}" \
    -days 365 \
    -subj "/C=IR/ST=Tehran/L=Tehran/O=Lab/OU=TheHive/CN=${SERVER_NAME}"

  chmod 600 "${KEY_PATH}"
  chmod 644 "${CERT_PATH}"

  echo "==> Self-signed certificate generated:"
  echo "    ${CERT_PATH}"
  echo "    ${KEY_PATH}"
fi

##################################
# 1) Configure Nginx for TheHive #
##################################

echo "==> Configuring Nginx reverse proxy for TheHive ..."

if ! command -v nginx >/dev/null 2>&1; then
  echo "WARNING: nginx is not installed. Skipping Nginx configuration."
else
  echo "==> Writing Nginx site configuration: ${NGINX_SITE_CONF}"
  mkdir -p "${NGINX_SITES_AVAILABLE}" "${NGINX_SITES_ENABLED}"

  cat > "${NGINX_SITE_CONF}" <<EOF
server {
    listen 443 ssl;
    server_name ${SERVER_NAME};

    ssl_certificate ${CERT_PATH};
    ssl_certificate_key ${KEY_PATH};

    location / {
        proxy_pass http://${BACKEND_HOST}:${BACKEND_PORT};
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains";
    }
}
EOF

  echo "==> Enabling Nginx site: ${NGINX_ENABLED_LINK}"
  ln -sf "${NGINX_SITE_CONF}" "${NGINX_ENABLED_LINK}"

  echo "==> Testing Nginx configuration ..."
  nginx -t

  echo "==> Reloading Nginx ..."
  systemctl reload nginx
fi

#################################
# 2) Configure Splunk TA lookup #
#################################

echo "==> Configuring TA-thehive-cortex on Splunk ..."

if [ ! -d "${APP_DIR}" ]; then
  echo "ERROR: ${APP_DIR} does not exist."
  echo "Install ${APP_NAME} from Splunkbase first (Apps > Manage Apps)."
  exit 1
fi

echo "==> Fixing ownership of TA app directory ..."
chown -R "${SPLUNK_USER}:${SPLUNK_GROUP}" "${APP_DIR}"

echo "==> Creating lookup directory: ${LOOKUP_DIR}"
mkdir -p "${LOOKUP_DIR}"
chown "${SPLUNK_USER}:${SPLUNK_GROUP}" "${LOOKUP_DIR}"
chmod 755 "${LOOKUP_DIR}"

echo "==> Creating *empty* instance lookup CSV (TheHive/TA UI will populate it): ${LOOKUP_FILE}"
# Create or truncate to empty file; no header, no rows.
: > "${LOOKUP_FILE}"

chown "${SPLUNK_USER}:${SPLUNK_GROUP}" "${LOOKUP_FILE}"
chmod 644 "${LOOKUP_FILE}"

###############################################################
# 2b) Append TheHive certificate to certifi's cacert.pem file #
###############################################################

if [ -f "${CERTIFI_CACERT}" ]; then
  echo "==> Backing up certifi cacert.pem ..."
  cp "${CERTIFI_CACERT}" "${CERTIFI_CACERT}.bak-$(date +%F_%H%M%S)"

  echo "==> Appending TheHive certificate (${CERT_PATH}) to certifi cacert.pem ..."
  cat "${CERT_PATH}" >> "${CERTIFI_CACERT}"
else
  echo "WARNING: certifi cacert.pem not found at: ${CERTIFI_CACERT}"
  echo "         Cannot append TheHive certificate for TLS verification."
fi

##########################################
# 3) Create TheHive Alerts & Cases input #
##########################################

echo "==> Creating inputs.conf stanza for 'TheHive: Alerts & Cases' (if missing) ..."

mkdir -p "${LOCAL_DIR}"
chown -R "${SPLUNK_USER}:${SPLUNK_GROUP}" "${LOCAL_DIR}"

if [ -f "${INPUTS_CONF}" ]; then
  if grep -q "^\[thehive_alerts_cases://thehive_alerts_cases\]" "${INPUTS_CONF}"; then
    echo "==> Stanza [thehive_alerts_cases://thehive_alerts_cases] already present in inputs.conf. Leaving it untouched."
  else
    echo "==> Appending the thehive_alerts_cases stanza to existing inputs.conf"
    cat >> "${INPUTS_CONF}" <<EOF

[thehive_alerts_cases://thehive_alerts_cases]
instance_id = ${INSTANCE_ID}
type = alerts_cases
index = ${THEHIVE_INDEX}
sourcetype = thehive:alerts_cases
disabled = 0
EOF
  fi
else
  echo "==> Creating new inputs.conf with thehive_alerts_cases stanza"
  cat > "${INPUTS_CONF}" <<EOF
[thehive_alerts_cases://thehive_alerts_cases]
instance_id = ${INSTANCE_ID}
type = alerts_cases
index = ${THEHIVE_INDEX}
sourcetype = thehive:alerts_cases
disabled = 0
EOF
fi

chown "${SPLUNK_USER}:${SPLUNK_GROUP}" "${INPUTS_CONF}"
chmod 644 "${INPUTS_CONF}"

########################################
# 4) Cleanup and restart Splunk       #
########################################

echo "==> Cleaning temporary lookup / kvs directories (optional) ..."
rm -rf "${SPLUNK_HOME}/var/run/splunk/lookup_tmp/"* || true
rm -rf "${SPLUNK_HOME}/var/run/splunk/kvs/"* || true

echo "==> Restarting Splunk ..."
"${SPLUNK_HOME}/bin/splunk" restart

echo "==> All done."
echo "Post-checks:"
echo "  1) curl -sk https://${SERVER_NAME}/api/v1/status"
echo "  2) In Splunk search:  | inputlookup thehive_cortex_instances"
echo "  3) In Splunk UI: Settings > Data inputs > TheHive: Alerts & Cases (thehive_alerts_cases should be visible and enabled)."
