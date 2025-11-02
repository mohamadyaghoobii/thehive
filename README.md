# TheHive 4 Bootstrap (Ubuntu 22.04)

One-click installer for **TheHive 4.1.24** on Ubuntu 22.04 (Jammy).
Installs and configures **Cassandra 3.11**, **Elasticsearch 7.17**, **TheHive**, and **Nginx** (reverse proxy on port 80).

> **Scope:** lab / POC / single-node. For production, add TLS, harden, resize, and plan backups.

## What it installs
- Cassandra 3.11 (localhost)
- Elasticsearch 7.17 (localhost, single-node, security disabled)
- TheHive 4.1.24 (binds to 127.0.0.1:9000)
- Nginx reverse proxy (serves TheHive on port 80)

## Requirements
- Ubuntu 22.04 (Jammy)
- Root privileges
- Outbound internet access to vendor repositories
- Inbound TCP/80 reachable from users (network ACLs / hypervisor / cloud SGs)

## Quick start
```bash
sudo bash scripts/install_thehive4.sh
# Optional: set PUBLIC_BASEURL=http://<SERVER-IP> before running
```

Open your browser: `http://<SERVER-IP>/` and complete the initial wizard.

## Health checks
```bash
journalctl -u cassandra -f
journalctl -u elasticsearch -f
journalctl -u thehive -f
tail -f /var/log/nginx/thehive-access.log /var/log/nginx/thehive-error.log

# Local (server) status checks
curl -s http://127.0.0.1:9000/api/status | jq .
curl -s http://127.0.0.1:9200 | jq .
```

## Uninstall (destructive)
```bash
sudo systemctl stop thehive elasticsearch cassandra nginx
sudo apt remove -y thehive elasticsearch cassandra nginx || true
sudo rm -rf /opt/thehive /etc/thehive /var/log/thehive \
            /var/lib/elasticsearch /var/log/elasticsearch \            /var/lib/cassandra /var/log/cassandra
```

## Roadmap
- Optional TLS via Nginx
- System tuning and backup docs
- Separate Cortex bootstrap (in a dedicated repo)

## License
MIT
