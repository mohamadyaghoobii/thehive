# Quickstart

## Install
```bash
sudo bash scripts/install_thehive4.sh
```

## Access
- Browser: `http://<SERVER-IP>/`
- First-run wizard will guide you to create the organization and admin user.

## Key variables (override before running)
- `PUBLIC_BASEURL` – e.g., `http://10.10.14.12`
- `ES_HEAP` – Elasticsearch heap (default: `1g`)
- `THEHIVE_HEAP_MB` – TheHive heap in MB (default: `1024`)
- `THEHIVE_ZIP_URL` – Direct URL to `thehive4-4.1.24-1.zip` (optional; script has candidates)
