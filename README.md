# TheHive & Cortex Enterprise Deployment Platform

![Platform](https://img.shields.io/badge/Platform-SOC%20Incident%20Response-blue)
![Version](https://img.shields.io/badge/Version-2.0--Enterprise-green)
![License](https://img.shields.io/badge/License-MIT-orange)

A production-ready deployment of **TheHive 5.2.16** and **Cortex 3.1.8** designed for Security Operations Centers (SOC).  
This environment supports efficient incident response, automated enrichment, collaboration, and large-scale case management.

---

## 🏗️ Architecture Overview

This deployment consists of five primary components that work together to provide a scalable and high-performance incident response platform:

### **1. TheHive (Port 9000)**
The central Incident Response platform where analysts manage alerts, cases, tasks, observables, collaboration workflows, and investigations.

### **2. Cortex (Port 9001)**
The analysis engine responsible for executing analyzers and automated response actions. TheHive communicates directly with Cortex to enrich observables and automate tasks.

### **3. Cassandra Database (Port 9042)**
A distributed NoSQL datastore used by TheHive to store case data, observables, metadata, and attachments. Ensures durability and high availability.

### **4. Elasticsearch (Port 9200)**
Indexes and provides fast search capabilities across alerts, cases, artifacts, and logs — enabling efficient investigations even at scale.

### **5. Nginx Reverse Proxy (Optional, Port 80/443)**
Provides secure external access (HTTPS), load balancing, and simplified access control for web interaction with TheHive and Cortex.

---

## 🚀 Quick Deployment

### Automated Installation

```bash
wget -O deploy.sh https://raw.githubusercontent.com/mohamadyaghoobii/thehive-cortex-deploy/master/deploy.sh
chmod +x deploy.sh
sudo ./deploy.sh
```

### Installed Components

| Component       | Version  | Purpose                      | Port |
|----------------|----------|------------------------------|------|
| TheHive        | 5.2.16   | Incident Response Platform   | 9000 |
| Cortex         | 3.1.8    | Analysis Engine              | 9001 |
| Elasticsearch  | 7.17.29  | Search and Analytics         | 9200 |
| Cassandra      | 3.11.x   | Distributed Database         | 9042 |
| Java (OpenJDK) | 11       | Runtime Environment          | -    |

---

## 📋 Requirements

- **OS:** Ubuntu 20.04/22.04 or Debian 11/12  
- **RAM:** 8GB min (16GB recommended)  
- **Storage:** 50GB+  
- **CPU:** 4 cores recommended  
- **Network:** Internet access + open ports (9000, 9001)

---

## 🛠️ Installation Steps

### 1. System Preparation

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y curl wget git
```

### 2. Deployment

```bash
sudo ./deploy.sh
```

### 3. Integration Setup

```bash
sudo ./configure-integration.sh
```

This will automatically create API keys and connect TheHive with Cortex.

---

## 🔐 Default Credentials

| Service | URL | Username | Password |
|--------|-----|----------|----------|
| TheHive | http://your-server:9000 | admin@thehive.local | secret |
| Cortex  | http://your-server:9001 | admin | admin |

⚠️ **Change these credentials immediately after installation.**

---

## 🧪 Health Checks

```bash
systemctl status thehive cortex elasticsearch cassandra
curl -s http://localhost:9000/api/status | jq .
curl -s http://localhost:9001/api/status | jq .
curl -s http://localhost:9200 | jq .
```

---

## 🗂️ Key Directories

| Path | Description |
|------|-------------|
| `/etc/thehive/application.conf` | TheHive main config |
| `/etc/cortex/application.conf` | Cortex main config |
| `/var/lib/cassandra/` | Cassandra data |
| `/var/lib/elasticsearch/` | Elasticsearch data |
| `/opt/thp/thehive/` | TheHive data and attachments |

---

## 🔧 Service Management

```bash
sudo systemctl restart thehive cortex
journalctl -u thehive -f
journalctl -u cortex -f
```

---

## 📈 Production Recommendations

- Enable HTTPS (TLS)
- Change all default passwords
- Configure firewall rules
- Schedule backups & monitoring
- Tune JVM heap sizes and Elasticsearch index performance

---

## 📄 License

Licensed under the **MIT License**.

---

<div align="center">

**🚀 Happy Incident Responding!**

</div>
