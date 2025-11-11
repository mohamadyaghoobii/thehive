TheHive & Cortex Enterprise Deployment Platform
https://img.shields.io/badge/Platform-SOC%2520Incident%2520Response-blue
https://img.shields.io/badge/Version-2.0--Enterprise-green
https://img.shields.io/badge/License-MIT-orange

A complete, production-ready deployment of TheHive 5.2.16 and Cortex 3.1.8 for Security Operations Centers. This automated deployment provides a robust incident response and threat analysis platform.

🏗️ Architecture Overview

┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   TheHive 5.2   │    │   Cortex 3.1    │    │   Web Interface  │
│   Port: 9000    │◄──►│   Port: 9001    │    │   Port: 80/443   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  Cassandra DB   │    │  Elasticsearch  │    │    Nginx Proxy  │
│   Port: 9042    │    │   Port: 9200    │    │   (Optional)    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
🚀 Quick Deployment
Automated One-Command Installation

# Download and execute the deployment script
wget -O deploy.sh https://raw.githubusercontent.com/your-repo/thehive-cortex-deploy/master/deploy.sh
chmod +x deploy.sh
sudo ./deploy.sh
What Gets Installed
Component	Version	Purpose	Port
TheHive	5.2.16	Incident Response Platform	9000
Cortex	3.1.8	Analysis Engine	9001
Elasticsearch	7.17.29	Search & Analytics	9200
Cassandra	3.11.x	Scalable Database	9042
Java	OpenJDK 11	Runtime Environment	-
📋 Prerequisites
System Requirements
OS: Ubuntu 20.04/22.04 or Debian 11/12

RAM: 8GB minimum, 16GB recommended

Storage: 50GB+ free space

CPU: 4+ cores recommended

Network: Internet access for package downloads

Network Requirements
Inbound Ports: 9000 (TheHive), 9001 (Cortex)

Outbound Access: To vendor repositories

Firewall: Ensure ports are accessible to your team

🛠️ Installation Steps
Step 1: System Preparation

# Update system and install dependencies
sudo apt update && sudo apt upgrade -y
sudo apt install -y curl wget git
Step 2: Run Deployment

# Execute the main deployment script
sudo ./deploy.sh
The deployment process includes:

✅ System dependency installation

✅ Elasticsearch 7.17.29 setup

✅ Cassandra database configuration

✅ TheHive 5.2.16 installation

✅ Cortex 3.1.8 installation

✅ Service configuration and optimization

✅ Health checks and validation

Step 3: Integration Setup

# Connect TheHive with Cortex
sudo ./configure-integration.sh
🔗 Cortex-TheHive Integration
Automated Integration
The configure-integration.sh script automatically:

Creates an organization admin user in Cortex

Generates API keys for secure communication

Configures TheHive to connect to Cortex

Tests the integration and verifies analyzer availability

Manual Integration (UI Method)
If you prefer manual setup or the automated script fails:

Step 1: Create Organization Admin in Cortex
Access Cortex UI: http://your-server:9001

Login: Use default credentials admin / admin

Navigate: Go to Organization → Users

Create User:

Login: thehive-integration

Name: TheHive Integration User

Roles: Select orgAdmin, read, analyze

Password: Set a strong password

Generate API Key:

Go to the user's profile

Click API Keys → Generate new key

Copy the API key - you'll need it for TheHive configuration

Step 2: Configure TheHive Manually
Edit the TheHive configuration file:


sudo nano /etc/thehive/application.conf
Add the Cortex configuration:

conf
play.modules.enabled += org.thp.thehive.connector.cortex.CortexModule

cortex {
  servers = [
    {
      name = "local-cortex"
      url = "http://127.0.0.1:9001"
      auth {
        type = "bearer"
        key = "YOUR_API_KEY_HERE"
      }
    }
  ]
}
Step 3: Restart and Verify

# Restart TheHive service
sudo systemctl restart thehive

# Verify integration
curl http://localhost:9000/api/connector/cortex/analyzer
🔐 Default Access Credentials
Service	URL	Default Credentials
TheHive	http://your-server:9000	admin@thehive.local / secret
Cortex	http://your-server:9001	admin / admin
⚠️ Security Note: Change these default passwords immediately after installation!

🧪 Health Verification
Service Status Check

# Use the built-in health check script
check-thehive-status

# Or check manually
systemctl status thehive cortex elasticsearch cassandra
API Endpoint Verification

# TheHive API
curl -s http://localhost:9000/api/status | jq .

# Cortex API  
curl -s http://localhost:9001/api/status | jq .

# Elasticsearch
curl -s http://localhost:9200 | jq .

# Integration test
curl -s http://localhost:9000/api/connector/cortex/analyzer | jq '. | length'
🗂️ Important Files & Directories
Configuration Files
/etc/thehive/application.conf - TheHive main configuration

/etc/cortex/application.conf - Cortex main configuration

/etc/elasticsearch/elasticsearch.yml - Elasticsearch config

/etc/cassandra/cassandra.yaml - Cassandra config

Data Directories
/opt/thp/thehive/ - TheHive data and attachments

/var/lib/cassandra/ - Cassandra database files

/var/lib/elasticsearch/ - Elasticsearch indices

Log Files
journalctl -u thehive -f - TheHive service logs

journalctl -u cortex -f - Cortex service logs

/var/log/elasticsearch/ - Elasticsearch logs

/var/log/cassandra/ - Cassandra logs

🔧 Management & Maintenance
Service Management

# Start all services
sudo systemctl start thehive cortex elasticsearch cassandra

# Stop all services  
sudo systemctl stop thehive cortex elasticsearch cassandra

# Restart services (common after config changes)
sudo systemctl restart thehive cortex

# Check service status
sudo systemctl status thehive cortex elasticsearch cassandra
Backup Configuration

# Backup configurations and data
sudo /root/backup-configs.sh

# The backup includes:
# - Application configurations
# - Service files
# - Database schemas
🐛 Troubleshooting
Common Issues
Services Not Starting

# Check service logs
journalctl -u thehive --lines=50
journalctl -u cortex --lines=50

# Verify database connectivity
curl -s http://localhost:9200 > /dev/null && echo "Elasticsearch: OK" || echo "Elasticsearch: FAIL"
cqlsh -e "DESCRIBE KEYSPACES;" > /dev/null && echo "Cassandra: OK" || echo "Cassandra: FAIL"
Integration Problems

# Test Cortex API directly
curl -H "Authorization: Bearer YOUR_API_KEY" http://localhost:9001/api/analyzer

# Verify user permissions in Cortex
# Check that the user has 'orgAdmin' role
Performance Issues

# Check system resources
check-thehive-status

# Monitor resource usage
htop
df -h
Getting Help
Check the service logs: journalctl -u service-name

Verify configuration files for syntax errors

Ensure all services are running and accessible

Check network connectivity between services

📈 Production Considerations
Security Hardening
Change all default passwords

Configure HTTPS/TLS encryption

Set up firewall rules

Implement network segmentation

Configure regular backups

Set up monitoring and alerting

Performance Optimization
Adjust JVM heap sizes based on available memory

Configure Cassandra and Elasticsearch for your workload

Set up regular maintenance tasks

Monitor disk space and performance metrics

Backup Strategy

# Regular configuration backups
0 2 * * * /root/backup-configs.sh

# Database backups (implement based on your environment)
# - Cassandra: nodetool snapshot
# - Elasticsearch: snapshot API
🗺️ Roadmap
TLS/SSL configuration automation

Multi-node cluster deployment

Docker container deployment

Advanced monitoring integration

Backup and restore automation

Performance tuning guides

📄 License
This project is licensed under the MIT License - see the LICENSE file for details.

🤝 Contributing
Contributions are welcome! Please feel free to submit pull requests or open issues for bugs and feature requests.

🙏 Acknowledgments
TheHive Project - For the amazing incident response platform

Cortex - For the powerful analysis engine

The security community - For continuous feedback and improvement

Need Help?

📖 TheHive Documentation

💬 Community Forum

🐛 GitHub Issues

<div align="center">
🚀 Happy Incident Responding!

</div>
