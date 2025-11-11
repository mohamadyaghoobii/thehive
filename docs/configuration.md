# Detailed Configuration Guide

## Table of Contents
- [TheHive Configuration](#thehive-configuration)
- [Cortex Configuration](#cortex-configuration)
- [Database Configuration](#database-configuration)
- [Integration Setup](#integration-setup)
- [Security Hardening](#security-hardening)

## TheHive Configuration

### Basic Settings

```conf
# /etc/thehive/application.conf

# Secret key (must be changed in production)
include "/etc/thehive/secret.conf"

# Server configuration
play.http.context = "/"
application.baseUrl = "http://your-domain.com:9000"

# Request size limits
play.http.parser.maxDiskBuffer = 1GB    # Max attachment size
play.http.parser.maxMemoryBuffer = 10M  # Max request size
