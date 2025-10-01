# Security Hardening Procedures Guide

This comprehensive guide covers security hardening procedures for Privatus-chat deployments, including system hardening, application security, network security, and compliance considerations.

## Table of Contents

- [System Hardening](#system-hardening)
- [Application Security](#application-security)
- [Network Security](#network-security)
- [Data Protection](#data-protection)
- [Access Control](#access-control)
- [Monitoring and Alerting](#monitoring-and-alerting)
- [Compliance](#compliance)
- [Incident Response](#incident-response)

## System Hardening

### Operating System Hardening

#### Linux Server Hardening
```bash
#!/bin/bash
# linux_hardening.sh

# Update system
apt-get update && apt-get upgrade -y
apt-get install -y unattended-upgrades fail2ban ufw auditd

# Configure automatic updates
cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF

# Configure firewall
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 6881/udp  # DHT port
ufw --force enable

# Configure fail2ban
cat > /etc/fail2ban/jail.local << 'EOF'
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600

[privatus-chat]
enabled = true
port = 80,443,8080
filter = privatus-chat
logpath = /var/log/privatus-chat/access.log
maxretry = 10
bantime = 3600
EOF

# Harden sysctl
cat > /etc/sysctl.d/99-security.conf << 'EOF'
# IP spoofing protection
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Ignore ICMP broadcast requests
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Disable source packet routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0

# Ignore send redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0

# Block SYN attacks
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5

# Log Martians
net.ipv4.conf.all.log_martians = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Ignore ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
EOF

sysctl -p /etc/sysctl.d/99-security.conf

# Set secure umask
echo 'umask 027' >> /etc/bash.bashrc

# Disable unused services
systemctl disable avahi-daemon
systemctl disable cups
systemctl disable bluetooth
systemctl mask ctrl-alt-del.target

# Configure auditd
cat > /etc/audit/auditd.conf << 'EOF'
log_file = /var/log/audit/audit.log
log_format = RAW
log_group = root
priority_boost = 4
flush = INCREMENTAL_ASYNC
freq = 50
max_log_file = 8
max_log_file_action = ROTATE
space_left = 75
space_left_action = SYSLOG
admin_space_left = 50
admin_space_left_action = SUSPEND
disk_full_action = SUSPEND
disk_error_action = SUSPEND
EOF

systemctl enable auditd
systemctl start auditd
```

#### Windows Server Hardening
```powershell
# Windows server hardening script
# windows_hardening.ps1

# Enable Windows Firewall
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

# Configure firewall rules for Privatus-chat
New-NetFirewallRule -DisplayName "Privatus-chat HTTP" -Direction Inbound -LocalPort 8080 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "Privatus-chat DHT" -Direction Inbound -LocalPort 6881 -Protocol UDP -Action Allow

# Enable Windows Defender
Set-MpPreference -DisableRealtimeMonitoring $false
Set-MpPreference -DisableBehaviorMonitoring $false

# Configure Windows Update
# Enable automatic updates
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -Value 4

# Disable unnecessary services
$services = @(
    "XboxGipSvc",
    "XblAuthManager",
    "XblGameSave",
    "XboxNetApiSvc",
    "WerSvc",
    "WMPNetworkSvc"
)

foreach ($service in $services) {
    Set-Service -Name $service -StartupType Disabled
    Stop-Service -Name $service -Force
}

# Configure audit policy
auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable
auditpol /set /category:"Object Access" /success:enable /failure:enable
auditpol /set /category:"Privilege Use" /success:enable /failure:enable

# Enable PowerShell logging
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting" -Value 1
```

### Container Security

#### Docker Security Hardening
```bash
#!/bin/bash
# docker_hardening.sh

# Enable Docker daemon security features
cat > /etc/docker/daemon.json << 'EOF'
{
  "iptables": true,
  "icc": false,
  "userns-remap": "default",
  "log-driver": "syslog",
  "log-opts": {
    "syslog-address": "unixgram:///var/run/syslog.sock",
    "tag": "docker"
  },
  "storage-driver": "overlay2",
  "tls": true,
  "tlsverify": true,
  "tlscacert": "/etc/docker/ca.pem",
  "tlscert": "/etc/docker/server-cert.pem",
  "tlskey": "/etc/docker/server-key.pem"
}
EOF

# Create Docker user namespace mapping
echo "privatus:100000:65536" >> /etc/subuid
echo "privatus:100000:65536" >> /etc/subgid

# Configure Docker content trust
export DOCKER_CONTENT_TRUST=1

# Enable Docker seccomp
cat > /etc/docker/seccomp.json << 'EOF'
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "syscalls": [
    {
      "name": "accept",
      "action": "SCMP_ACT_ALLOW"
    },
    {
      "name": "bind",
      "action": "SCMP_ACT_ALLOW"
    },
    {
      "name": "listen",
      "action": "SCMP_ACT_ALLOW"
    }
  ]
}
EOF

systemctl restart docker
```

#### Kubernetes Security
```yaml
apiVersion: v1
kind: PodSecurityPolicy
metadata:
  name: privatus-chat-restricted
spec:
  privileged: false
  allowPrivilegeEscalation: false
  requiredDropCapabilities:
    - ALL
  volumes:
    - 'configMap'
    - 'secret'
    - 'emptyDir'
    - 'persistentVolumeClaim'
  runAsUser:
    rule: 'MustRunAsNonRoot'
  seLinux:
    rule: 'RunAsAny'
  fsGroup:
    rule: 'RunAsAny'
  supplementalGroups:
    rule: 'RunAsAny'
```

## Application Security

### Secure Configuration

#### Environment Variables Security
```bash
# Secure environment configuration
cat > /opt/privatus-chat/config/.env.secure << 'EOF'
# Database Configuration
DATABASE_URL=postgresql://privatus:$(cat /opt/privatus-chat/secrets/db_password)@db:5432/privatus_prod

# Security Keys (generated securely)
SECRET_KEY_FILE=/opt/privatus-chat/secrets/secret_key
ENCRYPTION_MASTER_KEY_FILE=/opt/privatus-chat/secrets/master_key

# SSL/TLS Configuration
SSL_CERT_FILE=/opt/privatus-chat/ssl/cert.pem
SSL_KEY_FILE=/opt/privatus-chat/ssl/key.pem
SSL_CIPHERS=ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384

# Security Headers
SECURE_HEADERS=true
HSTS_MAX_AGE=31536000
CSP_DEFAULT_SRC="'self'"
CSP_SCRIPT_SRC="'self' 'unsafe-inline'"
CSP_STYLE_SRC="'self' 'unsafe-inline'"

# Rate Limiting
RATE_LIMIT_PER_MINUTE=100
RATE_LIMIT_BURST=20

# Session Security
SESSION_TIMEOUT=3600
SESSION_COOKIE_SECURE=true
SESSION_COOKIE_HTTPONLY=true
SESSION_COOKIE_SAMESITE=strict
EOF

# Set secure permissions
chmod 600 /opt/privatus-chat/config/.env.secure
chown privatus:privatus /opt/privatus-chat/config/.env.secure
```

#### Secrets Management
```bash
#!/bin/bash
# secrets_management.sh

# Generate secure secrets
openssl rand -base64 32 > /opt/privatus-chat/secrets/secret_key
openssl rand -base64 32 > /opt/privatus-chat/secrets/master_key
openssl rand -base64 16 > /opt/privatus-chat/secrets/db_password

# Set secure permissions
chmod 600 /opt/privatus-chat/secrets/*
chown privatus:privatus /opt/privatus-chat/secrets/*

# Backup secrets (encrypted)
tar -czf - /opt/privatus-chat/secrets/ | \
  openssl enc -aes-256-cbc -salt -pbkdf2 \
  -pass file:/opt/privatus-chat/secrets/master_key \
  > secrets_backup_$(date +%Y%m%d_%H%M%S).enc

# Rotate secrets periodically
cat > /etc/cron.daily/rotate-secrets << 'EOF'
#!/bin/bash
# Rotate application secrets

# Generate new secrets
openssl rand -base64 32 > /opt/privatus-chat/secrets/secret_key.new
openssl rand -base64 32 > /opt/privatus-chat/secrets/master_key.new

# Update application configuration atomically
mv /opt/privatus-chat/secrets/secret_key.new /opt/privatus-chat/secrets/secret_key
mv /opt/privatus-chat/secrets/master_key.new /opt/privatus-chat/secrets/master_key

# Restart application to use new secrets
systemctl reload privatus-chat

# Remove old backup files after successful rotation
find /opt/privatus-chat/secrets/backup -name "*.old" -mtime +30 -delete
EOF

chmod +x /etc/cron.daily/rotate-secrets
```

### Authentication and Authorization

#### Multi-Factor Authentication Setup
```python
# MFA configuration
MFA_CONFIG = {
    'issuer': 'Privatus-chat',
    'secret_length': 32,
    'valid_window': 1,
    'backup_codes_count': 10,
    'mfa_required_for_admin': True,
    'mfa_grace_period': 3600  # 1 hour grace period for new devices
}

# Session security
SESSION_CONFIG = {
    'secure': True,
    'httponly': True,
    'samesite': 'strict',
    'max_age': 3600,
    'domain': None,
    'path': '/',
    'regenerate_on_auth': True
}
```

#### Role-Based Access Control
```python
# RBAC configuration
RBAC_ROLES = {
    'admin': {
        'permissions': [
            'user_management',
            'system_configuration',
            'audit_log_access',
            'backup_management',
            'security_settings'
        ],
        'mfa_required': True
    },
    'moderator': {
        'permissions': [
            'message_moderation',
            'user_reports',
            'content_filtering'
        ],
        'mfa_required': False
    },
    'user': {
        'permissions': [
            'message_sending',
            'file_sharing',
            'profile_management'
        ],
        'mfa_required': False
    }
}
```

## Network Security

### TLS/SSL Configuration

#### Nginx SSL Hardening
```nginx
server {
    listen 443 ssl http2;
    server_name chat.example.com;

    # SSL configuration
    ssl_certificate /etc/ssl/certs/privatus-chat.crt;
    ssl_certificate_key /etc/ssl/private/privatus-chat.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384;
    ssl_prefer_server_ciphers off;

    # SSL security headers
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    ssl_session_tickets off;

    # Security headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload";
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'";
    add_header Referrer-Policy "strict-origin-when-cross-origin";

    # OCSP stapling
    ssl_stapling on;
    ssl_stapling_verify on;
    resolver 8.8.8.8 8.8.4.4 valid=300s;
    resolver_timeout 5s;

    location / {
        proxy_pass http://privatus_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

#### Certificate Management
```bash
#!/bin/bash
# certificate_management.sh

# Generate self-signed certificate (development)
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=chat.example.com"

# Generate certificate signing request (production)
openssl req -new -newkey rsa:4096 -keyout privatus-chat.key -out privatus-chat.csr \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=chat.example.com"

# Generate DH parameters for perfect forward secrecy
openssl dhparam -out dhparam.pem 4096

# Configure automatic certificate renewal
cat > /etc/cron.weekly/renew-certificates << 'EOF'
#!/bin/bash
# Certificate renewal script

CERT_DIR="/etc/ssl/certs"
CERT_FILE="$CERT_DIR/privatus-chat.crt"
KEY_FILE="$CERT_DIR/private/privatus-chat.key"

# Check if certificate expires in next 30 days
if openssl x509 -in $CERT_FILE -checkend $((30*24*3600)); then
    echo "Certificate is still valid"
else
    echo "Certificate expires soon, renewing..."

    # Renew certificate (this would integrate with Let's Encrypt or your CA)
    certbot renew

    # Reload services to use new certificate
    systemctl reload nginx
    systemctl reload privatus-chat
fi
EOF

chmod +x /etc/cron.weekly/renew-certificates
```

### Network Segmentation

#### VLAN Configuration
```bash
#!/bin/bash
# network_segmentation.sh

# Create VLAN interfaces for network segmentation
cat > /etc/netplan/50-privatus-vlans.yaml << 'EOF'
network:
  version: 2
  renderer: networkd
  vlans:
    privatus-app:
      id: 100
      link: eth0
      addresses: [10.0.1.0/24]
    privatus-db:
      id: 200
      link: eth0
      addresses: [10.0.2.0/24]
    privatus-admin:
      id: 300
      link: eth0
      addresses: [10.0.3.0/24]
EOF

netplan apply

# Configure iptables for VLAN isolation
iptables -A FORWARD -i privatus-app -o privatus-db -j DROP
iptables -A FORWARD -i privatus-db -o privatus-app -j DROP
iptables -A FORWARD -i privatus-app -o privatus-admin -j DROP
iptables -A FORWARD -i privatus-admin -o privatus-app -j DROP
```

## Data Protection

### Encryption at Rest

#### Database Encryption
```sql
-- PostgreSQL encryption setup
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Create encrypted tables
CREATE TABLE encrypted_messages (
    id SERIAL PRIMARY KEY,
    sender_id INTEGER NOT NULL,
    recipient_id INTEGER NOT NULL,
    content TEXT NOT NULL,
    content_iv TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Enable row-level encryption
ALTER TABLE encrypted_messages ADD COLUMN content_encrypted TEXT;
UPDATE encrypted_messages SET content_encrypted = pgp_sym_encrypt(content, 'master_key');
ALTER TABLE encrypted_messages DROP COLUMN content;
```

#### File Storage Encryption
```python
# File encryption configuration
FILE_ENCRYPTION_CONFIG = {
    'algorithm': 'AES-256-GCM',
    'key_derivation': 'PBKDF2',
    'key_length': 256,
    'iv_length': 96,
    'tag_length': 128,
    'iterations': 100000,
    'salt_length': 32
}

class EncryptedFileStorage:
    def store_file(self, file_path, content):
        # Generate encryption key and IV
        key = self.generate_key()
        iv = os.urandom(FILE_ENCRYPTION_CONFIG['iv_length'] // 8)

        # Encrypt file content
        encrypted_content = self.encrypt_content(content, key, iv)

        # Store encrypted file
        with open(file_path + '.enc', 'wb') as f:
            f.write(encrypted_content)

        # Store encryption metadata separately
        metadata = {
            'algorithm': FILE_ENCRYPTION_CONFIG['algorithm'],
            'key_hash': self.hash_key(key),
            'iv': iv.hex(),
            'original_size': len(content)
        }

        return metadata
```

### Encryption in Transit

#### Perfect Forward Secrecy
```bash
# Configure perfect forward secrecy
openssl dhparam -out /etc/ssl/dhparam.pem 4096

# Nginx configuration with PFS
ssl_dhparam /etc/ssl/dhparam.pem;
ssl_ecdh_curve secp384r1;
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384;
```

#### Certificate Pinning
```python
# Certificate pinning configuration
CERTIFICATE_PINS = {
    'chat.example.com': {
        'sha256': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
        'backup_pins': [
            'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=',
            'CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC='
        ]
    }
}

def verify_certificate_pinning(hostname, certificate):
    """Verify certificate against pinned certificates"""
    cert_fingerprint = self.get_certificate_fingerprint(certificate)

    if hostname in CERTIFICATE_PINS:
        pinned_fingerprints = [CERTIFICATE_PINS[hostname]['sha256']] + \
                             CERTIFICATE_PINS[hostname]['backup_pins']

        if cert_fingerprint not in pinned_fingerprints:
            raise CertificatePinningError(f"Certificate for {hostname} not pinned")

    return True
```

## Access Control

### User Authentication

#### Password Security Policy
```python
# Password policy configuration
PASSWORD_POLICY = {
    'min_length': 12,
    'max_length': 128,
    'require_uppercase': True,
    'require_lowercase': True,
    'require_digits': True,
    'require_symbols': True,
    'prevent_common_passwords': True,
    'prevent_dictionary_words': True,
    'check_password_strength': True,
    'password_history_count': 10,
    'password_expiry_days': 90,
    'account_lockout_threshold': 5,
    'account_lockout_duration': 30  # minutes
}

class PasswordValidator:
    def validate_password(self, password, user_context=None):
        """Validate password against security policy"""

        # Check length
        if len(password) < PASSWORD_POLICY['min_length']:
            raise ValidationError("Password too short")

        # Check complexity
        if PASSWORD_POLICY['require_uppercase'] and not re.search(r'[A-Z]', password):
            raise ValidationError("Password must contain uppercase letters")

        if PASSWORD_POLICY['require_digits'] and not re.search(r'\d', password):
            raise ValidationError("Password must contain digits")

        # Check against common passwords
        if self.is_common_password(password):
            raise ValidationError("Password is too common")

        # Check password strength using zxcvbn
        strength = self.check_password_strength(password, user_context)
        if strength['score'] < 3:
            raise ValidationError("Password is too weak")

        return True
```

#### Account Security
```python
# Account security measures
ACCOUNT_SECURITY_CONFIG = {
    'max_login_attempts': 5,
    'account_lockout_duration': 30,  # minutes
    'session_timeout': 3600,  # 1 hour
    'require_mfa_for_sensitive_actions': True,
    'login_notification': True,
    'suspicious_activity_detection': True,
    'geolocation_tracking': True,
    'device_fingerprinting': True
}

class AccountSecurityManager:
    def detect_suspicious_activity(self, login_attempt):
        """Detect suspicious login attempts"""

        # Check for unusual geolocation
        if self.is_unusual_location(login_attempt.ip_address):
            self.flag_suspicious_activity(login_attempt, "unusual_location")

        # Check for unusual time
        if self.is_unusual_time(login_attempt.timestamp):
            self.flag_suspicious_activity(login_attempt, "unusual_time")

        # Check for rapid login attempts
        if self.has_rapid_attempts(login_attempt.user_id):
            self.flag_suspicious_activity(login_attempt, "rapid_attempts")

        # Check device fingerprint
        if self.is_new_device(login_attempt.fingerprint):
            self.require_additional_verification(login_attempt)
```

## Monitoring and Alerting

### Security Monitoring

#### Intrusion Detection
```bash
#!/bin/bash
# intrusion_detection.sh

# Monitor failed login attempts
tail -f /var/log/auth.log | grep "Failed password" | \
while read line; do
    IP=$(echo $line | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}')
    echo "$(date): Failed login attempt from $IP" >> /var/log/security/failed_logins.log

    # Block IP after multiple failures
    COUNT=$(grep "$IP" /var/log/security/failed_logins.log | wc -l)
    if [ $COUNT -gt 5 ]; then
        iptables -A INPUT -s $IP -j DROP
        echo "$(date): Blocked IP $IP" >> /var/log/security/blocked_ips.log
    fi
done

# Monitor file system changes
auditctl -w /opt/privatus-chat/ -p wa -k privatus-files
auditctl -w /etc/privatus-chat/ -p wa -k privatus-config

# Monitor network connections
netstat -ant | grep :8080 | grep -v LISTEN | \
while read line; do
    echo "$(date): New connection: $line" >> /var/log/security/connections.log
done
```

#### Security Event Correlation
```python
class SecurityEventCorrelator:
    def __init__(self):
        self.event_window = 300  # 5 minutes
        self.correlation_rules = {
            'brute_force': {
                'events': ['failed_login', 'multiple_login_attempts'],
                'threshold': 10,
                'timeframe': 300,
                'action': 'block_ip'
            },
            'data_exfiltration': {
                'events': ['large_file_upload', 'unusual_data_export'],
                'threshold': 5,
                'timeframe': 600,
                'action': 'alert_admin'
            }
        }

    def correlate_events(self, events):
        """Correlate security events to detect attacks"""

        for rule_name, rule in self.correlation_rules.items():
            # Count events matching rule criteria
            matching_events = [
                event for event in events
                if event['type'] in rule['events'] and
                event['timestamp'] > time.time() - rule['timeframe']
            ]

            if len(matching_events) >= rule['threshold']:
                self.trigger_action(rule['action'], matching_events)

        return correlations
```

### Log Security

#### Secure Logging Configuration
```python
# Secure logging configuration
LOGGING_CONFIG = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'secure': {
            'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s - %(client_ip)s - %(user_id)s',
            'datefmt': '%Y-%m-%d %H:%M:%S'
        },
        'audit': {
            'format': '%(asctime)s - %(user)s - %(action)s - %(resource)s - %(result)s',
            'datefmt': '%Y-%m-%d %H:%M:%S'
        }
    },
    'handlers': {
        'secure_file': {
            'level': 'INFO',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': '/var/log/privatus-chat/security.log',
            'maxBytes': 10485760,  # 10MB
            'backupCount': 10,
            'formatter': 'secure'
        },
        'audit_file': {
            'level': 'INFO',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': '/var/log/privatus-chat/audit.log',
            'maxBytes': 10485760,
            'backupCount': 30,
            'formatter': 'audit'
        }
    },
    'loggers': {
        'security': {
            'handlers': ['secure_file'],
            'level': 'INFO',
            'propagate': False
        },
        'audit': {
            'handlers': ['audit_file'],
            'level': 'INFO',
            'propagate': False
        }
    }
}
```

## Compliance

### GDPR Compliance

#### Data Protection Measures
```python
# GDPR compliance configuration
GDPR_CONFIG = {
    'data_retention_periods': {
        'user_profiles': 365 * 3,  # 3 years
        'messages': 365 * 2,       # 2 years
        'audit_logs': 365 * 7,     # 7 years
        'security_logs': 365 * 2   # 2 years
    },
    'consent_management': {
        'required_consents': [
            'privacy_policy',
            'data_processing',
            'communication_preferences'
        ],
        'consent_expiry': 365,  # 1 year
        'withdrawal_process': True
    },
    'data_subject_rights': {
        'access_request_response_time': 30,  # days
        'deletion_request_response_time': 30, # days
        'data_portability_format': 'json'
    }
}

class GDPRComplianceManager:
    def handle_data_access_request(self, user_id):
        """Handle GDPR Article 15 - Right of access"""

        # Collect all user data
        user_data = self.collect_user_data(user_id)

        # Generate data export
        export_data = {
            'user_profile': user_data['profile'],
            'messages': user_data['messages'],
            'files': user_data['files'],
            'audit_trail': user_data['audit_logs'],
            'export_timestamp': datetime.utcnow(),
            'export_format_version': '1.0'
        }

        return self.encrypt_and_package_export(export_data)

    def handle_data_deletion_request(self, user_id):
        """Handle GDPR Article 17 - Right to erasure"""

        # Verify user identity
        if not self.verify_user_identity(user_id):
            raise SecurityError("Cannot verify user identity")

        # Anonymize user data
        self.anonymize_user_data(user_id)

        # Schedule data deletion
        self.schedule_data_deletion(user_id, GDPR_CONFIG['data_retention_periods'])

        # Log deletion request
        self.log_gdpr_action(user_id, 'data_deletion_requested')
```

### Security Auditing

#### Automated Security Auditing
```bash
#!/bin/bash
# security_audit.sh

# Perform comprehensive security audit
cat > /tmp/security_audit_$(date +%Y%m%d_%H%M%S).log << 'EOF'
=== SECURITY AUDIT REPORT ===
Generated: $(date)
System: $(uname -a)

=== FILE PERMISSIONS ===
$(find /opt/privatus-chat -type f -exec ls -la {} \;)

=== RUNNING PROCESSES ===
$(ps aux | grep privatus)

=== OPEN PORTS ===
$(netstat -tuln)

=== INSTALLED PACKAGES ===
$(dpkg -l | grep -E "(python|openssl|nginx)")

=== SSL CERTIFICATE INFO ===
$(openssl x509 -in /etc/ssl/certs/privatus-chat.crt -text -noout)

=== FIREWALL RULES ===
$(iptables -L -n -v)

=== USER ACCOUNTS ===
$(cat /etc/passwd | grep privatus)

=== LOG FILE INTEGRITY ===
$(ls -la /var/log/privatus-chat/)

EOF

# Check for common vulnerabilities
echo "=== VULNERABILITY SCAN ===" >> /tmp/security_audit.log
if command -v nikto &> /dev/null; then
    nikto -h localhost -port 8080 >> /tmp/security_audit.log
fi

# Check for open directories
echo "=== DIRECTORY LISTING CHECK ===" >> /tmp/security_audit.log
curl -I http://localhost:8080/ | grep -i "index"

# Send audit report to administrators
cat /tmp/security_audit.log | mail -s "Security Audit Report" admin@example.com
```

## Incident Response

### Incident Response Plan

#### Automated Incident Response
```python
class IncidentResponseManager:
    def __init__(self):
        self.response_playbooks = {
            'brute_force_attack': {
                'detection': 'multiple_failed_logins',
                'severity': 'high',
                'actions': [
                    'block_attacker_ip',
                    'notify_security_team',
                    'increase_rate_limiting',
                    'enable_additional_logging'
                ]
            },
            'data_breach': {
                'detection': 'unusual_data_access',
                'severity': 'critical',
                'actions': [
                    'isolate_affected_systems',
                    'notify_authorities',
                    'activate_backup_communications',
                    'preserve_evidence'
                ]
            }
        }

    def handle_incident(self, incident_type, incident_data):
        """Handle security incident according to playbook"""

        if incident_type not in self.response_playbooks:
            raise ValueError(f"Unknown incident type: {incident_type}")

        playbook = self.response_playbooks[incident_type]

        # Execute automated response actions
        for action in playbook['actions']:
            try:
                self.execute_action(action, incident_data)
                self.log_action_execution(action, 'success', incident_data)
            except Exception as e:
                self.log_action_execution(action, 'failed', incident_data, str(e))

        # Notify human responders if severity is high
        if playbook['severity'] in ['high', 'critical']:
            self.notify_human_responders(incident_type, incident_data)

        return incident_id
```

#### Evidence Preservation
```python
class EvidenceManager:
    def preserve_evidence(self, incident_data):
        """Preserve digital evidence for investigation"""

        # Create evidence package
        evidence_id = self.generate_evidence_id()
        evidence_dir = f"/var/evidence/incident_{evidence_id}"

        # Collect system state
        system_state = {
            'timestamp': datetime.utcnow(),
            'processes': self.get_running_processes(),
            'network_connections': self.get_network_connections(),
            'open_files': self.get_open_files(),
            'memory_dump': self.get_memory_dump(),
            'disk_images': self.get_disk_images()
        }

        # Create cryptographic hash for integrity
        evidence_hash = self.calculate_evidence_hash(system_state)

        # Store evidence with chain of custody
        evidence_record = {
            'evidence_id': evidence_id,
            'collection_time': system_state['timestamp'],
            'collected_by': 'automated_system',
            'incident_id': incident_data['incident_id'],
            'hash': evidence_hash,
            'data': system_state
        }

        self.store_evidence(evidence_record)
        return evidence_id
```

## Best Practices

### Security Hardening Checklist

- [ ] Implement principle of least privilege
- [ ] Keep systems and software updated
- [ ] Use strong encryption for data at rest and in transit
- [ ] Implement proper access controls and authentication
- [ ] Configure security monitoring and alerting
- [ ] Implement network segmentation
- [ ] Use secure coding practices
- [ ] Implement proper logging and audit trails
- [ ] Plan for incident response and disaster recovery
- [ ] Conduct regular security assessments and penetration testing

### Compliance Checklist

- [ ] Implement data protection measures (GDPR compliance)
- [ ] Maintain audit logs for compliance requirements
- [ ] Implement data retention and deletion policies
- [ ] Conduct regular security training for administrators
- [ ] Implement change management procedures
- [ ] Maintain security documentation and procedures
- [ ] Conduct regular compliance audits
- [ ] Implement data classification policies
- [ ] Maintain chain of custody for digital evidence
- [ ] Implement proper vendor management procedures

## Support and Resources

### Security Tools

- **Vulnerability Scanning**: [Nessus](https://www.tenable.com/), [OpenVAS](https://www.openvas.org/)
- **Intrusion Detection**: [Snort](https://www.snort.org/), [Suricata](https://suricata.io/)
- **Log Analysis**: [ELK Stack](https://www.elastic.co/elastic-stack/), [Splunk](https://www.splunk.com/)
- **Certificate Management**: [Let's Encrypt](https://letsencrypt.org/), [Vault](https://www.vaultproject.io/)
- **Secrets Management**: [HashiCorp Vault](https://www.vaultproject.io/), [AWS Secrets Manager](https://aws.amazon.com/secrets-manager/)

### Getting Help

- **Security Best Practices**: [OWASP](https://owasp.org/), [NIST](https://www.nist.gov/)
- **Compliance Guidelines**: [GDPR](https://gdpr.eu/), [CCPA](https://cppa.ca.gov/)
- **GitHub Issues**: [Report Issues](https://github.com/privatus-chat/privatus-chat/issues)
- **Security Discussions**: [GitHub Discussions](https://github.com/privatus-chat/privatus-chat/discussions)

---

*Last updated: January 2025*
*Privatus-chat v3.0.0 - Enhanced Security Edition*