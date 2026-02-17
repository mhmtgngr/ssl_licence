# SSL & Licence Management

A comprehensive Python tool for managing SSL certificates, software licences,
and tracking product lifecycle/support dates with AI-powered alerting.

## Project Structure

```
ssl_licence/
├── main.py                              # CLI entry point (ssl + licence + tracker)
├── pyproject.toml                       # Project configuration
├── requirements.txt                     # Dependencies
├── config/
│   └── settings.py                      # Project-wide settings
│
├── ssl/                                 # SSL Certificate Module
│   ├── certificate.py                   # Certificate generation & management
│   ├── monitor.py                       # Certificate expiry monitoring
│   └── utils/helpers.py                 # SSL utility functions
│
├── licence/                             # Licence Key Module
│   ├── generator.py                     # HMAC-signed licence key generation
│   ├── validator.py                     # Licence key validation
│   ├── manager.py                       # Licence lifecycle management
│   ├── templates/defaults.py            # Default licence templates
│   ├── validators/                      # Custom validation strategies
│   └── generators/                      # Custom generation strategies
│
├── tracker/                             # Product Licence & Support Tracker
│   ├── product.py                       # Product data model (14 categories)
│   ├── registry.py                      # CRUD + filtering + persistence
│   ├── alert_engine.py                  # Multi-threshold alert engine
│   ├── search.py                        # Full-text search + faceted filtering
│   ├── reports.py                       # Dashboard, expiry, compliance, cost reports
│   ├── products/                        # Built-in product catalogues
│   │   ├── microsoft.py                 # Windows Server, SQL Server, Exchange, .NET...
│   │   ├── cloud.py                     # AWS, Azure, GCP services + K8s versions
│   │   └── network.py                   # F5, Citrix, HAProxy, NGINX, Cisco, Palo Alto
│   ├── ai/
│   │   └── analyzer.py                  # AI risk assessment, upgrade planning, cost opt
│   └── notifications/
│       └── notifier.py                  # Console, Email, Webhook, Slack, File notifications
│
├── scripts/                             # Standalone scripts
│   ├── generate_cert.py
│   ├── issue_licence.py
│   └── check_certs.py
│
├── tests/                               # Unit tests
│   ├── test_ssl/
│   ├── test_licence/
│   └── test_tracker/
│       ├── test_product.py
│       ├── test_alert_engine.py
│       ├── test_registry.py
│       ├── test_search.py
│       └── test_analyzer.py
│
├── data/                                # Runtime data (registries, logs)
└── docs/
```

## Usage

### SSL Certificate Management

```bash
# Generate a self-signed certificate
python main.py ssl generate mysite --cn example.com --org "My Org" --days 365

# List managed certificates
python main.py ssl list

# Check remote domain certificate expiry
python main.py ssl check example.com google.com
```

### Licence Key Management

```bash
# Issue a licence
python main.py licence issue "John Doe" --type standard --days 365

# Validate a licence key
python main.py licence validate "STA-XXXXXXXXXXXX-XXXXXXXX-XXXXXXXX"

# List all licences
python main.py licence list

# Revoke a licence
python main.py licence revoke "STA-XXXXXXXXXXXX-XXXXXXXX-XXXXXXXX"
```

### Product Licence & Support Tracker

Track licences and end-of-support dates for all your products — Microsoft,
cloud services, load balancers, network equipment, databases, and more.

#### Add products to track

```bash
# Microsoft product with support dates
python main.py tracker add "Windows Server" \
  --vendor Microsoft --version 2019 --category microsoft \
  --support-end 2024-01-09 --extended-end 2029-01-09 \
  --cost 6000 --env production --owner "IT Ops" --tags critical server

# Load balancer
python main.py tracker add "BIG-IP" \
  --vendor F5 --version 16.x --category load_balancer \
  --expiry 2026-12-31 --eol 2028-07-31 \
  --cost 25000 --env production

# Cloud subscription
python main.py tracker add "Azure SQL Database" \
  --vendor Microsoft --version "Current" --category cloud_platform \
  --licence-type pay_as_you_go --cost 12000 --env production

# SSL certificate as a tracked product
python main.py tracker add "Wildcard Cert *.example.com" \
  --vendor DigiCert --version "2024" --category ssl_certificate \
  --expiry 2025-06-15 --cost 500
```

#### View alerts (6 months, 3 months, 1 month, 1 week thresholds)

```bash
# Show all alerts
python main.py tracker alerts

# Filter by severity
python main.py tracker alerts --level critical

# Filter by vendor
python main.py tracker alerts --vendor Microsoft
```

Example output:
```
======================================================================
  LICENCE & SUPPORT ALERTS — 2026-02-17 10:30 UTC
======================================================================

  [!!!] CRITICAL   | CRITICAL: BIG-IP (F5) — licence_expiry in 5 days ...
       Target date: 2026-02-22
       Days remaining: 5

  [!!]  HIGH       | HIGH: Windows Server (Microsoft) — extended_support_end in 25 days ...
       Target date: 2026-03-14
       Days remaining: 25

  [!]   MEDIUM     | MEDIUM: Azure SQL (Microsoft) — licence_expiry in 85 days ...
       Target date: 2026-05-13
       Days remaining: 85
```

#### List and search products

```bash
# List all tracked products
python main.py tracker list

# Filter by category
python main.py tracker list --category load_balancer

# Filter by vendor
python main.py tracker list --vendor Microsoft

# Filter by support status
python main.py tracker list --status end_of_support

# Full-text search
python main.py tracker search "SQL"
python main.py tracker search "load balancer" --sort expiry_asc
```

#### Dashboard and reports

```bash
# Interactive dashboard
python main.py tracker dashboard

# Generate expiry report (next 6 months)
python main.py tracker report --type expiry --days 180

# Compliance report
python main.py tracker report --type compliance --output compliance.json

# Cost analysis
python main.py tracker report --type cost

# Export all products to CSV
# (via Python: ReportGenerator.export_csv("products.csv"))
```

#### AI-powered analysis

```bash
# Full AI analysis summary
python main.py tracker analyze

# Risk assessment (scores 0-10 per product)
python main.py tracker analyze --risk

# Upgrade/migration plan for at-risk products
python main.py tracker analyze --upgrade

# Cost optimization suggestions
python main.py tracker analyze --cost

# Save full report
python main.py tracker analyze --output ai_report.json
```

#### Browse built-in product catalogues

```bash
# Microsoft lifecycle dates (Windows Server, SQL Server, Exchange, .NET...)
python main.py tracker catalogue microsoft

# Cloud services (AWS, Azure, GCP + Kubernetes versions)
python main.py tracker catalogue cloud

# Network products (F5, Citrix, HAProxy, NGINX, Cisco, Palo Alto, Fortinet)
python main.py tracker catalogue network
```

### Notifications

The system supports multiple notification channels:

- **Console** — color-coded severity output (default)
- **Email** — SMTP digest with HTML table
- **Webhook** — HTTP POST with JSON payload
- **Slack** — Incoming webhook with formatted blocks
- **File** — Append to `data/alerts.log`

Configure via Python:
```python
from tracker.notifications.notifier import EmailNotifier, SlackNotifier

email = EmailNotifier(
    smtp_host="smtp.example.com",
    from_addr="alerts@example.com",
    to_addrs=["admin@example.com"],
    username="user", password="pass",
)
email.send(alerts)

slack = SlackNotifier(webhook_url="https://hooks.slack.com/services/...")
slack.send(alerts)
```

## Alert Thresholds

Default thresholds (configurable):

| Threshold | Level    | Action                              |
|-----------|----------|-------------------------------------|
| 6 months  | LOW      | Plan renewal/migration              |
| 3 months  | MEDIUM   | Initiate renewal process            |
| 1 month   | HIGH     | Urgent — begin procurement          |
| 1 week    | CRITICAL | Emergency — immediate action needed |
| Past due  | EXPIRED  | Already expired — fix now           |

## Supported Product Categories

| Category           | Examples                                          |
|--------------------|---------------------------------------------------|
| microsoft          | Windows Server, SQL Server, Exchange, .NET         |
| cloud_platform     | AWS EC2, Azure VMs, GCP Compute                   |
| load_balancer      | F5 BIG-IP, Citrix ADC, HAProxy, NGINX, Azure LB   |
| network_equipment  | Cisco switches, routers                            |
| database           | SQL Server, Oracle, PostgreSQL                     |
| operating_system   | Windows, RHEL, Ubuntu LTS                          |
| security           | Cisco ASA, Palo Alto PAN-OS, Fortinet FortiOS      |
| virtualization     | VMware vSphere, Hyper-V                            |
| container          | Kubernetes, Docker Enterprise, OpenShift            |
| middleware         | WebLogic, JBoss, IIS                               |
| ssl_certificate    | DigiCert, Let's Encrypt, Sectigo certs             |
| software_licence   | Any commercial software licence                    |
| saas               | Jira, Salesforce, ServiceNow, Datadog              |
| other              | Anything else                                      |

## Configuration

Environment variables:

- `LICENCE_SECRET` — HMAC signing secret for licence keys (required in production)
- `LOG_LEVEL` — Logging level (default: INFO)

## Testing

```bash
python -m pytest tests/ -v
```
