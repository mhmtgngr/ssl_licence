# SSL & Licence Management

A Python tool for managing SSL certificates and software licences.

## Project Structure

```
ssl_licence/
├── main.py                    # CLI entry point
├── pyproject.toml             # Project configuration
├── requirements.txt           # Dependencies
├── config/
│   └── settings.py            # Project-wide settings
├── ssl/
│   ├── certificate.py         # Certificate generation & management
│   ├── monitor.py             # Certificate expiry monitoring
│   └── utils/
│       └── helpers.py         # SSL utility functions
├── licence/
│   ├── generator.py           # Licence key generation
│   ├── validator.py           # Licence key validation
│   ├── manager.py             # Licence lifecycle management
│   ├── templates/
│   │   └── defaults.py        # Default licence templates
│   ├── validators/            # Custom validation strategies
│   └── generators/            # Custom generation strategies
├── scripts/
│   ├── generate_cert.py       # Standalone cert generation script
│   ├── issue_licence.py       # Standalone licence issuing script
│   └── check_certs.py         # Standalone cert monitoring script
├── tests/
│   ├── test_ssl/
│   │   └── test_certificate.py
│   └── test_licence/
│       ├── test_generator.py
│       └── test_validator.py
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

### Licence Management

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

## Configuration

Set environment variables to configure:

- `LICENCE_SECRET` - HMAC signing secret for licence keys (required in production)
- `LOG_LEVEL` - Logging level (default: INFO)

## Testing

```bash
python -m pytest tests/
```
