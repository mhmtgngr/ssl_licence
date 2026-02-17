"""Default licence template configurations."""

TRIAL_TEMPLATE = {
    "licence_type": "trial",
    "valid_days": 30,
    "features": ["basic"],
    "max_users": 1,
}

STANDARD_TEMPLATE = {
    "licence_type": "standard",
    "valid_days": 365,
    "features": ["basic", "export", "reports"],
    "max_users": 5,
}

PROFESSIONAL_TEMPLATE = {
    "licence_type": "professional",
    "valid_days": 365,
    "features": ["basic", "export", "reports", "api", "integrations"],
    "max_users": 25,
}

ENTERPRISE_TEMPLATE = {
    "licence_type": "enterprise",
    "valid_days": None,  # perpetual
    "features": [
        "basic", "export", "reports", "api",
        "integrations", "sso", "audit", "custom_branding",
    ],
    "max_users": 0,  # unlimited
}

TEMPLATES = {
    "trial": TRIAL_TEMPLATE,
    "standard": STANDARD_TEMPLATE,
    "professional": PROFESSIONAL_TEMPLATE,
    "enterprise": ENTERPRISE_TEMPLATE,
}
