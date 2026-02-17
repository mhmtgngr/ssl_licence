#!/usr/bin/env python3
"""Script to issue a new software licence."""

import argparse
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import LICENCE_SIGNING_SECRET, LICENCE_STORAGE_PATH
from licence.manager import LicenceManager


def main():
    parser = argparse.ArgumentParser(description="Issue a software licence")
    parser.add_argument("issued_to", help="Licensee name or identifier")
    parser.add_argument(
        "--type",
        choices=["trial", "standard", "professional", "enterprise"],
        default="standard",
        help="Licence type",
    )
    parser.add_argument("--days", type=int, help="Validity in days (omit for perpetual)")
    parser.add_argument("--features", nargs="*", help="Enabled features")
    parser.add_argument("--max-users", type=int, default=1, help="Max concurrent users")

    args = parser.parse_args()

    manager = LicenceManager(
        signing_secret=LICENCE_SIGNING_SECRET,
        storage_path=str(LICENCE_STORAGE_PATH),
    )

    licence = manager.issue(
        licence_type=args.type,
        issued_to=args.issued_to,
        valid_days=args.days,
        features=args.features,
        max_users=args.max_users,
    )

    print(f"Licence issued successfully!")
    print(f"  Key:     {licence.key}")
    print(f"  Type:    {licence.licence_type}")
    print(f"  To:      {licence.issued_to}")
    print(f"  Issued:  {licence.issued_at.isoformat()}")
    if licence.expires_at:
        print(f"  Expires: {licence.expires_at.isoformat()}")
    else:
        print(f"  Expires: Never (perpetual)")


if __name__ == "__main__":
    main()
