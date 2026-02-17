#!/usr/bin/env python3
"""Script to generate a self-signed SSL certificate."""

import argparse
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sslcert.certificate import CertificateManager, CertificateInfo


def main():
    parser = argparse.ArgumentParser(
        description="Generate a self-signed SSL certificate"
    )
    parser.add_argument("name", help="Certificate name (used for filenames)")
    parser.add_argument("--cn", required=True, help="Common Name (domain)")
    parser.add_argument("--org", default="", help="Organization")
    parser.add_argument("--country", default="US", help="Country code")
    parser.add_argument("--days", type=int, default=365, help="Validity in days")
    parser.add_argument("--key-size", type=int, default=2048, help="RSA key size")
    parser.add_argument(
        "--san", nargs="*", default=[], help="Subject Alternative Names"
    )

    args = parser.parse_args()

    info = CertificateInfo(
        common_name=args.cn,
        organization=args.org,
        country=args.country,
        valid_days=args.days,
        san_domains=args.san,
    )

    manager = CertificateManager()
    cert_path = manager.generate_self_signed(args.name, info)
    print(f"Certificate generated: {cert_path}")
    print(f"Private key: {manager.keys_dir / f'{args.name}.key'}")


if __name__ == "__main__":
    main()
