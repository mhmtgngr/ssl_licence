"""DNS zone transfer (AXFR) service using dnspython."""

import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class ZoneTransferRecord:
    """A DNS record retrieved via zone transfer."""

    hostname: str
    record_type: str  # A, AAAA, CNAME
    value: str
    ttl: int = 3600


class ZoneTransferService:
    """Perform AXFR zone transfers against DNS servers."""

    WANTED_TYPES = {"A", "AAAA", "CNAME"}

    def transfer_zone(
        self,
        server: str,
        zone_name: str,
        tsig_key: str | None = None,
        tsig_algorithm: str = "hmac-sha256",
        timeout: float = 30.0,
    ) -> list[ZoneTransferRecord]:
        """Perform an AXFR zone transfer and return A/AAAA/CNAME records.

        Args:
            server: IP address or hostname of the DNS server.
            zone_name: The DNS zone to transfer (e.g., "example.com").
            tsig_key: Optional TSIG key (format: "keyname:base64secret").
            tsig_algorithm: TSIG algorithm (default hmac-sha256).
            timeout: Transfer timeout in seconds.

        Returns empty list on failure.
        """
        try:
            import dns.query
            import dns.zone
            import dns.tsigkeyring
            import dns.rdatatype
            import dns.name
        except ImportError:
            logger.error("dnspython is not installed")
            return []

        records = []

        try:
            keyring = None
            keyname = None
            if tsig_key and ":" in tsig_key:
                keyname, secret = tsig_key.split(":", 1)
                keyring = dns.tsigkeyring.from_text({keyname: secret})

            xfr_kwargs = {
                "where": server,
                "zone": zone_name,
                "timeout": timeout,
                "lifetime": timeout,
            }
            if keyring:
                xfr_kwargs["keyring"] = keyring
                xfr_kwargs["keyname"] = dns.name.from_text(keyname)
                xfr_kwargs["keyalgorithm"] = tsig_algorithm

            zone = dns.zone.from_xfr(dns.query.xfr(**xfr_kwargs))

            for name, node in zone.nodes.items():
                fqdn = str(name)
                if fqdn == "@":
                    fqdn = zone_name
                elif not fqdn.endswith(f".{zone_name}"):
                    fqdn = f"{fqdn}.{zone_name}"

                for rdataset in node.rdatasets:
                    rtype = dns.rdatatype.to_text(rdataset.rdtype)
                    if rtype not in self.WANTED_TYPES:
                        continue
                    for rdata in rdataset:
                        value = str(rdata).rstrip(".")
                        records.append(ZoneTransferRecord(
                            hostname=fqdn,
                            record_type=rtype,
                            value=value,
                            ttl=rdataset.ttl,
                        ))

        except Exception as e:
            logger.error("Zone transfer failed for %s from %s: %s", zone_name, server, e)

        return records
