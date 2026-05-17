"""
DNS Enumeration Module
======================
Enumerates DNS records for target domains.
Supports: A, AAAA, MX, TXT, CNAME, NS, SOA records.
Uses dnspython library with aiohttp fallback.
"""

import asyncio
from typing import Dict, List, Any


class DNSEnumerator:
    """
    DNS record enumerator using dnspython.
    """

    def __init__(self, domain: str, config: Dict, logger):
        self.domain = domain
        self.config = config
        self.logger = logger
        self.record_types = config.get("recon", {}).get("dns_types", ["A", "AAAA", "MX", "TXT", "CNAME", "NS"])

    async def enumerate(self) -> Dict[str, Any]:
        """
        Enumerate all DNS record types for the domain.

        Returns:
            Dictionary of record type -> list of records
        """
        records = {}

        try:
            import dns.resolver
            import dns.exception

            resolver = dns.resolver.Resolver()
            resolver.timeout = 10
            resolver.lifetime = 15

            for rtype in self.record_types:
                try:
                    answers = resolver.resolve(self.domain, rtype)
                    records[rtype] = [str(r) for r in answers]
                    self.logger.debug(f"DNS {rtype} for {self.domain}: {records[rtype]}")
                except dns.exception.NXDOMAIN:
                    records[rtype] = []
                except dns.exception.NoAnswer:
                    records[rtype] = []
                except dns.exception.Timeout:
                    records[rtype] = []
                    self.logger.debug(f"DNS timeout for {rtype} record of {self.domain}")
                except Exception as e:
                    records[rtype] = []
                    self.logger.debug(f"DNS error for {rtype}: {e}")

        except ImportError:
            self.logger.warning("dnspython not installed. DNS enumeration limited.")
            records = await self._fallback_dns()

        self.logger.info(f"DNS enumeration complete for {self.domain}")
        return records

    async def _fallback_dns(self) -> Dict[str, Any]:
        """Fallback DNS using system tools or basic socket."""
        import socket
        records = {}

        try:
            # Basic A record lookup
            a_records = socket.getaddrinfo(self.domain, None)
            records["A"] = list(set(r[4][0] for r in a_records if "." in r[4][0]))
        except Exception:
            records["A"] = []

        for rtype in self.record_types:
            if rtype not in records:
                records[rtype] = []

        return records

    def check_zone_transfer(self) -> List[str]:
        """
        Attempt DNS zone transfer (AXFR) - passive check only.
        Returns list of records if zone transfer is allowed.
        """
        try:
            import dns.zone
            import dns.query

            zone = dns.zone.from_xfr(dns.query.xfr(self.domain, self.domain, timeout=10))
            names = [str(n) for n in zone.nodes.keys()]
            if names:
                self.logger.warning(f"ZONE TRANSFER ALLOWED for {self.domain}!")
            return names
        except Exception:
            return []

    def check_dnssec(self) -> Dict[str, Any]:
        """Check if DNSSEC is configured for the domain."""
        try:
            import dns.resolver
            try:
                answers = dns.resolver.resolve(self.domain, "DNSKEY")
                return {"dnssec": True, "keys": len(list(answers))}
            except Exception:
                return {"dnssec": False, "keys": 0}
        except ImportError:
            return {"dnssec": None, "error": "dnspython not available"}
