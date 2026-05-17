"""
Subdomain Enumeration Module
OWASP WSTG Bug Bounty Automation Framework

Features:
- crt.sh enumeration
- AlienVault OTX enumeration
- RapidDNS enumeration
- Duplicate removal
- File export support
- Timeout handling
- Error handling
"""

import requests
import json
from concurrent.futures import ThreadPoolExecutor


class SubdomainEnumerator:
    """
    Professional subdomain enumeration engine.
    """

    def __init__(self, domain):
        self.domain = domain
        self.results = set()

        self.headers = {
            "User-Agent": (
                "Mozilla/5.0 (X11; Linux x86_64) "
                "AppleWebKit/537.36 "
                "(KHTML, like Gecko) "
                "Chrome/120.0 Safari/537.36"
            )
        }

    def crtsh_enum(self):
        """
        Enumerate subdomains using crt.sh
        """

        url = f"https://crt.sh/?q=%25.{self.domain}&output=json"

        try:
            response = requests.get(
                url,
                headers=self.headers,
                timeout=15
            )

            if response.status_code == 200:
                data = response.json()

                for entry in data:
                    name = entry.get("name_value", "")

                    for subdomain in name.split("\n"):
                        subdomain = subdomain.strip().lower()

                        if "*" not in subdomain:
                            self.results.add(subdomain)

        except Exception as error:
            print(f"[CRT.SH ERROR] {error}")

    def alienvault_enum(self):
        """
        Enumerate subdomains using AlienVault OTX
        """

        url = (
            f"https://otx.alienvault.com/api/v1/indicators/"
            f"domain/{self.domain}/passive_dns"
        )

        try:
            response = requests.get(
                url,
                headers=self.headers,
                timeout=15
            )

            if response.status_code == 200:
                data = response.json()

                for entry in data.get("passive_dns", []):
                    hostname = entry.get("hostname", "")

                    if hostname.endswith(self.domain):
                        self.results.add(hostname.lower())

        except Exception as error:
            print(f"[ALIENVAULT ERROR] {error}")

    def rapiddns_enum(self):
        """
        Enumerate subdomains using RapidDNS
        """

        url = f"https://rapiddns.io/subdomain/{self.domain}?full=1"

        try:
            response = requests.get(
                url,
                headers=self.headers,
                timeout=15
            )

            if response.status_code == 200:
                lines = response.text.splitlines()

                for line in lines:
                    if self.domain in line:
                        parts = line.split(">")

                        for part in parts:
                            if self.domain in part:
                                subdomain = (
                                    part.split("<")[0]
                                    .strip()
                                    .lower()
                                )

                                if (
                                    subdomain.endswith(self.domain)
                                    and "*" not in subdomain
                                ):
                                    self.results.add(subdomain)

        except Exception as error:
            print(f"[RAPIDDNS ERROR] {error}")

    def remove_invalid_entries(self):
        """
        Remove invalid subdomain entries
        """

        cleaned = set()

        for subdomain in self.results:
            if (
                subdomain
                and "@" not in subdomain
                and " " not in subdomain
            ):
                cleaned.add(subdomain)

        self.results = cleaned

    def save_results(self, output_file):
        """
        Save subdomains to file
        """

        try:
            with open(output_file, "w") as file:
                for subdomain in sorted(self.results):
                    file.write(subdomain + "\n")

            print(f"[+] Saved results to {output_file}")

        except Exception as error:
            print(f"[SAVE ERROR] {error}")

    def run(self, output_file=None):
        """
        Run all enumeration methods
        """

        print(f"[+] Starting subdomain enumeration for {self.domain}")

        with ThreadPoolExecutor(max_workers=5) as executor:
            executor.submit(self.crtsh_enum)
            executor.submit(self.alienvault_enum)
            executor.submit(self.rapiddns_enum)

        self.remove_invalid_entries()

        print(
            f"[+] Total subdomains discovered: "
            f"{len(self.results)}"
        )

        if output_file:
            self.save_results(output_file)

        return sorted(self.results)


if __name__ == "__main__":

    domain = input("Enter target domain: ").strip()

    enumerator = SubdomainEnumerator(domain)

    results = enumerator.run(
        output_file="subdomains.txt"
    )

    for subdomain in results:
        print(subdomain)