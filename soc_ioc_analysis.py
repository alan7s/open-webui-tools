"""
title: SOC IOC Analysis
author: alan7s
author_url: https://github.com/alan7s/open-webui-tools
funding_url: https://github.com/open-webui
version: 0.0.1
"""

import requests
from pydantic import Field

class Tools:
    def __init__(self):
        self.vt_api = "you-virustotal-api"
        self.abuseipdb_api = "your-abuseipdb-api"

    def analyze_remote_ip(
        self,
        ip: str = Field(..., description="IP address to be analyzed"),
    ) -> dict:
        """
        Get for a given IP, the last analysis stats from VirusTotal and abuse confidence score from AbuseIPDB.
        :param ip: The IP address.
        :return: The IP analysis from VirusTotal and AbuseIPDB or an error message.
        """
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"accept": "application/json", "x-apikey": self.vt_api}

        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            data = response.json()
            vt_stats = data["data"]["attributes"]["last_analysis_stats"]
        except requests.exceptions.RequestException as e:
            vt_stats = f"Error {e}"

        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
        headers = {"Accept": "application/json", "Key": self.abuseipdb_api}

        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            data = response.json()
            abuse_stats = data["data"]["abuseConfidenceScore"]
        except requests.exceptions.RequestException as e:
            abuse_stats = f"Error {e}"

        return (
            f"VirusTotal IP analysis: {vt_stats}; AbuseIPDB IP analysis: {abuse_stats}"
        )

    def analyze_domain(
        self,
        domain: str = Field(..., description="Domain address to be analyzed"),
    ) -> dict:
        """
        Get for a given domain, the last analysis stats from VirusTotal.
        :param ip: The domain address.
        :return: The domain analysis from VirusTotal or an error message.
        """
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {"accept": "application/json", "x-apikey": self.vt_api}

        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            data = response.json()
            vt_stats = data["data"]["attributes"]["last_analysis_stats"]
        except requests.exceptions.RequestException as e:
            vt_stats = f"Error {e}"

        return f"VirusTotal domain analysis: {vt_stats}"
