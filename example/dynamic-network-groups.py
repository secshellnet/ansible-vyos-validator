#!/usr/bin/env python3

# this script is being used to get dynamic address groups from e. g. google, github and cloudflare

import json
import logging

from ipaddress import ip_network, IPv4Network, IPv6Network
from typing import List

import requests

from aggregate_prefixes import aggregate_prefixes

logger = logging.Logger(__name__)


class Provider:
    def __init__(self):
        self._ipv4_addresses = list()
        self._ipv6_addresses = list()

        # get ip addresses from cloudflare api
        self._fetch()

        # aggregate networks if possible and sort them by netmask
        self._ipv4_addresses = sorted(aggregate_prefixes(self._ipv4_addresses), key=lambda x: x.prefixlen)
        self._ipv6_addresses = sorted(aggregate_prefixes(self._ipv6_addresses), key=lambda x: x.prefixlen)

    def _fetch(self):
        raise NotImplementedError()

    def _add_ip_address(self, address: str):
        address_obj = ip_network(address, strict=False)
        if isinstance(address_obj, IPv4Network):
            self._add_ipv4_address(address_obj)
        else:
            self._add_ipv6_address(address_obj)

    def _add_ipv4_address(self, address_obj: IPv4Network):
        # remove duplicates
        if address_obj in self._ipv4_addresses:
            return
        self._ipv4_addresses.append(address_obj)

    def _add_ipv6_address(self, address_obj: IPv6Network):
        # remove duplicates
        if address_obj in self._ipv6_addresses:
            return
        self._ipv6_addresses.append(address_obj)

    def get_v4(self) -> List[str]:
        # convert ipv4 network objects to strings
        return [str(address) for address in self._ipv4_addresses]

    def get_v6(self) -> List[str]:
        # convert ipv6 network objects to strings
        return [str(address) for address in self._ipv6_addresses]


class Github(Provider):
    def _fetch(self):
        resp = requests.get("https://api.github.com/meta")
        if resp.status_code != 200:
            logger.warning("GITHUB API: %s", resp.text)
            return

        for grp in ["api", "packages", "git"]:
            for address in resp.json().get(grp):
                # determine the address family this network belongs to (ipv4 / ipv6)
                self._add_ip_address(address)


class Google(Provider):
    def _fetch(self):
        resp = requests.get("https://www.gstatic.com/ipranges/goog.json")
        if resp.status_code != 200:
            logger.warning("GOOGLE API: %s", resp.text)
            return

        for obj in resp.json().get("prefixes"):
            for key, address in obj.items():
                self._add_ip_address(address)


class Cloudflare(Provider):
    def _fetch(self):
        self._fetch_raw("https://www.cloudflare.com/ips-v4")
        self._fetch_raw("https://www.cloudflare.com/ips-v6")

    def _fetch_raw(self, api: str):
        resp = requests.get(api)
        if resp.status_code != 200:
            logger.warning("CLOUDFLARE API: %s", resp.text)
            return data

        for address in resp.text.split("\n"):
            self._add_ip_address(address)


if __name__ == '__main__':
    groups = {
        "NET-GITHUB": (github := Github()).get_v4(),
        "NET-GITHUB-6": github.get_v6(),

        "NET-GOOGLE": (google := Google()).get_v4(),
        "NET-GOOGLE-6": google.get_v6(),

        "NET-CLOUDFLARE": (cloudflare := Cloudflare()).get_v4(),
        "NET-CLOUDFLARE-6": cloudflare.get_v6(),
    }

    data = list()
    for group_name, addresses in groups.items():
        data.append({
            "name": group_name,
            "afi": 'ipv6' if group_name.endswith('-6') else 'ipv4',
            "members": [{"address": addr} for addr in addresses]
        })

    print(json.dumps(data))