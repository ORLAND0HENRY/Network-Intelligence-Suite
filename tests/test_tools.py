"""Unit tests for safe input validation and metadata handling."""

import argparse

import pytest
from scapy.all import IP

from network_intelligence.health import is_loopback_url
from network_intelligence.monitor import is_outbound_public_traffic
from network_intelligence.scanner import parse_private_network


@pytest.mark.parametrize("value", ["10.0.0.0/24", "172.16.2.0/24", "192.168.1.0/24"])
def test_private_network_accepts_small_rfc1918_ranges(value):
    assert parse_private_network(value).num_addresses == 256


@pytest.mark.parametrize("value", ["8.8.8.0/24", "192.168.0.0/16", "192.168.1.4/32", "::1/128", "not-a-network"])
def test_private_network_rejects_out_of_scope_or_large_ranges(value):
    with pytest.raises(argparse.ArgumentTypeError):
        parse_private_network(value)


@pytest.mark.parametrize(
    "url",
    ["http://localhost:8000/", "https://127.0.0.1/", "http://[::1]/"],
)
def test_loopback_url_accepts_loopback_only(url):
    assert is_loopback_url(url)


@pytest.mark.parametrize(
    "url",
    ["http://example.com/", "http://127.0.0.1.example.com/", "ftp://localhost/", "http://user:pass@localhost/", "http://192.168.1.1/"],
)
def test_loopback_url_rejects_non_loopback_or_credential_urls(url):
    assert not is_loopback_url(url)


def test_monitor_returns_only_private_to_global_ipv4():
    packet = IP(src="192.168.1.10", dst="1.1.1.1")
    assert is_outbound_public_traffic(packet) == ("192.168.1.10", "1.1.1.1")


@pytest.mark.parametrize(
    ("source", "destination"),
    [("192.168.1.10", "192.168.1.1"), ("8.8.8.8", "1.1.1.1"), ("192.168.1.10", "127.0.0.1")],
)
def test_monitor_ignores_non_outbound_traffic(source, destination):
    assert is_outbound_public_traffic(IP(src=source, dst=destination)) is None
