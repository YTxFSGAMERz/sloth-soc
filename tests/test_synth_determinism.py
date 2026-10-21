"""Tests verifying synthetic log generator byte-determinism and RFC reserved address safety."""

import csv
import ipaddress
from pathlib import Path

from sloth_soc.synth.generator import SyntheticGenerator

RESERVED_NETS = [
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("2001:db8::/32"),
    ipaddress.ip_network("10.0.0.0/8"),
]


def test_synthetic_byte_determinism(tmp_path: Path):
    dir1 = tmp_path / "run1"
    dir2 = tmp_path / "run2"

    gen1 = SyntheticGenerator(seed=42, days=3)
    meta1 = gen1.generate(dir1)

    gen2 = SyntheticGenerator(seed=42, days=3)
    meta2 = gen2.generate(dir2)

    # Compare hashes for each file
    for fname in meta1["files"]:
        sha1 = meta1["files"][fname]["sha256"]
        sha2 = meta2["files"][fname]["sha256"]
        assert sha1 == sha2, f"Hash mismatch for {fname}: {sha1} != {sha2}"

    # Also compare raw bytes on disk
    for rel_path in ["auth.log", "nginx/access.log", "fail2ban.log", "ufw.log", "labels.csv"]:
        b1 = (dir1 / rel_path).read_bytes()
        b2 = (dir2 / rel_path).read_bytes()
        assert b1 == b2, f"Byte content differs for {rel_path}!"


def test_synthetic_only_uses_reserved_ips(tmp_path: Path):
    out_dir = tmp_path / "synth_ips"
    gen = SyntheticGenerator(seed=7, days=2)
    gen.generate(out_dir)

    labels_file = out_dir / "labels.csv"
    with open(labels_file, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            ip_str = row["ip"]
            ip = ipaddress.ip_address(ip_str)
            is_reserved = any(ip in net for net in RESERVED_NETS)
            assert is_reserved, f"IP {ip_str} is NOT in any RFC-reserved test range!"
