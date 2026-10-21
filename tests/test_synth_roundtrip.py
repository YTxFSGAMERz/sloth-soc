"""Round-trip verification: synthetic logs ingested by parsers achieve >= 99% parse coverage."""

from pathlib import Path

from sloth_soc.parsers import parse_file
from sloth_soc.synth.generator import SyntheticGenerator


def test_roundtrip_synthetic_coverage(tmp_path: Path):
    synth_dir = tmp_path / "roundtrip_test"
    generator = SyntheticGenerator(seed=1, days=3)
    generator.generate(synth_dir)

    # 1. SSHD Parser
    auth_events, auth_stats = parse_file(synth_dir / "auth.log", source="sshd", year_hint=2026)
    assert auth_stats.lines_total > 0
    assert auth_stats.coverage >= 0.99, f"SSHD parse coverage too low: {auth_stats.coverage}"

    # 2. Nginx Parser
    nginx_events, nginx_stats = parse_file(
        synth_dir / "nginx" / "access.log", source="nginx", year_hint=2026
    )
    assert nginx_stats.lines_total > 0
    assert nginx_stats.coverage >= 0.99, f"Nginx parse coverage too low: {nginx_stats.coverage}"

    # 3. Fail2ban Parser
    f2b_events, f2b_stats = parse_file(
        synth_dir / "fail2ban.log", source="fail2ban", year_hint=2026
    )
    assert f2b_stats.lines_total > 0
    assert f2b_stats.coverage >= 0.99, f"Fail2ban parse coverage too low: {f2b_stats.coverage}"

    # 4. UFW Parser
    ufw_events, ufw_stats = parse_file(synth_dir / "ufw.log", source="ufw", year_hint=2026)
    assert ufw_stats.lines_total > 0
    assert ufw_stats.coverage >= 0.99, f"UFW parse coverage too low: {ufw_stats.coverage}"
