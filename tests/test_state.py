"""Tests for baseline state store in SQLite."""

from sloth_soc.state import StateStore


def test_state_known_ip_and_user():
    with StateStore(":memory:") as store:
        assert not store.is_known_ip("198.51.100.10")
        assert not store.is_known_user_ip("alice", "198.51.100.10")

        # Record baseline
        store.record_ip("198.51.100.10", "2026-10-15")
        store.record_user_ip("alice", "198.51.100.10", "2026-10-15")

        assert store.is_known_ip("198.51.100.10")
        assert store.is_known_user_ip("alice", "198.51.100.10")
        # Other users from same IP not known
        assert not store.is_known_user_ip("bob", "198.51.100.10")


def test_state_hourly_baselines():
    with StateStore(":memory:") as store:
        rate = store.get_hourly_rate(3)
        assert rate["mean_fail"] >= 0.1

        store.update_hourly_baseline(hour=3, fail_count=10, count_404=5)
        store.update_hourly_baseline(hour=3, fail_count=20, count_404=15)

        updated_rate = store.get_hourly_rate(3)
        assert updated_rate["mean_fail"] == 15.0
        assert updated_rate["mean_404"] == 10.0
