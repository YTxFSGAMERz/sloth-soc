"""Tests for individual detectors (rules R1-R8, stat, iforest, rf, ensemble)."""

import pandas as pd

from sloth_soc.detectors.ensemble import EnsembleDetector
from sloth_soc.detectors.iforest import IsolationForestDetector
from sloth_soc.detectors.rules import evaluate_rules
from sloth_soc.detectors.stat import StatDetector


def test_rules_r1_burst():
    row = pd.Series({"auth_fail_max_5m": 15})
    matches = evaluate_rules(row)
    assert any(m.rule_id == "R1" for m in matches)
    assert any(m.severity == "medium" for m in matches)


def test_rules_r2_spray():
    row = pd.Series({"distinct_users": 10, "invalid_user_ratio": 0.8})
    matches = evaluate_rules(row)
    assert any(m.rule_id == "R2" for m in matches)


def test_rules_r3_probing():
    # R3 standard
    row1 = pd.Series({"probe_hits": 6, "probe_2xx": 0})
    matches1 = evaluate_rules(row1)
    assert any(m.rule_id == "R3" for m in matches1)
    assert any(m.severity == "medium" for m in matches1)

    # R3b exposed path with 2xx
    row2 = pd.Series({"probe_hits": 6, "probe_2xx": 1})
    matches2 = evaluate_rules(row2)
    assert any(m.rule_id == "R3b" for m in matches2)
    assert any(m.severity == "high" for m in matches2)


def test_rules_r4_port_scan():
    row = pd.Series({"max_ports_5m": 20})
    matches = evaluate_rules(row)
    assert any(m.rule_id == "R4" for m in matches)


def test_rules_r5_critical_stuffing():
    # R5: credential stuffing success
    row = pd.Series({"ok_after_fail": 1, "first_seen_ever": 1})
    matches = evaluate_rules(row)
    assert any(m.rule_id == "R5" for m in matches)
    assert any(m.severity == "critical" for m in matches)


def test_rules_r7_low_and_slow():
    row = pd.Series({"auth_fail_total": 12, "active_hours": 8, "auth_fail_max_5m": 2})
    matches = evaluate_rules(row)
    assert any(m.rule_id == "R7" for m in matches)


def test_rules_r8_injection():
    row = pd.Series({"inj_marker_hits": 2})
    matches = evaluate_rules(row)
    assert any(m.rule_id == "R8" for m in matches)


def test_iforest_detector_fit_and_score():
    df_train = pd.DataFrame(
        [
            {"auth_fail_total": 0, "auth_fail_max_5m": 0, "probe_hits": 0, "http_total": 50},
            {"auth_fail_total": 1, "auth_fail_max_5m": 1, "probe_hits": 0, "http_total": 60},
            {"auth_fail_total": 0, "auth_fail_max_5m": 0, "probe_hits": 0, "http_total": 55},
        ]
    )
    df_test = pd.DataFrame(
        [
            {"auth_fail_total": 0, "auth_fail_max_5m": 0, "probe_hits": 0, "http_total": 52},
            {"auth_fail_total": 100, "auth_fail_max_5m": 50, "probe_hits": 20, "http_total": 200},
        ]
    )

    detector = IsolationForestDetector(seed=42)
    detector.fit(df_train)
    scores = detector.score(df_test)

    assert len(scores) == 2
    # Anomalous row should have higher score
    assert scores[1] > scores[0]


def test_stat_detector_fdr():
    df = pd.DataFrame(
        [
            {"auth_fail_total": 0, "http_total": 10, "http_404_ratio": 0.0},
            {"auth_fail_total": 50, "http_total": 10, "http_404_ratio": 0.0},
        ]
    )
    stat_det = StatDetector()
    stat_det.fit(df)
    scores = stat_det.score(df)
    assert len(scores) == 2
    assert scores[1] > scores[0]


def test_ensemble_detector():
    df = pd.DataFrame(
        [
            {"auth_fail_total": 0, "auth_fail_max_5m": 0, "probe_hits": 0, "http_total": 10},
            {"auth_fail_total": 25, "auth_fail_max_5m": 15, "probe_hits": 8, "http_total": 10},
        ]
    )
    ens = EnsembleDetector(seed=42)
    ens.fit(df)
    scores = ens.score(df)
    assert len(scores) == 2
    assert scores[1] > scores[0]
