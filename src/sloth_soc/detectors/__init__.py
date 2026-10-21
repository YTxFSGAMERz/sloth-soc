"""Detector implementations: rules, stat, iforest, rf, tabpfn, and ensemble."""

from sloth_soc.detectors.base import Detector, RuleMatch
from sloth_soc.detectors.ensemble import EnsembleDetector
from sloth_soc.detectors.iforest import IsolationForestDetector
from sloth_soc.detectors.rf import RandomForestDetector
from sloth_soc.detectors.rules import RuleDetector, evaluate_rules
from sloth_soc.detectors.stat import StatDetector
from sloth_soc.detectors.tabpfn_det import TabPFNDetector

__all__ = [
    "Detector",
    "EnsembleDetector",
    "IsolationForestDetector",
    "RandomForestDetector",
    "RuleDetector",
    "RuleMatch",
    "StatDetector",
    "TabPFNDetector",
    "evaluate_rules",
]
