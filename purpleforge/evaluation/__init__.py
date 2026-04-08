"""
PurpleForge evaluation framework.

Evaluates scenario detections against authorized labelled datasets only.
For defensive evaluation use — measures precision, recall, F1, MTTD,
reproducibility variance, and false-positive rate.
"""

from purpleforge.evaluation.dataset import LabelledDataset, DatasetItem, ExpectedDetection, load_dataset
from purpleforge.evaluation.runner import EvaluationRunner, Observation
from purpleforge.evaluation.report import EvaluationReport

__all__ = [
    "LabelledDataset",
    "DatasetItem",
    "ExpectedDetection",
    "load_dataset",
    "EvaluationRunner",
    "Observation",
    "EvaluationReport",
]
