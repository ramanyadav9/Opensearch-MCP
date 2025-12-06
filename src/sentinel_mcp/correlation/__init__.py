"""Correlation Engine for Sentinel-AI

Provides entity correlation, relationship mapping, and timeline reconstruction.
"""

from .engine import CorrelationEngine
from .models import CorrelationResult, EntityGraph, Entity, Relationship

__all__ = [
    'CorrelationEngine',
    'CorrelationResult',
    'EntityGraph',
    'Entity',
    'Relationship',
]
