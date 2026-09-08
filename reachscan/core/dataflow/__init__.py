"""Dataflow analysis — taint source/sink tracking along known paths."""

from core.dataflow.sources import classify_source
from core.dataflow.tracer import DataflowTracer

__all__ = ["classify_source", "DataflowTracer"]
