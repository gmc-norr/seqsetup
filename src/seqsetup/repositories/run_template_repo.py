"""Repository for RunTemplate database operations."""

from ..models.run_template import RunTemplate
from .base import BaseRepository


class RunTemplateRepository(BaseRepository[RunTemplate]):
    """Thin data-access layer for run templates. No business logic."""

    COLLECTION = "run_templates"
    MODEL_CLASS = RunTemplate
