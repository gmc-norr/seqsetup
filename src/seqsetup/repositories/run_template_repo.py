"""Repository for RunTemplate database operations."""

import logging

from ..models.run_template import RunTemplate
from .base import BaseRepository

logger = logging.getLogger(__name__)


class RunTemplateRepository(BaseRepository[RunTemplate]):
    """Thin data-access layer for run templates. No business logic."""

    COLLECTION = "run_templates"
    MODEL_CLASS = RunTemplate

    def list_all_readable(self) -> tuple[list[RunTemplate], list[str]]:
        """Every template that can be read, and the ids of those that cannot.

        One template this release cannot read -- one naming an instrument it
        does not know (``models.sequencing_run.stored_platform``) -- must not
        take the Run Templates page or the New Run page down with it. The
        unreadable ids come back so the page can name them: one is never
        dropped silently (CLAUDE.md: never silently discard data). Each is
        logged at WARNING for the administrator who has to repair it.
        Nothing is written.
        """
        templates: list[RunTemplate] = []
        unreadable: list[str] = []
        for doc in self.collection.find():
            try:
                templates.append(RunTemplate.from_dict(doc))
            except Exception as exc:
                template_id = str(doc.get("_id") or "") or "(a template document with no id)"
                logger.warning("Template %s could not be read: %s", template_id, exc)
                unreadable.append(template_id)
        return templates, unreadable
