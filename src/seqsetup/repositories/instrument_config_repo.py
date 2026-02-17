"""Repository for instrument visibility configuration."""

from ..models.instrument_config import InstrumentConfig
from .base import SingletonConfigRepository


class InstrumentConfigRepository(SingletonConfigRepository[InstrumentConfig]):
    """Repository for managing instrument visibility configuration in MongoDB."""

    CONFIG_ID = "instrument_config"
    MODEL_CLASS = InstrumentConfig
