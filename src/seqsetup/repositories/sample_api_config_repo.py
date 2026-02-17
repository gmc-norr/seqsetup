"""Repository for sample API configuration."""

from ..models.sample_api_config import SampleApiConfig
from .base import SingletonConfigRepository


class SampleApiConfigRepository(SingletonConfigRepository[SampleApiConfig]):
    """Repository for managing sample API configuration in MongoDB.

    Uses singleton pattern - only one configuration document exists.
    """

    CONFIG_ID = "sample_api_config"
    MODEL_CLASS = SampleApiConfig
