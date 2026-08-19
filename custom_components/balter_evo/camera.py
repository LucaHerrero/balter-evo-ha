"""Camera platform for Balter EVO video door stations.

Designed for on-demand snapshot access with zero continuous background streaming.
This ensures the door intercom is NEVER blocked for other residents or incoming rings.
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

from homeassistant.components.camera import Camera, CameraEntityFeature
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from . import BalterConfigEntry
from .api import BalterCloudClient
from .const import DOMAIN
from .p2p import async_p2p_get_snapshot

_LOGGER = logging.getLogger(__name__)

# Minimum cache time in seconds to prevent flooding the door station on rapid dashboard refreshes
SNAPSHOT_CACHE_TTL = 30.0


async def async_setup_entry(
    hass: HomeAssistant,
    entry: BalterConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Set up Balter EVO camera entities."""
    data = entry.runtime_data
    entities = []

    for device in data.devices:
        entities.append(BalterDoorbellCamera(hass, data.client, device))

    async_add_entities(entities)


class BalterDoorbellCamera(Camera):
    """Camera entity for a Balter EVO video door station."""

    _attr_has_entity_name = True
    _attr_icon = "mdi:doorbell-video"
    _attr_supported_features = CameraEntityFeature.ON_OFF
    # Critical: Disable background polling so HA does not continuously occupy the intercom channel
    _attr_should_poll = False

    def __init__(
        self,
        hass: HomeAssistant,
        client: BalterCloudClient,
        device: dict[str, Any],
    ) -> None:
        """Initialize the doorbell camera entity."""
        super().__init__()
        self.hass = hass
        self._client = client
        self._device = device
        self._duid = device["duid"]
        self._attr_unique_id = f"{self._duid}_camera"
        self._attr_name = f"{device.get('name', 'Türstation')} Kamera"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, self._duid)},
            name=device.get("name", "Balter EVO"),
            manufacturer="Balter / Homaxi",
            model=device.get("model", "EVO 2"),
        )
        self._last_image: bytes | None = None
        self._last_image_time: float = 0
        self._lock = asyncio.Lock()

    async def async_camera_image(
        self, width: int | None = None, height: int | None = None
    ) -> bytes | None:
        """Return a still image on demand.
        
        Uses an in-memory cache to prevent continuous channel occupation.
        If a new frame is needed, it fetches it transiently and releases the session immediately.
        """
        now = time.time()
        # Serve cached image if within TTL to protect intercom availability
        if self._last_image and (now - self._last_image_time < SNAPSHOT_CACHE_TTL):
            return self._last_image

        async with self._lock:
            # Double-check cache after acquiring lock
            if self._last_image and (time.time() - self._last_image_time < SNAPSHOT_CACHE_TTL):
                return self._last_image

            try:
                dynamic_password = await self._client.get_dynamic_password(self._duid)
                image_bytes = await async_p2p_get_snapshot(
                    self.hass,
                    self._duid,
                    dynamic_password,
                    data_encode_key=self._device.get("data_encode_key"),
                )
                if image_bytes:
                    self._last_image = image_bytes
                    self._last_image_time = time.time()
                    return image_bytes
            except Exception as err:
                _LOGGER.warning("Could not fetch P2P snapshot for %s: %s", self._duid, err)

        return self._last_image
